"""Windows Event Log (EVTX) parser.

Uses the pure-python `python-evtx` library to read binary .evtx files and parses
each record's XML rendering with the standard library.

Adapter note: the parser is reached through the shared `BaseParser` interface.
If `python-evtx` is unavailable in a deployment, register an alternative
implementation (e.g. libevtx bindings) under the same `file_type="evtx"`
key and nothing else in TRACE-X changes.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from ..config import PARSERS_VERSION
from ..normalization import NormalizedEvent, coerce_datetime
from .base import BaseParser, ParseResult, ParserError, RowError, register

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Event-ID -> internal event_type. Only ids relevant to this investigation
# scope get a specific type; everything else stays a generic Windows event so
# we never pretend to understand a record we have not mapped.
EVENT_ID_TYPES = {
    "1102": "audit_log_cleared",
    "1101": "audit_log_cleared",
    "1100": "event_logging_shutdown",
    "104": "event_log_cleared",
    "4688": "process_creation",
    "4697": "service_installed",
    "4719": "audit_policy_change",
    "4720": "account_created",
    "4624": "logon_success",
    "4625": "logon_failure",
    "4648": "explicit_credential_logon",
    "4663": "file_access",
    "4656": "handle_requested",
    "4660": "object_deleted",
    "4670": "permissions_changed",
    "4616": "system_time_changed",
    "4698": "scheduled_task_changed",
    "4702": "scheduled_task_updated",
    "1": "process_creation",  # Sysmon
    "11": "file_deleted",      # Sysmon FileDelete
    "23": "file_deleted_archived",
    "3": "network_connection",
}

# Event-data keys we promote into normalized columns (absent keys stay null).
KEY_ALIASES = {
    "user": ["SubjectUserName", "TargetUserName", "UserName", "AccountName"],
    "process_name": ["NewProcessName", "ProcessName", "ImagePath", "Image", "FileName"],
    "file_path": ["ObjectName", "TargetFilename", "FileName", "Path", "MemberName"],
    "process_id": ["NewProcessId", "ProcessId", "ProcessID", "TargetProcessId"],
    "host": ["Computer", "WorkstationName"],
    "device_id": ["Device", "DeviceName", "Drive"],
}

AUDIT_CLEAR_PROVIDERS = ("Microsoft-Windows-Eventlog", "Security-Auditing")


def _pick(data: dict, keys: list[str]):
    for key in keys:
        value = data.get(key)
        if value not in (None, "-", ""):
            return value
    return None


def _parse_event_time(text: str | None):
    """Parse Windows SYSTEMTIME ('...1234567Z', 100ns ticks) reliably."""
    if not text:
        return None
    text = text.strip()
    if "." in text:
        head, _, rest = text.partition(".")
        digits = rest.rstrip("Zz")
        frac = digits[:6].ljust(6, "0")
        text = f"{head}.{frac}{rest[len(digits):]}"
    return coerce_datetime(text)


def _describe(event_type: str, event_id: str, provider: str | None, data: dict) -> str:
    subject = data.get("SubjectUserName") or data.get("TargetUserName")
    bits = [f"Windows event {event_id}"]
    if provider:
        bits.append(f"from provider {provider}")
    if event_type == "audit_log_cleared":
        bits.append("audit/security log cleared")
        who = data.get("SubjectUserName")
        if who:
            bits.append(f"initiated by {who}")
    elif event_type == "event_log_cleared":
        bits.append(f"event log '{data.get('Channel', data.get('LogFile', '?'))}' cleared")
    elif event_type == "file_access":
        bits.append(f"access to {data.get('ObjectName', 'an object')}")
        if data.get("Accesses"):
            bits.append(f"access mask: {data['Accesses']}")
    elif event_type == "process_creation":
        bits.append(f"process started: {data.get('NewProcessName') or data.get('Image') or 'unknown'}")
    elif event_type == "system_time_changed":
        bits.append("system time changed")
        if data.get("SystemTime"):
            bits.append(f"new system time {data['SystemTime']}")
    elif event_type == "permissions_changed":
        bits.append(f"permissions changed on {data.get('ObjectName', 'an object')}")
    elif subject:
        bits.append(f"actor {subject}")
    if data.get("IpAddress") and data["IpAddress"] not in ("-", "::1", "127.0.0.1"):
        bits.append(f"source address {data['IpAddress']}")
    return " ".join(bits)


@register
class EvtxParser(BaseParser):
    name = "evtx"
    version = PARSERS_VERSION
    display_name = "Windows Event Log (EVTX)"
    file_types = ("evtx",)
    source_type = "windows_event_log"
    description = "Binary Windows Event Log files parsed with python-evtx."

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        try:
            from Evtx.Evtx import Evtx
        except ImportError as exc:  # pragma: no cover - adapter boundary
            raise ParserError(
                "python-evtx is not installed; register an alternative EVTX "
                "parser implementation for file_type='evtx'."
            ) from exc

        result = ParseResult(timezone_note="Windows SYSTEMTIME values interpreted as UTC")
        source_name = original_name or Path(file_path).name
        record_index = 0
        try:
            log = Evtx(str(file_path))
        except Exception as exc:
            raise ParserError(f"not a readable EVTX file: {exc}") from exc

        try:
            with log:
                for record in log.records():
                    record_index += 1
                    try:
                        event = self._parse_record(record, source_name, record_index)
                        if event is not None:
                            result.events.append(event)
                    except Exception as exc:  # keep going: one bad record != bad file
                        result.errors.append(
                            RowError(
                                row_index=record_index,
                                record_id=str(getattr(record, "record_num", lambda: None)()),
                                reason="record_parse_error",
                                detail=str(exc),
                            )
                        )
        except Exception as exc:
            raise ParserError(f"failed reading EVTX stream: {exc}") from exc

        if record_index == 0:
            result.warnings.append("EVTX file contained no records")

        providers = {e.raw_record.get("provider") for e in result.events if e.raw_record}
        result.metadata = {
            "record_total": record_index,
            "providers": sorted(p for p in providers if p),
            "event_ids": sorted({e.raw_record.get("event_id") for e in result.events
                                 if e.raw_record and e.raw_record.get("event_id")}),
        }
        return result

    def _parse_record(self, record, source_name: str, index: int) -> NormalizedEvent | None:
        xml_text = record.xml()
        root = ET.fromstring(xml_text)
        system = root.find("e:System", NS)
        if system is None:
            raise ValueError("record has no System element")

        provider_node = system.find("e:Provider", NS)
        provider = provider_node.get("Name") if provider_node is not None else None
        event_id_node = system.find("e:EventID", NS)
        event_id = (event_id_node.text or "").strip() if event_id_node is not None else ""
        time_node = system.find("e:TimeCreated", NS)
        system_time = time_node.get("SystemTime") if time_node is not None else None
        computer_node = system.find("e:Computer", NS)
        computer = computer_node.text if computer_node is not None else None
        execution = system.find("e:Execution", NS)
        pid = None
        if execution is not None and execution.get("ProcessID"):
            try:
                pid = int(execution.get("ProcessID"))
            except ValueError:
                pid = None
        user_node = system.find("e:UserID", NS)
        sid = user_node.text if user_node is not None else None
        record_id_node = system.find("e:EventRecordID", NS)
        record_id = record_id_node.text if record_id_node is not None else str(index)
        level_node = system.find("e:Level", NS)
        channel_node = system.find("e:Channel", NS)

        data: dict[str, str] = {}
        for node in root.findall("e:EventData/e:Data", NS):
            name = node.get("Name")
            if name:
                data[name] = (node.text or "").strip()
        # Some records place their payload under UserData instead.
        user_data = root.find("e:UserData", NS)
        if user_data is not None:
            for child in list(user_data):
                tag = child.tag.split("}")[-1]
                for sub in list(child):
                    data[sub.tag.split("}")[-1]] = (sub.text or "").strip()
                if child.text and child.text.strip():
                    data[tag] = child.text.strip()

        event_type = EVENT_ID_TYPES.get(event_id, "windows_event")
        ts, ts_raw, precision, confidence, tz_note = _normalize_system_time(system_time)

        user = _pick(data, KEY_ALIASES["user"]) or sid
        raw = {
            "event_id": event_id,
            "provider": provider,
            "level": level_node.text if level_node is not None else None,
            "channel": channel_node.text if channel_node is not None else None,
            "computer": computer,
            "record_id": record_id,
            "system_time": system_time,
            "user_sid": sid,
            "process_id": record_pid(execution) or pid,
            "event_data": data,
            "xml": xml_text,
        }

        return NormalizedEvent(
            timestamp=ts,
            timestamp_raw=ts_raw,
            timestamp_precision=precision,
            timestamp_confidence=confidence,
            timezone_note=tz_note,
            event_type=event_type,
            source_type=self.source_type,
            source_file=source_name,
            source_record_id=record_id,
            host=computer,
            user=user,
            process_id=raw["process_id"],
            process_name=_pick(data, KEY_ALIASES["process_name"]),
            file_path=_pick(data, KEY_ALIASES["file_path"]),
            device_id=_pick(data, KEY_ALIASES["device_id"]),
            description=_describe(event_type, event_id, provider, data),
            raw_record=raw,
            raw_record_reference=f"{source_name}#{record_id}",
            parser_name=self.name,
            parser_version=self.version,
        )


def record_pid(execution) -> int | None:
    if execution is None:
        return None
    value = execution.get("ProcessID")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalize_system_time(system_time: str | None):
    dt = _parse_event_time(system_time)
    if dt is None:
        return None, system_time, "unknown", "none", "unparsable SYSTEMTIME value"
    return (
        dt,
        system_time,
        "second",
        "high",
        "Windows SYSTEMTIME interpreted as UTC (no local offset stored in EVTX)",
    )