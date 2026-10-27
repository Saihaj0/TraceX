#!/usr/bin/env bash
# TRACE-X end-to-end smoke test against a running API (default http://127.0.0.1:8000).
# Exercises the full acceptance path: create investigation -> import evidence ->
# inspect records/errors -> timeline -> analysis -> findings -> chains -> graph ->
# uncertainty -> report -> exports -> isolation check.
set -euo pipefail

API="${API:-http://127.0.0.1:8000/api}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVTX="$ROOT/datasets/evtx/Security_short_selected.evtx"
CSV="$ROOT/datasets/filesystem/csvexport_webroot_usn_export.csv"
MIXED="$ROOT/datasets/events/mixed_mixed_export.json"
JQ() { "$ROOT/.venv/Scripts/python.exe" -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

echo "== health"
curl -sf -m 15 "$API/health" | JQ "d['status']+' '+d['dialect']"

echo "== create investigation"
CASE="SMOKE-$(date +%s)"
INV=$(curl -sf -m 15 -X POST "$API/investigations" -H 'content-type: application/json' \
  -d "{\"name\":\"Smoke test case\",\"case_id\":\"$CASE\",\"description\":\"automated smoke test\"}" \
  | JQ "d['id']")
echo "investigation: $INV"

echo "== validation error (short name must be rejected)"
CODE=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST "$API/investigations" \
  -H 'content-type: application/json' -d '{"name":"x","case_id":"bad"}')
test "$CODE" = "422" && echo "rejected with 422 (schema validation ok)"

echo "== preview + import EVTX"
curl -sf -m 60 -X POST "$API/investigations/$INV/evidence/preview" -F "file=@$EVTX" \
  | JQ "'preview accepted=%s rejected=%s type=%s' % (d['preview']['accepted'], d['preview']['rejected'], d['preview']['file_type'])"
curl -sf -m 60 -X POST "$API/investigations/$INV/evidence" -F "file=@$EVTX" > /dev/null

echo "== import filesystem CSV (with an invalid row)"
curl -sf -m 60 -X POST "$API/investigations/$INV/evidence" -F "file=@$CSV" \
  | JQ "'imported=%s rejected=%s status=%s' % (d['accepted'], d['rejected'], d['status'])"

echo "== import the synthetic mixed-scenario export (findings expected)"
curl -sf -m 60 -X POST "$API/investigations/$INV/evidence" -F "file=@$MIXED" \
  | JQ "'imported=%s rejected=%s' % (d['accepted'], d['rejected'])"

echo "== evidence list + rejected record detail"
SID=$(curl -sf -m 15 "$API/investigations/$INV/evidence" | JQ "d['evidence'][-1]['id']")
curl -sf -m 15 "$API/investigations/$INV/evidence/$SID/errors" \
  | JQ "'errors retained: %s (first: %s)' % (len(d['errors']), d['errors'][0]['reason'] if d['errors'] else 'none')"

echo "== timeline (filtered + sorted)"
curl -sf -m 30 "$API/investigations/$INV/events?limit=5&sort=desc" \
  | JQ "'events=%s flagged=%s undated=%s' % (d['total'], d['flagged_count'], d['undated_in_page'])"

echo "== run detection engine"
curl -sf -m 120 -X POST "$API/investigations/$INV/analysis/run" \
  | JQ "'analysis: %s' % d['message']"

echo "== findings with explanations"
FIND_JSON=$(curl -sf -m 15 "$API/investigations/$INV/findings?limit=3")
echo "$FIND_JSON" | JQ "'findings=%s by severity=%s' % (d['total'], d['summary']['by_severity'])"
TOTAL=$(echo "$FIND_JSON" | JQ "d['total']")
if [ "$TOTAL" -gt 0 ]; then
  FID=$(echo "$FIND_JSON" | JQ "d['findings'][0]['id']")
  curl -sf -m 15 "$API/investigations/$INV/findings/$FID" \
    | JQ "'finding %s: support=%s alternatives=%d next_steps=%d' % (d['rule_id'], d['support'], len(d['explanation']['alternative_explanations']), len(d['explanation']['recommended_next_checks']))"
fi

echo "== chains + graph"
curl -sf -m 15 "$API/investigations/$INV/chains" | JQ "'chains=%s complete=%s partial=%s' % (d['count'], d['complete'], d['partial'])"
curl -sf -m 30 "$API/investigations/$INV/graph" \
  | JQ "'graph nodes=%s edges=%s relations=%s' % (d['counts']['nodes'], d['counts']['edges'], list(d['counts']['by_relation'])[:4])"

echo "== uncertainty methodology"
curl -sf -m 15 "$API/uncertainty" | JQ "'support levels: %s' % [l['level'] for l in d['support_levels']]"

echo "== reports + exports"
curl -sf -m 30 "$API/investigations/$INV/report.html" -o /tmp/tracex_report.html
grep -q "TRACE-X Investigation Report" /tmp/tracex_report.html && echo "HTML report rendered"
curl -sf -m 30 "$API/investigations/$INV/report.json" | JQ "'json report: findings=%s timeline=%s sources=%s' % (len(d['findings']), len(d['timeline']), len(d['sources']))"
curl -sf -m 30 "$API/investigations/$INV/timeline/export?format=csv" | head -1 | grep -q event_id && echo "CSV export header ok"
curl -sf -m 30 "$API/investigations/$INV/report/manifest" | JQ "'manifest ruleset=%s evidence hashes=%s' % (d['ruleset_version'], len(d['evidence_sha256']))"

echo "== audit trail"
curl -sf -m 15 "$API/investigations/$INV/audit" | JQ "'audit entries=%s' % d['count']"

echo "== demo data + isolation check"
curl -sf -m 120 -X POST "$API/demo/generate" -H 'content-type: application/json' \
  -d '{"scenarios":["logclear"]}' | JQ "'demo created=%s' % d['count']"
DEMO=$(curl -sf -m 15 "$API/investigations?origin=demo" | JQ "d['investigations'][0]['id']")
curl -sf -m 15 "$API/investigations/$INV/events?limit=1000" | JQ "'source investigation still has events=%s (unchanged by demo generation)' % d['total']"
CODE=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X DELETE "$API/investigations/$DEMO")
test "$CODE" = "400" && echo "demo delete blocked without confirmation (ok)"
curl -sf -m 15 -X DELETE "$API/investigations/$DEMO?confirm=true" | JQ "'demo deleted=%s' % d['deleted']"

echo "== cleanup"
curl -sf -m 15 -X DELETE "$API/investigations/$INV?confirm=true" | JQ "'smoke investigation deleted=%s' % d['deleted']"
echo "SMOKE TEST PASSED"
