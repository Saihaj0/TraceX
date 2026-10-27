# TRACE-X Evaluation Results

Generated: 2026-10-18T10:48:29Z · Engine 1.0.0 · Ruleset 1.0.0

These results are produced live by `POST /api/evaluation/run` (`backend/app/evaluation.py`),
which replays the controlled scenarios in throwaway in-memory databases. Numbers below are
from that run — they are never hardcoded in the harness or the UI. Regenerate any time:

```bash
cd backend && ../.venv/Scripts/python -m app.evaluation
```

## Setup

- **11 labelled scenarios** (synthetic, from `app/datasets.py`), **79 ingested events**,
  covering legitimate activity, log clearing, artifact deletion, timestamp manipulation,
  clock drift, incomplete collection, unrelated-but-adjacent activity, and mixed
  benign+suspicious sequences.
- Each scenario declares **ground truth**: expected rules (AF-001…AF-008), expected
  suspicion chains, and a ground-truth event sort.
- Three configurations are replayed on identical inputs:
  - **A** — timeline reconstruction only
  - **B** — timeline + detection rules
  - **C** — timeline + rules + graph correlation + uncertainty-aware reasoning
- **Errors in this run: none** (total wall time ≈ 1.9 s for 33 scenario-configurations).

## Aggregate metrics

| Metric | A (timeline) | B (+ rules) | C (+ graph/reasoning) |
|---|---|---|---|
| Rule TP / FP / FN / TN | 0 / 0 / 21 / 67 | **21 / 0 / 0 / 67** | **21 / 0 / 0 / 67** |
| Rule precision | null¹ | **1.0** | **1.0** |
| Rule recall | 0.0 | **1.0** | **1.0** |
| Rule false-positive rate | 0.0 | **0.0** | **0.0** |
| Chain TP / FP / FN / TN | 0 / 0 / 8 / 47 | not built² | **8 / 0 / 0 / 47** |
| Chain precision | null¹ | null² | **1.0** |
| Chain recall | 0.0 | 0.0² | **1.0** |
| Event-order accuracy | **1.0** | **1.0** | **1.0** |
| Relationship accuracy³ | n/a | n/a | **1.0** |
| Explainability coverage⁴ | n/a | **1.0** | **1.0** |
| Mean analysis time | n/a | 7 ms | 18 ms |
| Mean wall time per scenario | 31 ms | 67 ms | 47 ms |

¹ 0/0 is undefined: configuration A predicts nothing, so precision is reported as null
with an explicit note rather than 1.0 or 0.0.
² By design: configurations A and B do not build graph edges, so chains are not evaluated
for B (expected chains appear as false negatives only in the A comparison).
³ Relationship accuracy covers observed-edge coverage (every event must stay linked to its
recording artifact), temporal direction of ordered edges (no backwards PRECEDES /
POSSIBLY_CAUSAL), and POSSIBLY_CAUSAL anchor validity (shared file path or host+user;
proximity alone may never create one).
⁴ Fraction of findings carrying the full explanation contract: observed evidence,
correlation, hypothesis with uncertainty, what the finding does *not* establish,
limitations, alternative explanations, recommended next checks, rule metadata,
qualitative support level, and a source record id on every evidence row.

## Reading the A/B/C story

- **A → B** isolates the detection layer: recall rises from 0.0 to 1.0 with no false
  positives — every expected rule fires on its scenario and nothing fires on benign ones
  (including "legitimate administrative cleanup", "unrelated events close together", and
  "incomplete evidence collection", which are exactly the classic false-positive traps).
- **B → C** isolates correlation + reasoning: chain precision/recall reach 1.0 where B
  produces no chains at all, and relationship accuracy confirms no graph edge contradicts
  chronology or its own anchor.
- **Event-order accuracy 1.0 in all configurations** confirms timeline reconstruction is
  independent of the detection layers and handles undated records (sorted last, counted
  separately) correctly.
- Rules that lack their required evidence are **skipped with a machine-readable reason**
  (e.g. "AF-006 skipped: needs at least 3 records from a continuous log source, found 1")
  rather than silently passing — visible in the per-scenario output.

## Honest limitations (mirrored from the harness output)

- The dataset is synthetic and authored by the same project: these numbers measure
  **consistency with declared ground truth, not real-world validity**.
- Eleven small scenarios cannot represent real casework diversity; treat this as a
  **regression baseline, not a published benchmark**.
- No independently labelled corpus or inter-rater agreement was used; the treatment of
  ambiguous scenarios (e.g. bulk cleanup flagged by AF-003/AF-005 in a legitimate-admin
  context) is a documented design decision, not an external standard.
- Processing times are wall-clock on one developer machine, reported for regression
  comparison only.
