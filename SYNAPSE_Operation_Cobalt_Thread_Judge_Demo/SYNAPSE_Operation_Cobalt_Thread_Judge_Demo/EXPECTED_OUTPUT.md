# Expected qualitative output

These are **expected signals**, not fixed scores.

## CT-001 - Identity / access audit
Look for:
- user `s.kapoor`
- external test IP `203.0.113.54`
- password-only login
- `DATA_EXPORT_ADMIN`
- ticket `EXC-7742`
- export `client_export_q3.csv`
- archive `client_export_q3.zip`

## CT-002 - Internal email
Expected artifact-aware email reconstruction:
- participants
- timestamps
- subjects
- message bodies
- `CLIENT_MASTER_Q3`
- `client_export_q3.zip`
- `EXC-7742`
- concern about missing destination / approval chronology

## CT-003 - Export manifest
Look for:
- export job `EXP-260911-441`
- requester `s.kapoor`
- ticket `EXC-7742`
- `CLIENT_MASTER_Q3`
- archive `client_export_q3.zip`
- 38,477,122-byte archive
- security-approval control note

## CT-004 - Network activity
Look for:
- `s.kapoor`
- `203.0.113.54`
- `198.51.100.64`
- `vault-sync.example`
- `EXP-260911-441`
- `client_export_q3.zip`
- large outbound transfer

## CT-005 - Policy exception PDF
Look for:
- `EXC-7742`
- `CLIENT_MASTER_Q3`
- `client_export_q3.zip`
- `vault-sync.example`
- generated timestamp `22:07 IST`
- chronology mismatch: the role request was already recorded earlier

## Expected graph story

```text
CT-001 AUDIT
   |  s.kapoor / EXC-7742 / client_export_q3.zip
   v
CT-002 EMAIL
   |  EXC-7742 / client_export_q3.zip
   v
CT-003 EXPORT MANIFEST
   |  EXP-260911-441 / client_export_q3.zip
   v
CT-004 NETWORK
   |  vault-sync.example / EXC-7742
   v
CT-005 EXCEPTION PDF
```

The exact edge labels depend on the current correlation engine.

**Correlation is a lead, not proof of causation.**

## Coverage / blind spot
Risk and coverage values should not be pre-scripted. The key expected behavior is that a significant artifact with comparatively low recorded review can rise in blind-spot priority, and additional review can reduce that mismatch.

## Final report
The generated report should consolidate the resulting case state: evidence inventory, integrity, triage findings, relationships, coverage, potential blind spots, timeline, audit / custody, methods, and limitations.
