# Spec: `policy-core`

## Objective
Implementiert die persistente SQLite-WAL-Datenbank, die erweiterbare Regelschema-Registry (4 v1-Kernbereiche + v2-Hooks), Geräte-Enrollment & Gerätegruppen, die deterministische Prioritäts- & Konfliktauflösungs-Engine, den Regel-Simulator sowie die Agent-Check-in- & Compliance-API.

## Tech Stack
- Python 3, FastAPI, Pydantic v2, SQLite3 (`WAL` + `foreign_keys=ON`)

## Commands
- Tests: `python -m pytest backend/tests/ -v`

## Project Structure
- `backend/app/db/` (`connection.py`, `schema.py`, `idempotency.py`)
- `backend/app/engine/` (`schema_registry.py`, `resolver.py`)
- `backend/app/adapters/` (`delivery.py`)
- `backend/app/routes/` (`policies.py`, `assignments.py`, `devices.py`, `simulator.py`, `enrollment.py`, `agent.py`, `dashboard.py`)
- `backend/app/main.py`

## Boundaries
- **Always:** API-Payloads in `camelCase` gemäß `docs/contracts/api-and-policy-contract.md` validieren; `Idempotency-Key` atomar per `UNIQUE`-Constraint absichern; Revisionen bei Richtlinienänderungen inkrementieren.
- **Never:** Unvalidierte Regelkonfigurationen in der Datenbank ablegen.

## Success Criteria
- Alle 11 v1-`ruleType`s sowie `custom.raw_setting` validieren typsicher.
- Konfliktauflösung (`priority=1` gewinnt bei `OVERRIDE`; Zusammenführung bei `APPEND_UNIQUE`) inkl. Simulator-Trace und komplettem Agent-Zyklus ist zu 100 % durch `pytest` abgedeckt.
