# Implementation Plan: NS8-AdvancedPolicyManager

## Overview
Vollständige Umsetzung des NethServer-8-Rootless-Moduls `NS8-AdvancedPolicyManager` für Windows-, Linux- und macOS-Clients mit Samba-AD- & OpenLDAP-Unterstützung (`ldapproxy`), Single-Container-Pod (FastAPI + SQLite WAL + Vue 3 Admin-SPA), NS8-Cockpit-Setup-UI (Vue 2 + Carbon) und laufzeitfreiem Rust-Client-Agenten inkl. Desired-State-Rollback.

## Architecture Decisions
- **Verbindlicher API- & Schema-Vertrag:** `docs/contracts/api-and-policy-contract.md` (`camelCase` JSON, `UPPER_SNAKE_CASE` Enums).
- **Single-Container Rootless Pod:** Beseitigt Multi-Container-Race-Conditions; SQLite im WAL-Modus mit konsistentem Online-Backup (`sqlite3.Connection.backup`) für NS8-Restic.
- **NS8 `ldapproxy`-Integration:** Podman läuft mit `--network=slirp4netns:allow_host_loopback=true` und übersetzt `127.0.0.1` auf `10.0.2.2`; unterstützt sowohl `schema=ad` (Samba AD) als auch `schema=rfc2307` (OpenLDAP).
- **Zukunftssichere v2-Hooks:** `PolicyRule` Schema-Registry reserviert `CUSTOM_FINETUNING` (`custom.raw_setting`) und `PolicyDeliveryAdapter` abstrahiert `AgentBundleDeliveryAdapter` (aktiv) neben `SambaSysvolExporterAdapter` und `MobileMdmProfileAdapter`.
- **Desired-State Rollback:** Der Agent speichert angewendete Regeln inkl. Vorher-Zustand in `applied_state.json` und rollt weggefallene Regeln vor dem Anwenden neuer Regeln automatisch zurück.

## Swarm Execution Streams
1. **`ns8-infra`:** `imageroot/`, `ui/` (NS8 Cockpit), `Containerfile`s, `build-images.sh`, `tests/ns8/`
2. **`backend-api`:** `backend/` (`directory-auth` + `policy-core` + `backend/tests/`)
3. **`policy-web`:** `web/` (`policy-web` Vue 3 + TypeScript + Tailwind SPA)
4. **`rust-agent`:** `agent/` (`ns8-policy-agent` Rust-Crate + OS-Enforcer + Rollout-Skripte + `cargo test`)
5. **Coordinator Integration & Verification:** End-to-End Live-Test (Backend + SPA + Rust-Agent Check-in & Rollback), Browser-UI-Abnahme mit Screenshots, Docker-Image-Build.
