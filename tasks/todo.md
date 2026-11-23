# Task Checklist: NS8-AdvancedPolicyManager

## Phase 0: Specs & Shared Contract
- [x] Task 0: Capability Map, Modul-Specs (`SPEC-*.md`) und gemeinsamer Schnittstellenvertrag (`docs/contracts/api-and-policy-contract.md`) erstellt.

## Phase 1: Parallel Module Implementation (Swarm)
- [x] Task 1 (`ns8-infra`): NS8 `imageroot/` Actions, Systemd-Unit, Restic-Backup-Hooks, `Containerfile`s, `build-images.sh` und `tests/ns8/`
  - Acceptance: Kein `get-status` Override, überall `agent.dump_env()`, `10.0.2.2` Loopback-Übersetzung, `pytest tests/ns8/` (18/18) grün.
- [x] Task 2 (`ns8-infra`): NS8 Cockpit-UI (`ui/`) mit Vue 2 + `@nethserver/ns8-ui-lib` (`Status.vue`, `Settings.vue`, `About.vue`, `de`/`en` i18n)
  - Acceptance: Pflicht-i18n-Keys vorhanden, keine verbotene `createSuccessNotificationForApp`, `npm run build` in `ui/` grün.
- [x] Task 3 (`backend-api`): `directory-auth` (`Ldap3DirectoryProvider` für AD & OpenLDAP + `InMemoryDirectoryProvider` + RBAC-Auth & Directory-Routen)
  - Acceptance: Login, Gruppenprüfung (`ADMIN_GROUPS`), Bootstrap-Admin und Benutzer-/Gruppensuche per `pytest` verifiziert.
- [x] Task 4 (`backend-api`): `policy-core` (SQLite WAL, 11 v1-`ruleType`s + v2-Hooks, Prioritäts-Resolver, Simulator, Idempotenz, Agent- & Installer-Routen, SPA-Static-Serving)
  - Acceptance: Komplette `pytest backend/tests/ -v` Suite (20/20 inkl. Konflikt-Trace & Agent-Lebenszyklus) grün.
- [x] Task 5 (`policy-web`): Dedizierte Vue-3-Policy-GUI (`web/`) mit Login, Dashboard, 4-Kategorien-Baukasten, Prioritäts-Zuweisungen, Simulator, Gerätegruppen & Rollout-Center
  - Acceptance: `npm run typecheck` & `npm run build` in `web/` fehlerfrei; barrierearme, klare Oberfläche (`de`/`en`) im Browser verifiziert.
- [x] Task 6 (`rust-agent`): Rust Cross-Platform-Agent (`agent/`) inkl. `WindowsEnforcer`, `LinuxEnforcer`, `MacOsEnforcer`, Desired-State-Rollback (`applied_state.json`) & Installer-Skripten
  - Acceptance: `cargo test` (8/8) und `cargo build --release` in `agent/` fehlerfrei.

## Checkpoint: Full-Stack & UI Verification
- [x] Task 7 (Coordinator): End-to-End-Integrationstest (`tests/e2e/test_full_stack_e2e.py`: Live-Backend + gebaute `web/dist` SPA + echtes Rust-Agent-Binary `enroll` -> `sync` -> `rollback` auf Windows/Linux/macOS) und interaktive Browser-Prüfung aller 7 Ansichten erfolgreich abgeschlossen.
