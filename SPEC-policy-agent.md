# Spec: `policy-agent`

## Objective
Schlanker, laufzeitfreier Rust-Hintergrunddienst (`ns8-policy-agent`) für Windows, Linux und macOS mit Token-Enrollment, periodischem Check-in, idempotenter Regelanwendung für alle 4 v1-Kategorien, sauberem Desired-State-Rollback beim Wegfall von Regeln und Live-Compliance-Bericht.

## Tech Stack
- Rust (`edition = "2021"`), `serde`, `serde_json`, `ureq` (`rustls`), `sha2`
- Rollout-Skripte: `install.ps1` (Windows Service), `install-linux.sh` (`systemd`), `install-macos.sh` (`LaunchDaemon`)

## Commands
- Tests: `cd agent && cargo test`
- Release Build: `cd agent && cargo build --release`

## Project Structure
- `agent/Cargo.toml`
- `agent/src/main.rs`, `cli.rs`, `config.rs`, `api.rs`, `models.rs`, `state.rs`, `engine.rs`
- `agent/src/runner.rs` (`SystemRunner` Trait: `RealSystemRunner` + `MockSystemRunner`)
- `agent/src/enforcers/` (`mod.rs`, `windows.rs`, `linux.rs`, `macos.rs`)
- `agent/installers/` (`install.ps1`, `install-linux.sh`, `install-macos.sh`)

## Boundaries
- **Always:** Vor dem Anwenden neuer Regeln entfernte Regeln anhand von `applied_state.json` zurückrollen (`ROLLED_BACK`); nur vom Agenten selbst gesetzte Gruppenmitglieder/Dateien verändern; `--dry-run` Modus unterstützen.
- **Never:** Bestehende lokale Administratoren löschen, die nicht vom Agenten hinzugefügt wurden; C-OpenSSL-Abhängigkeiten einführen.

## Success Criteria
- `cargo test` prüft `WindowsEnforcer`, `LinuxEnforcer`, `MacOsEnforcer` sowie den kompletten Desired-State-Rollback-Zyklus fehlerfrei.
- Das kompilierte Binary kommuniziert live mit dem FastAPI-Backend (`enroll` → `sync` → `compliance`).
