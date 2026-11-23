# Spec: `ns8-packaging`

## Objective
Stellt die vollständig NethServer-8-konforme Rootless-Modulhülle (`imageroot/`, Cockpit-UI `ui/`, `Containerfile`s, `build-images.sh`, Restic-Backup/Restore/Clone) für `NS8-AdvancedPolicyManager` bereit.

## Tech Stack
- Python 3 (NS8 `agent` & `agent.ldapproxy` Pakete)
- Systemd User Service + Rootless Podman (`--network=slirp4netns:allow_host_loopback=true`)
- NS8 Cockpit UI: Vue 2 + `@nethserver/ns8-ui-lib` + `@carbon/icons-vue`

## Commands
- NS8 Action Tests: `python -m pytest tests/ns8/ -v`
- Cockpit UI Build: `cd ui && npm install && npm run build`

## Project Structure
- `imageroot/actions/` (`create-module`, `get-configuration`, `configure-module`, `destroy-module`, `restore-module`, `clone-module`)
- `imageroot/events/user-domain-changed/10reload`
- `imageroot/systemd/user/advancedpolicymanager.service`
- `imageroot/etc/state-include.conf`, `imageroot/bin/module-dump-state`, `imageroot/bin/module-cleanup-state`
- `imageroot/update-module.d/20pull_images`
- `ui/` (NS8 Cluster-Admin Modul-UI)
- `Containerfile`, `Containerfile.app`, `build-images.sh`

## Boundaries
- **Always:** `agent.dump_env()` nach jedem `agent.set_env()` aufrufen; Podman strikt auf `127.0.0.1:${TCP_PORT}:8080` binden; `--pull=missing` verwenden; LF-Zeilenenden erzwingen; `127.0.0.1` des `ldapproxy` auf `10.0.2.2` umschreiben.
- **Never:** `imageroot/actions/get-status` überschreiben; `this.createSuccessNotificationForApp(...)` im Cockpit-UI aufrufen; `--pull=always` in `.service`-Units verwenden.

## Success Criteria
- Alle NS8-Architekturtests in `tests/ns8/` bestehen.
- `ui/` kompiliert fehlerfrei zu statischen Assets für `/ui`.
- Schnittstelle entspricht exakt `docs/contracts/api-and-policy-contract.md` (Abschnitt 1).
