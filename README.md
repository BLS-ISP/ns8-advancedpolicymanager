# NS8-AdvancedPolicyManager

Zentrales, leicht verständliches **Policy-, Berechtigungs- und Konfigurations-Management** für **NethServer 8 (NS8)** – gebaut für **Windows, Linux und macOS** mit nahtloser Anbindung an **NS8 Samba Active Directory** und **NS8 OpenLDAP**.

---

## Highlights

- **Verständlicher 4-Bereiche-Baukasten statt kryptischer RSAT-GPOs:**
  1. **Zugriff & Berechtigungen:** Anmeldekontrolle pro Gerät sowie lokale Admin- bzw. `sudo`-Rechte (mit Schutz bestehender lokaler Administratoren).
  2. **Arbeitsumgebung:** Automatische SMB-/NFS-Netzlaufwerke, IPP-/SMB-Drucker und Login-/Start-Skripte (PowerShell, Bash, Zsh).
  3. **Sicherheit & Geräte:** Bildschirmsperre / Inaktivitäts-Timeout, USB-/Wechseldatenträger-Sperre (`ALLOW` / `READ_ONLY` / `BLOCK`) und Host-Firewall.
  4. **Desktop & Browser:** Verwaltete Richtlinien für Chrome, Edge & Firefox, zentrales Hintergrundbild und Systemsperren.
- **Samba AD & OpenLDAP Parität:** Nutzt nativ den NS8 `ldapproxy` (`schema=ad` inkl. verschachtelter Gruppen sowie `schema=rfc2307` für OpenLDAP).
- **Eigene Gerätegruppen + Prioritäts-Matrix (`#1` gewinnt):** Verbindet Live-Benutzer/-Gruppen aus dem Verzeichnis (*Wer?*) mit flexiblen Gerätegruppen (*Wo?*) und unterstützt sowohl `OVERRIDE` als auch `APPEND_UNIQUE`.
- **Live-Regel-Simulator:** Zeigt vor dem Ausrollen für jede Kombination aus Benutzer und Computer die effektiven Regeln inklusive Konflikt- und Überschreibungs-Trace an.
- **Leichtgewichtiger Rust-Agent mit Desired-State-Rollback:** Einzelnes laufzeitfreies Binary (`ns8-policy-agent`) für Windows Service, Linux `systemd` und macOS `LaunchDaemon` – setzt wegfallende Richtlinien automatisch sauber zurück (`ROLLED_BACK`) und meldet den Compliance-Status live an das Dashboard.
- **Offene v2+-Architektur:** Vorbereitete Schema- und Delivery-Adapter-Schnittstellen für tiefes Finetuning (`custom.raw_setting`: Registry/ADMX/`dconf`/`plist`), Samba-`SYSVOL`-Export und Mobile-MDM.

---

## Projektstruktur

| Pfad | Modul | Beschreibung |
|---|---|---|
| `imageroot/` | `ns8-packaging` | NS8 Rootless-Actions, `ldapproxy`-Event-Hooks, Podman-Systemd-Service & Restic Online-Backup |
| `ui/` | `ns8-packaging` | NS8 Cluster-Admin (Cockpit) Modul-Oberfläche (Vue 2 + `@nethserver/ns8-ui-lib` + Carbon) |
| `backend/` | `directory-auth` & `policy-core` | FastAPI-Backend, AD/OpenLDAP-Connector, SQLite (WAL), Policy-Engine, Simulator & Agent-API |
| `web/` | `policy-web` | Dedizierte Admin-Web-GUI hinter Traefik (Vue 3 + TypeScript + Vite + Tailwind CSS, `de`/`en`) |
| `agent/` | `policy-agent` | Cross-Platform Rust-Agent (`ns8-policy-agent`) inkl. OS-Enforcern & Rollout-Skripten |
| `docs/` | Architektur & Verträge | Bestätigtes Zielbild (`docs/intent/`) & verbindlicher API-/Schema-Vertrag (`docs/contracts/`) |

---

## Lokale Entwicklung & Tests

### 1. NS8 Packaging & Cockpit-UI testen
```bash
python -m pytest tests/ns8/ -v
cd ui && npm install && npm run build
```

### 2. Backend starten & testen
```bash
python -m pytest backend/tests/ -v
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```
*(Im lokalen Entwicklungsmodus ohne gesetztes `LDAP_HOST` startet das Backend automatisch mit realistischen Demo-AD/LDAP-Konten – Login: `administrator` / `Admin123!`.)*

### 3. Policy-Web-GUI bauen
```bash
cd web && npm install && npm run typecheck && npm run build
```

### 4. Cross-Platform Rust-Agent testen & bauen
```bash
cd agent && cargo test && cargo build --release
```

---

## Container-Images bauen & in NethServer 8 installieren

```bash
REPOBASE=ghcr.io/deine-org IMAGETAG=1.0.0 ./build-images.sh
```

Auf dem NethServer-8-Cluster installieren:
```bash
add-module ghcr.io/deine-org/advancedpolicymanager:1.0.0 1
```
Anschließend im **NS8 Cluster-Admin** unter **Einstellungen** der Instanz den gewünschten FQDN (z. B. `policies.firma.de`), die NS8 User Domain (Samba AD oder OpenLDAP) und die berechtigten Admin-Gruppen (z. B. `Domain Admins`) auswählen.
