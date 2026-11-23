# Capability Map: NS8-AdvancedPolicyManager

**Status:** Freigegeben (2026-11-23)

`NS8-AdvancedPolicyManager` bündelt fünf klar abgegrenzte, unabhängig testbare Fähigkeiten (Capabilities). Jedes Modul erhält nach Freigabe dieser Map eine eigene Spezifikation (`SPEC-<module-id>.md`) entlang der Abhängigkeitsreihenfolge.

| Module id | Verantwortung (Responsibility) | Depends on |
|---|---|---|
| `ns8-packaging` | NethServer-8-Rootless-Modulhülle (`imageroot/` Actions, Podman-Systemd-Units auf `127.0.0.1`, Traefik-Route, `ldapproxy`-Binding, Restic Backup/Restore/Clone, Cockpit-UI `ui/` für Grundeinstellungen & Status) | — |
| `directory-auth` | Verzeichnis-Integration & RBAC-Authentifizierung (Live-Abfrage von Benutzern & Gruppen aus NS8 Samba AD und OpenLDAP via `ldapproxy`, Session-/Token-Login für berechtigte LDAP/AD-Admin-Gruppen sowie Notfall-/Bootstrap-Admin) | `ns8-packaging` |
| `policy-core` | Policy-Engine, Geräte-Registry & Erweiterungs-Adapter (versioniertes JSON-Schema für die 4 v1-Kernbereiche + v2-Hooks für Finetuning/ADMX/`SYSVOL`/MDM, Enrollment & Gerätegruppen, Prioritäts- & Konfliktauflösung, Effektive-Regeln-Simulator, Desired-State-Rollback-Diffing & Compliance-API) | `directory-auth` |
| `policy-web` | Dedizierte Policy-Web-GUI hinter Traefik (Übersichts-Dashboard, verständlicher Baukasten-Editor für Windows/Linux/macOS, Zuweisungs- & Prioritäts-Matrix, Effektive-Regeln-Vorschau, Geräteflotte mit Live-Status & Agent-Rollout-Center) | `directory-auth`, `policy-core` |
| `policy-agent` | Leichtgewichtiger Cross-Platform-Client-Agent für Windows, Linux & macOS (Token-Enrollment, Heartbeat/Check-in, idempotente OS-Enforcer für alle 4 v1-Kategorien inkl. sauberem Rollback entfernter Regeln, Live-Compliance-Bericht sowie OS-Installationsskripte) | `policy-core` |

**Build order:** `ns8-packaging` → `directory-auth` → `policy-core` → `policy-web`, `policy-agent`

## Modulgrenzen & Erweiterungspunkte (v2+ Ready)

1. **`ns8-packaging` ↔ Backend (`directory-auth` / `policy-core`):** Übergibt Konfiguration ausschließlich über NS8-Umgebungsvariablen (`TCP_PORT`, `TRAEFIK_HOST`, `LDAP_*` aus `ldapproxy`, `ADMIN_GROUPS`, `DATA_DIR`) und bindet den App-Container strikt auf `127.0.0.1:${TCP_PORT}`.
2. **`policy-core` Schema-Registry (Hook für Finetuning/ADMX):** Jede Regel wird als typisiertes Modul (`category`, `rule_type`, `schema_version`, `platforms`, `config`) gespeichert. Spätere Finetuning-/ADMX-/Registry-/dconf-/plist-Regeln klinken sich als weitere `rule_type`-Schemata ein, ohne Zuweisungs-, Prioritäts- oder Rollback-Logik zu ändern.
3. **`policy-core` Delivery-Adapter (Hook für `SYSVOL` & Mobile-MDM):** Die Konfliktauflösung berechnet einen plattformneutralen *Effective Policy Tree*. In v1 liest der `AgentDeliveryAdapter` diesen Baum; in v2+ können `SambaSysvolGpoAdapter` und `MobileMdmAdapter` denselben aufgelösten Baum konsumieren.
