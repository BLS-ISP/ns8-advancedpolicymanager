# Changelog

All notable changes to **NS8-AdvancedPolicyManager** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-23

### Added
- **Live LDAP/AD Group Discovery in NS8 Cockpit Settings (`list-domain-groups` & `Settings.vue`):** Replaced manual comma-separated group text entry with live NS8 `ldapproxy` / `Ldapclient` group discovery, searchable Carbon `NsMultiSelect` tags (displaying group member counts and descriptions), automatic domain schema badges (`Samba AD` / `OpenLDAP`), a manual group refresh trigger, and 1-click quick-add chips for detected administrative groups (such as `Domain Admins`, `IT-Admins`, `admins`).

### Improved
- **Samba AD Primary Group & LDAPS Proxy Handling (`directory-auth`):** Added automatic resolution of Active Directory well-known `primaryGroupID` RIDs (`512` `Domain Admins`, `513` `Domain Users`) and streamlined TLS socket setup for custom-port `ldapproxy` endpoints.

## [1.0.0] - 2026-11-23

### Added
- **NethServer 8 Rootless Packaging (`ns8-packaging`):** Full rootless Podman module (`imageroot/`), Traefik HTTPS virtual host routing, automatic NS8 `ldapproxy` binding (`Samba AD` & `OpenLDAP`), Restic online SQLite backup/restore/clone hooks, and NS8 Cluster-Admin Cockpit UI (`ui/` in German & English).
- **Directory Integration & RBAC (`directory-auth`):** Live user and group lookup for both Samba Active Directory (including nested groups) and OpenLDAP (`RFC2307`), group-based admin login (`ADMIN_GROUPS`), and optional local emergency bootstrap admin.
- **Policy Engine & Simulator (`policy-core`):** SQLite WAL persistence, atomic `Idempotency-Key` protection, 11 structured cross-platform rule types across 4 categories (*Access & Privileges*, *Workspace*, *Security & Devices*, *Desktop & Browser*), v2 extensibility hooks (`custom.raw_setting`, `SambaSysvolExporterAdapter`, `MobileMdmProfileAdapter`), priority conflict resolution (`OVERRIDE` & `APPEND_UNIQUE`), and live Effective-Policy Simulator with conflict trace.
- **Dedicated Policy Admin Web GUI (`policy-web`):** Bilingual (`de`/`en`) Vue 3 + TypeScript + Tailwind CSS web console for visual policy authoring, priority assignment matrix, live policy simulation, endpoint compliance monitoring, and one-line rollout commands.
- **Cross-Platform Client Agent (`policy-agent`):** Zero-dependency Rust daemon (`ns8-policy-agent`) with native prebuilt binaries and installer scripts for **Windows** (Windows Service), **Linux** (`systemd`), and **macOS** (`LaunchDaemon`), featuring two-phase desired-state enforcement and surgical policy rollback (`ROLLED_BACK`) without modifying pre-existing local administrators.
