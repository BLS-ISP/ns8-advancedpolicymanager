# API, Schema & Environment Contract: NS8-AdvancedPolicyManager

Dieses Dokument ist der **verbindliche Schnittstellenvertrag (Single Source of Truth)** zwischen `ns8-packaging`, `directory-auth`, `policy-core`, `policy-web` und `policy-agent`.

Alle JSON-Payloads über HTTP nutzen durchgängig **`camelCase`**; alle Enum-Werte nutzen **`UPPER_SNAKE_CASE`**.

---

## 1. NS8 Container Environment Contract (`ns8-packaging` → `backend`)

| Variable | Beispiel / Default | Beschreibung |
|---|---|---|
| `APM_PORT` | `8080` | Interner HTTP-Port im Container (Podman publiziert `127.0.0.1:${TCP_PORT}:8080`) |
| `APM_DATA_DIR` | `/data` | Persistentes Verzeichnis für `apm.db` (SQLite WAL) |
| `APM_STATIC_DIR` | `/app/web_dist` | Gebaute statische Dateien von `policy-web` |
| `APM_AGENT_ARTIFACTS_DIR` | `/app/agent_artifacts` | Vorkompilierte Agent-Binaries & Installer-Templates |
| `APM_PUBLIC_URL` | `https://policies.example.org` | Öffentliche Basis-URL für generierte Agent-Rollout-Befehle |
| `JWT_SECRET` | `<64-hex-chars>` | HMAC-SHA256 Secret für Admin-Session-Tokens |
| `LDAP_MODE` | `ldapproxy` \| `mock` | `ldapproxy` im NS8-Cluster, `mock` für lokale Entwicklung/Tests |
| `LDAP_DOMAIN` | `ad.example.org` | Name der angebundenen NS8 User Domain |
| `LDAP_SCHEMA` | `ad` \| `rfc2307` | `ad` für Samba AD, `rfc2307` für OpenLDAP |
| `LDAP_HOST` | `10.0.2.2` | `ldapproxy`-Zieladresse aus Rootless-Podman (`slirp4netns:allow_host_loopback=true`) |
| `LDAP_PORT` | `40123` | Lokaler `ldapproxy`-Port |
| `LDAP_TLS` | `false` \| `true` | StartTLS/LDAPS-Flag aus `Ldapproxy().get_domain()` |
| `LDAP_BASE_DN` | `dc=ad,dc=example,dc=org` | Basis-DN für Benutzer- und Gruppensuche |
| `LDAP_BIND_DN` | `cn=ldapservice,...` | Service-Bind-DN (optional bei anonymem OpenLDAP) |
| `LDAP_BIND_PASSWORD` | `secret` | Service-Bind-Passwort |
| `ADMIN_GROUPS` | `Domain Admins,admins` | Kommagetrennte LDAP/AD-Gruppennamen mit Vollzugriff auf die Policy-Web-GUI |
| `BOOTSTRAP_ADMIN_ENABLED` | `true` \| `false` | Aktiviert lokalen Notfall-Admin-Zugang |
| `BOOTSTRAP_ADMIN_USERNAME` | `admin` | Benutzername des lokalen Notfall-Admins |
| `BOOTSTRAP_ADMIN_PASSWORD_HASH` | `pbkdf2:sha256:...` | Passwort-Hash des Notfall-Admins (Dev-Fallback `BOOTSTRAP_ADMIN_PASSWORD`) |

---

## 2. Gemeinsame HTTP-Konventionen

### Fehlerformat (alle 4xx/5xx Antworten)
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Menschenlesbare Fehlermeldung",
    "details": null
  }
}
```

### Paginierung (alle Listen-Endpunkte)
Query-Parameter: `?page=1&pageSize=25&search=...`
```json
{
  "data": [],
  "pagination": {
    "page": 1,
    "pageSize": 25,
    "totalItems": 0,
    "totalPages": 1
  }
}
```

### Authentifizierung & Idempotenz
- **Admin-API:** Header `Authorization: Bearer <accessToken>`
- **Agent-API (`/api/v1/agent/checkin`, `/api/v1/agent/compliance`):** Header `Authorization: Bearer <deviceToken>`
- **Idempotenz:** `POST /api/v1/policies`, `POST /api/v1/assignments`, `POST /api/v1/enrollment-tokens` und `POST /api/v1/agent/enroll` akzeptieren optional `Idempotency-Key: <string>`. Gleicher Key + gleicher Body liefert gespeicherte Antwort; gleicher Key + abweichender Body liefert `422 IDEMPOTENCY_KEY_REUSED`; paralleler Request liefert `409 IDEMPOTENCY_IN_PROGRESS`.

---

## 3. Policy-Regelschema (`PolicyRule`)

Jede Richtlinie (`Policy`) enthält ein Array `rules: PolicyRule[]`:

```json
{
  "ruleId": "rule-usb-block",
  "category": "SECURITY",
  "ruleType": "security.usb_storage",
  "schemaVersion": 1,
  "platforms": ["WINDOWS", "LINUX", "MACOS"],
  "mergeStrategy": "OVERRIDE",
  "config": {
    "mode": "BLOCK"
  }
}
```

### Plattform- & Kategorie-Enums
- `OsFamily`: `"WINDOWS"` | `"LINUX"` | `"MACOS"`
- `PolicyCategory`: `"ACCESS"` | `"WORKSPACE"` | `"SECURITY"` | `"DESKTOP"` | `"CUSTOM_FINETUNING"`
- `MergeStrategy`: `"OVERRIDE"` | `"APPEND_UNIQUE"`

### Alle 11 v1-`ruleType`-Definitionen + v2-Erweiterungs-Hook

1. **`access.login_access`** (`category: "ACCESS"`, default `mergeStrategy: "OVERRIDE"`)
   ```json
   {
     "mode": "ALLOW_LIST",
     "allowedGroups": ["Buchhaltung", "IT-Admins"],
     "allowedUsers": [],
     "denyGroups": []
   }
   ```
   *(`mode`: `"ALLOW_ALL"` | `"ALLOW_LIST"`)*

2. **`access.local_admins`** (`category: "ACCESS"`, default `mergeStrategy: "APPEND_UNIQUE"`)
   ```json
   {
     "adminGroups": ["IT-Admins"],
     "adminUsers": [],
     "passwordlessSudo": false
   }
   ```

3. **`workspace.network_shares`** (`category: "WORKSPACE"`, default `mergeStrategy: "APPEND_UNIQUE"`)
   ```json
   {
     "mounts": [
       {
         "id": "share-buchhaltung",
         "name": "Buchhaltung",
         "protocol": "SMB",
         "remotePath": "\\\\files.firma.local\\buchhaltung",
         "windowsDriveLetter": "X:",
         "unixMountPath": "/mnt/buchhaltung",
         "reconnectAtLogon": true
       }
     ]
   }
   ```
   *(`protocol`: `"SMB"` | `"NFS"`)*

4. **`workspace.printers`** (`category: "WORKSPACE"`, default `mergeStrategy: "APPEND_UNIQUE"`)
   ```json
   {
     "printers": [
       {
         "id": "prn-og1",
         "name": "Buerodrucker-OG1",
         "uri": "ipp://print.firma.local/ipp/og1",
         "isDefault": true,
         "driverModel": "everywhere"
       }
     ]
   }
   ```

5. **`workspace.scripts`** (`category: "WORKSPACE"`, default `mergeStrategy: "APPEND_UNIQUE"`)
   ```json
   {
     "scripts": [
       {
         "id": "scr-logon-env",
         "name": "Arbeitsplatz-Initialisierung",
         "trigger": "LOGON",
         "runAs": "USER",
         "timeoutSeconds": 60,
         "windowsPowershell": "Write-Output 'Ready'",
         "linuxBash": "echo 'Ready'",
         "macosZsh": "echo 'Ready'"
       }
     ]
   }
   ```
   *(`trigger`: `"LOGON"` | `"STARTUP"`, `runAs`: `"USER"` | `"SYSTEM"`)*

6. **`security.screen_lock`** (`category: "SECURITY"`, default `mergeStrategy: "OVERRIDE"`)
   ```json
   {
     "idleTimeoutSeconds": 300,
     "requirePasswordOnWake": true,
     "lockDelaySeconds": 5
   }
   ```

7. **`security.usb_storage`** (`category: "SECURITY"`, default `mergeStrategy: "OVERRIDE"`)
   ```json
   {
     "mode": "BLOCK"
   }
   ```
   *(`mode`: `"ALLOW"` | `"READ_ONLY"` | `"BLOCK"`)*

8. **`security.firewall`** (`category: "SECURITY"`, default `mergeStrategy: "OVERRIDE"`)
   ```json
   {
     "isEnabled": true,
     "defaultInbound": "BLOCK",
     "allowStealthMode": true,
     "allowedTcpPorts": [22, 3389],
     "allowedUdpPorts": []
   }
   ```
   *(`defaultInbound`: `"BLOCK"` | `"ALLOW"`)*

9. **`desktop.browser`** (`category: "DESKTOP"`, default `mergeStrategy: "OVERRIDE"`)
   ```json
   {
     "targets": ["CHROME", "EDGE", "FIREFOX"],
     "homepageUrl": "https://intranet.firma.local",
     "restoreOnStartup": "HOMEPAGE",
     "disableIncognito": true,
     "disablePasswordManager": false,
     "forceExtensions": []
   }
   ```
   *(`restoreOnStartup`: `"HOMEPAGE"` | `"LAST_SESSION"`)*

10. **`desktop.wallpaper`** (`category: "DESKTOP"`, default `mergeStrategy: "OVERRIDE"`)
    ```json
    {
      "imageUrl": "https://intranet.firma.local/wallpaper.jpg",
      "fitMode": "FILL",
      "isLocked": true
    }
    ```
    *(`fitMode`: `"FILL"` | `"FIT"` | `"CENTER"`)*

11. **`desktop.system_restrictions`** (`category: "DESKTOP"`, default `mergeStrategy: "OVERRIDE"`)
    ```json
    {
      "disableControlPanel": true,
      "disableRegistryTools": true,
      "disableTerminalForStandardUsers": false
    }
    ```

12. **`custom.raw_setting`** (`category: "CUSTOM_FINETUNING"`, default `mergeStrategy: "APPEND_UNIQUE"` — v2+ Hook)
    ```json
    {
      "items": [
        {
          "id": "raw-1",
          "targetOs": "WINDOWS",
          "engine": "REGISTRY",
          "path": "HKLM\\SOFTWARE\\Policies\\Custom",
          "key": "EnableFeature",
          "valueType": "INT",
          "value": "1"
        }
      ]
    }
    ```

---

## 4. REST-API-Endpunkte (`/api/v1`)

### System & Auth
- `GET /api/v1/health` → `{ "status": "ok", "version": "1.0.0", "ldapMode": "ldapproxy", "ldapDomain": "ad.example.org" }`
- `POST /api/v1/auth/login`
  - Request: `{ "username": "administrator", "password": "..." }`
  - Response `200`: `{ "accessToken": "...", "expiresIn": 28800, "user": { "username": "administrator", "displayName": "Domain Admin", "groups": ["Domain Admins"], "authSource": "LDAP" } }`
- `GET /api/v1/auth/me` → `{ "username": "...", "displayName": "...", "groups": [...], "authSource": "LDAP" | "BOOTSTRAP", "ldapDomain": "..." }`
- `POST /api/v1/auth/logout` → `204 No Content`

### Directory (`directory-auth`)
- `GET /api/v1/directory/users?search=&page=1&pageSize=25`
  - Item: `{ "username": "m.mueller", "displayName": "Max Müller", "email": "m.mueller@firma.local", "dn": "...", "groups": ["Buchhaltung", "Domain Users"] }`
- `GET /api/v1/directory/groups?search=&page=1&pageSize=25`
  - Item: `{ "name": "Buchhaltung", "description": "Abteilung Finanzbuchhaltung", "dn": "...", "memberCount": 8 }`

### Dashboard & Schema-Katalog
- `GET /api/v1/dashboard/summary`
  - Response:
    ```json
    {
      "totalDevices": 12,
      "compliantDevices": 10,
      "degradedDevices": 1,
      "errorDevices": 1,
      "offlineDevices": 0,
      "activePolicies": 4,
      "activeAssignments": 5,
      "deviceByOs": { "WINDOWS": 6, "LINUX": 4, "MACOS": 2 },
      "ldapDomain": "ad.example.org",
      "ldapSchema": "ad",
      "recentEvents": [
        { "id": "evt-1", "timestamp": "2026-11-23T18:00:00Z", "deviceHostname": "WIN-BUCH-01", "status": "COMPLIANT", "message": "4 Regeln aktiv (Revision 3)" }
      ]
    }
    ```
- `GET /api/v1/schema/catalog` → Metadaten aller registrierten `ruleType`s und Delivery-Adapter (`AGENT_PULL`, vorbereitete Hooks `SAMBA_SYSVOL`, `MOBILE_MDM`).

### Richtlinien (`policies`)
- `GET /api/v1/policies?search=&page=1&pageSize=25`
- `POST /api/v1/policies`
  - Input: `{ "name": "Basis-Sicherheit", "description": "...", "isEnabled": true, "rules": [ ... ] }`
  - Output `201`: `{ "id": "pol-...", "name": "...", "description": "...", "isEnabled": true, "revision": 1, "rules": [...], "createdAt": "...", "updatedAt": "..." }`
- `GET /api/v1/policies/{id}`
- `PATCH /api/v1/policies/{id}` (erhöht `revision` bei Regeländerungen automatisch um `+1`)
- `DELETE /api/v1/policies/{id}` → `204`

### Zuweisungen & Prioritäten (`assignments`)
- `GET /api/v1/assignments?page=1&pageSize=50` (sortiert nach `priority ASC`, wobei `1` = höchste Priorität)
- `POST /api/v1/assignments`
  - Input:
    ```json
    {
      "policyId": "pol-...",
      "priority": 1,
      "isEnabled": true,
      "targetUserType": "GROUP",
      "targetUserRef": "Buchhaltung",
      "targetDeviceType": "DEVICE_GROUP",
      "targetDeviceRef": "grp-office",
      "osFilter": ["WINDOWS", "LINUX", "MACOS"]
    }
    ```
    *(`targetUserType`: `"ALL"` | `"USER"` | `"GROUP"`; `targetDeviceType`: `"ALL"` | `"DEVICE"` | `"DEVICE_GROUP"`)*
  - Output `201`: enthält zusätzlich `id`, `policyName`, `targetDeviceGroupName`, `createdAt`, `updatedAt`.
- `PATCH /api/v1/assignments/{id}` (inkl. Prioritätsänderung)
- `POST /api/v1/assignments/reorder`
  - Input: `{ "orderedAssignmentIds": ["asg-1", "asg-2", "asg-3"] }` → vergibt atomar `priority = 1..N`.
- `DELETE /api/v1/assignments/{id}` → `204`

### Gerätegruppen & Geräte (`device-groups` & `devices`)
- `GET /api/v1/device-groups?search=&page=1&pageSize=50`
- `POST /api/v1/device-groups` → Input: `{ "name": "Büro Buchhaltung", "description": "2. OG", "tags": ["office", "finance"] }`
- `PATCH /api/v1/device-groups/{id}`
- `DELETE /api/v1/device-groups/{id}` → `204`
- `GET /api/v1/devices?search=&osFamily=&complianceStatus=&deviceGroupId=&page=1&pageSize=25`
  - Item:
    ```json
    {
      "id": "dev-...",
      "hostname": "WIN-BUCH-01",
      "osFamily": "WINDOWS",
      "osVersion": "Windows 11 Pro 24H2",
      "arch": "x86_64",
      "agentVersion": "1.0.0",
      "currentUser": "m.mueller",
      "deviceGroupIds": ["grp-office"],
      "deviceGroupNames": ["Büro Buchhaltung"],
      "appliedRevision": 3,
      "complianceStatus": "COMPLIANT",
      "lastSeenAt": "2026-11-23T18:20:00Z",
      "complianceItems": [
        { "ruleType": "security.usb_storage", "status": "APPLIED", "message": "USB mass storage blocked" }
      ],
      "createdAt": "..."
    }
    ```
- `GET /api/v1/devices/{id}`
- `PATCH /api/v1/devices/{id}` → Input: `{ "deviceGroupIds": ["grp-office"] }` (ordnet Gerät Gerätegruppen zu)
- `DELETE /api/v1/devices/{id}` (widerruft zugleich `deviceToken`)

### Effektive-Regeln-Simulator (`simulator`)
- `POST /api/v1/simulator/evaluate`
  - Input: `{ "username": "m.mueller", "deviceId": "dev-...", "osFamilyOverride": null }` (entweder `deviceId` oder `osFamilyOverride` + optionale `deviceGroupIds`)
  - Output `200`:
    ```json
    {
      "username": "m.mueller",
      "resolvedUserGroups": ["Buchhaltung", "Domain Users"],
      "device": { "id": "dev-...", "hostname": "WIN-BUCH-01", "osFamily": "WINDOWS", "deviceGroupNames": ["Büro Buchhaltung"] },
      "effectiveRules": [ ... ],
      "trace": [
        {
          "ruleType": "security.usb_storage",
          "category": "SECURITY",
          "winningPolicyId": "pol-1",
          "winningPolicyName": "IT-Ausnahme",
          "winningAssignmentId": "asg-1",
          "winningPriority": 1,
          "mergeStrategy": "OVERRIDE",
          "shadowedPolicies": [
            { "policyId": "pol-2", "policyName": "Basis-Sicherheit", "priority": 2, "action": "OVERRIDDEN" }
          ]
        }
      ]
    }
    ```

### Enrollment-Tokens & Installer (`enrollment-tokens` & `installers`)
- `GET /api/v1/enrollment-tokens?page=1&pageSize=25`
- `POST /api/v1/enrollment-tokens`
  - Input: `{ "name": "Rollout Buchhaltung", "defaultDeviceGroupId": "grp-office", "expiresInHours": 168, "maxUses": 50 }`
  - Output `201`: `{ "id": "tok-...", "name": "...", "plainToken": "apm_enroll_...", "tokenPrefix": "apm_enroll_ab12", "defaultDeviceGroupId": "grp-office", "defaultDeviceGroupName": "Büro Buchhaltung", "expiresAt": "...", "maxUses": 50, "useCount": 0, "installCommands": { "windowsPowershell": "...", "linuxBash": "...", "macosZsh": "..." } }`
- `DELETE /api/v1/enrollment-tokens/{id}` → `204`
- `GET /api/v1/installers/{script_name}` (`install.ps1`, `install-linux.sh`, `install-macos.sh`) → liefert das vorkonfigurierte Installationsskript (`text/plain`).
- `GET /api/v1/installers/binaries/{platform}/{arch}` → liefert das kompilierte Agent-Binary (bzw. `404 BINARY_NOT_BUILT` falls für eine Fremdarchitektur lokal nicht vorgebaut).

### Agent-Endpunkte (`policy-agent` ↔ `policy-core`)
- `POST /api/v1/agent/enroll` (öffentlich, geschützt durch `enrollmentToken`)
  - Input:
    ```json
    {
      "enrollmentToken": "apm_enroll_...",
      "hostname": "WIN-BUCH-01",
      "osFamily": "WINDOWS",
      "osVersion": "Windows 11 Pro 24H2",
      "arch": "x86_64",
      "agentVersion": "1.0.0",
      "machineId": "hw-uuid-1234"
    }
    ```
  - Output `201`:
    ```json
    {
      "deviceId": "dev-...",
      "deviceToken": "apm_dev_...",
      "pollIntervalSeconds": 120
    }
    ```
- `POST /api/v1/agent/checkin` (Header `Authorization: Bearer <deviceToken>`)
  - Input:
    ```json
    {
      "hostname": "WIN-BUCH-01",
      "osFamily": "WINDOWS",
      "osVersion": "Windows 11 Pro 24H2",
      "agentVersion": "1.0.0",
      "currentUser": "m.mueller",
      "appliedRevision": 2
    }
    ```
  - Output `200`:
    ```json
    {
      "deviceId": "dev-...",
      "bundleRevision": 3,
      "stateHash": "sha256:...",
      "pollIntervalSeconds": 120,
      "effectiveRules": [ ... ]
    }
    ```
- `POST /api/v1/agent/compliance` (Header `Authorization: Bearer <deviceToken>`)
  - Input:
    ```json
    {
      "appliedRevision": 3,
      "status": "COMPLIANT",
      "items": [
        {
          "ruleType": "security.usb_storage",
          "action": "ENFORCED",
          "status": "APPLIED",
          "message": "USBSTOR Start set to 4"
        },
        {
          "ruleType": "desktop.wallpaper",
          "action": "ROLLED_BACK",
          "status": "APPLIED",
          "message": "Restored previous wallpaper setting"
        }
      ]
    }
    ```
    *(`status` gesamt: `"COMPLIANT"` | `"DEGRADED"` | `"ERROR"`; Item-`status`: `"APPLIED"` | `"SKIPPED_UNSUPPORTED"` | `"FAILED"`; Item-`action`: `"ENFORCED"` | `"ROLLED_BACK"`)*
  - Output `200`: `{ "acknowledged": true, "recordedAt": "..." }`
