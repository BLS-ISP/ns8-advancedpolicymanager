# Statement of Intent: NS8-AdvancedPolicyManager

**Status:** Bestätigt (2026-11-23)

## Kurzfassung

- **Ziel (Outcome):** Eigenständiges NethServer-8-Modul (`NS8-AdvancedPolicyManager`) mit intuitiver Web-GUI und leichtgewichtigem Cross-Platform-Policy-Agenten zur zentralen Umsetzung von Benutzer-, Gruppen- und Computer-Richtlinien auf **Windows, Linux und macOS**.
- **Zielgruppe (User):** NS8-Cluster-Admins sowie delegierte IT-/Domänen-Admins (Anmeldung an der dedizierten Policy-Web-App über konfigurierbare LDAP/AD-Gruppen ohne vollen NS8-Cluster-Root-Zugriff).
- **Warum jetzt (Auslöser):** NethServer 8 besitzt von Haus aus keine eigene Richtlinien-GUI; Windows-RSAT (`gpmc.msc`) ist unübersichtlich, liefert keinerlei Status- oder Fehler-Rückmeldung vom Client und schließt Linux, macOS sowie OpenLDAP-Domänen aus.
- **Erfolgskriterium (Success):**
  - Benutzer und Benutzergruppen werden live aus der angebundenen NS8 User Domain (**Samba AD** und **OpenLDAP**) geladen.
  - Verwaltete Computer registrieren sich über den mitgelieferten Agenten per Enrollment-Token und lassen sich direkt in der GUI in eigene **Gerätegruppen/Standorte** organisieren.
  - Die **4 Kern-Regelbereiche für v1** lassen sich nach klarer Priorität zuweisen, als *Effektive Regeln* simulieren, auf Windows/Linux/macOS durchsetzen, beim Entfernen sauber zurückrollen (**Desired-State Rollback**) und per Live-Compliance-Status überwachen:
    1. **Zugriff & Berechtigungen:** Anmeldeberechtigungen pro Gerät/Gruppe sowie lokale Admin- bzw. `sudo`-Rechte.
    2. **Arbeitsumgebung:** Automatische Netzlaufwerke (SMB/NFS), Drucker-Anbindung und Login-/Start-Skripte.
    3. **Sicherheit & Geräte:** Bildschirmsperre / Inaktivitäts-Timeout, USB-/Wechseldatenträger-Sperre, Basis-Firewall-Regeln.
    4. **Desktop & Apps:** Browser-Vorgaben (Startseite, Pflicht-Erweiterungen, Restriktionen), Hintergrundbild und Sperren ausgewählter Systemeinstellungen.
- **Rahmenbedingungen & Erweiterbarkeit (Constraints):**
  - Regelkonformes Rootless-NS8-Modul (Podman gebunden an `127.0.0.1:${TCP_PORT}`, HTTPS-Veröffentlichung über NS8-Traefik, Verzeichniszugriff über NS8 `ldapproxy`, NS8-Cockpit-Panel für Modul-Setup/Status, Restic-Backup/Restore/Clone).
  - Konfliktfreie Koexistenz auf Server und Endgeräten neben dem bestehenden separaten NS8-Modul für Software-/Patch-Deployment.
  - **Offene Schema- & Adapter-Architektur von Tag 1:** Policy-Definitionen und Zustell-Adapter sind so gekapselt, dass spätere Ausbaustufen (v2+) ohne Umbau des Kerns ergänzt werden können:
    - Finetuning-Katalog für tiefgehende Einzelschalter (Registry / ADMX / `dconf` / `plist`),
    - optionaler nativer Samba-AD-`SYSVOL`/GPO-Exporter,
    - optionale Mobile-MDM-Anbindung (iOS / Android).
- **Bewusst nicht in v1 (Out of scope):**
  - Kein Software- oder Patch-Deployment (bereits durch separates eigenes NS8-Modul abgedeckt).
  - Kein Smartphone-MDM (iOS/Android), kein direktes Beschreiben fremder Samba-`SYSVOL`-Container und noch kein Vollsortiment tausender roher ADMX-Einzelschalter in v1 (architektonisch vorbereitet für spätere Ausbaustufen).
