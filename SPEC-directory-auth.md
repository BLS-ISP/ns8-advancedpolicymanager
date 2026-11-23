# Spec: `directory-auth`

## Objective
Verbindet `NS8-AdvancedPolicyManager` live mit NS8 Samba Active Directory (`schema=ad`) und NS8 OpenLDAP (`schema=rfc2307`) über `ldapproxy` und authentifiziert berechtigte Domänen-/IT-Admins anhand konfigurierbarer Gruppen (`ADMIN_GROUPS`) sowie eines optionalen Notfall-Admins.

## Tech Stack
- Python 3, FastAPI, Pydantic v2, `ldap3`
- HMAC-SHA256 signierte Bearer-Tokens + PBKDF2-HMAC-SHA256 für lokalen Bootstrap-Admin

## Commands
- Tests: `python -m pytest backend/tests/test_directory_auth.py -v`

## Project Structure
- `backend/app/config.py`
- `backend/app/directory/` (`base.py`, `ldap_provider.py`, `mock_provider.py`)
- `backend/app/auth/` (`tokens.py`, `dependencies.py`, `routes.py`)

## Boundaries
- **Always:** LDAP-Suchfilter strikt escapen (`escape_filter_chars`); verschachtelte AD-Gruppen und OpenLDAP `posixGroup`/`groupOfNames` auflösen; `InMemoryDirectoryProvider` für deterministische Offline-Tests & Dev-Modus pflegen.
- **Never:** Klartext-Passwörter loggen oder speichern.

## Success Criteria
- Login für berechtigte AD/LDAP-Gruppenmitglieder gelingt (`200`), unberechtigte Benutzer erhalten `403 FORBIDDEN`.
- Benutzer- und Gruppensuche liefern paginierte Ergebnisse gemäß `docs/contracts/api-and-policy-contract.md`.
