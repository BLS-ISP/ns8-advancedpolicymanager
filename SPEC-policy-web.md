# Spec: `policy-web`

## Objective
Bietet eine sofort verständliche, produktionsreife Web-GUI hinter Traefik zum Erstellen von Richtlinien für Windows, Linux und macOS, Verwalten von Prioritäts-Zuweisungen, Simulieren effektiver Regeln, Überwachen der Geräte-Compliance und Ausrollen des Agenten.

## Tech Stack
- Vue 3 (Composition API `<script setup lang="ts">`), TypeScript, Vite, Vue Router, Tailwind CSS

## Commands
- Typecheck: `cd web && npm run typecheck`
- Build: `cd web && npm run build`

## Project Structure
- `web/src/api/` (typisierter Client exakt passend zu `docs/contracts/api-and-policy-contract.md`)
- `web/src/i18n/` (`de.ts` Standard + `en.ts`)
- `web/src/components/` (AppShell, OsBadges, StatusBadge, RuleBuilderCards)
- `web/src/views/` (`LoginView.vue`, `DashboardView.vue`, `PoliciesView.vue`, `AssignmentsView.vue`, `SimulatorView.vue`, `DevicesView.vue`, `EnrollView.vue`)

## Boundaries
- **Always:** Klare deutsche & englische Alltagssprache statt kryptischer Registry-Pfade; sichtbare OS-Badges (`Windows`, `Linux`, `macOS`); barrierearme Semantik (`<button>`, `<label>`, Tastaturfokus), sinnvolle Loading-/Empty-/Error-States; sachliches Enterprise-Farbschema (Slate/Blue/Emerald/Amber/Rose – kein generischer Lila-KI-Look).
- **Never:** Komponenten >250 Zeilen ohne saubere Aufteilung; ungetypte `any`-Payloads an den API-Grenzen.

## Success Criteria
- `npm run typecheck` und `npm run build` laufen mit 0 Fehlern durch.
- Alle 6 Kernansichten + Login bedienen das echte Backend fehlerfrei.
