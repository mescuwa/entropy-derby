# Frontend Placeholder

Future work:

- React or Svelte single-page app for bettors.
- Features:
  - Displays server commitment before betting window opens.
  - Collects stake, selected horse, and client seed.
  - Streams live race simulation frames (reuse ASCII or SVG rendering).
  - Shows settlement receipts plus verification instructions.
- Integrations:
  - REST API for bet placement and settlement.
  - WebSocket channel for race status updates.
- Responsible gambling UX: limits, cooldowns, educational links.

The frontend is intentionally separate from the engine so that jurisdictions can adapt branding, compliance messaging, and languages without touching the core C++ logic.

