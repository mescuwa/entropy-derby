# Reference Server (Placeholder)

This directory will house a minimal HTTP API that exposes the Inside Track engine. The current plan:

1. Implement a lightweight REST server (e.g., drogon, oatpp, cpp-httplib).
2. Endpoints:
   - `POST /commit` – publishes the latest `serverSeed` hash.
   - `POST /bet` – accepts `{horseId, stake, clientSeed}` and stores them in SQLite.
   - `POST /settle` – closes the race, runs `ProvablyFairRng`, resolves bets, and records payouts.
   - `GET /race/:id` – returns `{serverSeed, clientSeed, nonce, winner}` for public verification.
3. Persistence: SQLite or Postgres for bets, commitments, and settlement records.
4. Authentication: API keys or OAuth for back-office tooling; signed requests for partners.
5. Observability: Structured JSON logs plus Prometheus metrics for commitments, exposures, and payout ratios.

The HTTP layer will remain optional; the engine itself stays framework-agnostic so operators can embed it inside any stack (C++, Rust, Go, or even WASM).

