# PackageGuard v2 — deploy under your own account

This is a clean, current rebuild of PackageGuard that **you control**, replacing the
copy running on an inaccessible account. Same wallet, same endpoints, upgraded so agents
can actually discover it.

## What changed vs. the live version
- Runs on **Base mainnet** through the **Coinbase CDP facilitator** — the piece that gets
  it cataloged in the x402 **Bazaar** that agents search (the old one was absent from it).
- **Upgraded agent-facing metadata**: sharper tool description with trigger words, broader
  tags (typosquat, cve, malware, slopsquatting…), `outputSchema`, and safe-to-call
  annotations (`readOnlyHint`, `idempotentHint`) that agent loops read before calling.
- Endpoints: `GET /health` (free), `POST /check` (x402-gated, the paid path),
  `POST /mcp` (`initialize` + `tools/list` for MCP discovery).
- Wallet payee defaults to your address `0x0a51…D504`.

## Verified in sandbox
- Installs cleanly; safety logic runs against live npm / PyPI / OSV.dev
  (real packages resolve, `expresss` typosquat caught, fake package → `unsafe`).
- Mainnet config correctly **requires** CDP keys (won't run on the public testnet
  facilitator) — confirming the wiring is right.

## Deploy steps (we do these together — you log in, I drive)

1. **Coinbase CDP keys** — at https://portal.cdp.coinbase.com (same login as your wallet),
   create an API key. Copy the **Key ID** and **Secret**. These enable mainnet settlement
   and Bazaar listing.
2. **GitHub** — create a new repo `packageguard` under your account and push this folder.
3. **Render** — in the **Avenity** workspace, New → Web Service → connect the repo.
   - Build command: `npm install`
   - Start command: `npm start`
   - Environment variables (from `.env.example`):
     `RECEIVE_ADDRESS`, `NETWORK=eip155:8453`, `PRICE=$0.005`,
     `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET`
4. **Verify** — once live, `GET /health` should return `{ok:true, facilitator:"cdp"}`,
   and `POST /check` (no payment) should return HTTP 402 with mainnet payment terms.
5. **Update listings** — point the MCP Registry / Smithery entries at the new `/mcp` URL,
   then submit to Glama, PulseMCP, mcp.so, and confirm it appears in the CDP Bazaar.

## Note on the old deployment
The previous service (`packageguard-k4s4.onrender.com`) stays up until this one is verified,
so nothing breaks in the meantime. Money already flows to your wallet from either.
