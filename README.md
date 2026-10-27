# lightning-wavelength-action-ref-anchor

A worked example that derives an **`action_ref`** — a deterministic,
content-addressed identifier for an agent action
([`action-ref-v1`](https://github.com/giskard09/argentum-core/blob/master/docs/spec/action-ref.md)) —
for a **real** L402 ([Lightning HTTP 402](https://github.com/lightninglabs/L402))
payment-and-access event, and anchors it permissionlessly on-chain.

Lightning Labs' [Wavelength mainnet launch](https://lightning.engineering/posts/2026-10-23-wavelength-mainnet-launch/)
(2026-10-23) describes agents paying autonomously via L402, "no human
approving each payment." L402 solves agent-pays-autonomously. It says
nothing about a third party later verifying what the agent did with what
it paid for, without trusting the agent or the paying operator — the same
gap this repo family has found, undocumented, behind every payment layer
it has checked (Visa OUSD, Cloudflare's Monetization Gateway, AWS
CloudFront, Sapiom, coinbase x402 deployments). This is the first time we
found it behind a **real, live, four-day-old** venue instead of a press
release.

> **Provenance, up front (read `PROVENANCE.md` for the full statement).**
> Everything here is real except one piece, clearly flagged: Aperture
> (Lightning Labs' own reference L402 proxy) was not run, because its
> backend is `lnd`-only and our Lightning infrastructure is `phoenixd`
> (ACINQ), a different implementation. `l402/server.py` implements the
> published L402 spec directly against `phoenixd` instead. The payment
> itself, the preimage, the macaroon, and the `action_ref` derivation are
> all real — a real `402` challenge, a real BOLT11 invoice, a real
> Lightning payment between two independent `phoenixd` testnet3 nodes, a
> real preimage, a real `200 OK`. Also documented: a byte-verified
> discrepancy between `macaroon-spec.md`'s published HMAC chain formula
> and the chain its own named reference implementations (`pymacaroons`,
> `libmacaroons`, `gopkg.in/macaroon.v2` — so Aperture too) actually
> compute.

## The gap

L402 binds a macaroon to a Lightning payment's hash so a server can verify
*that it was paid* with no database lookup. It says nothing about what
happens after: once the agent presents a valid macaroon+preimage and gets
its `200 OK`, nothing about that specific exchange — which resource, which
payment, at what time — is independently checkable by a party who was not
the server itself. The server's own logs are the only record.

```
   Client                    L402 server                public chain (Base)
   ┌──────────────┐         ┌──────────────────┐        ┌────────────────────┐
   │ pays invoice   │ 402/pay│ payment_hash,      │ bind  │ AnchorRegistry     │
   │ gets preimage  │───────▶│ preimage, macaroon,│──────▶│  anchor(bytes32)   │
   │ gets resource  │        │ resource path      │ ref   │  Anchored(ref,..)  │
   └──────────────┘         └──────────────────┘        └────────────────────┘
                                                           operator-independent
                                                           timestamp / finality
```

## Doctrine: spec-agnostic to L402's format

We derive `action_ref` from the four canonical fields only. We do not ask
Lightning Labs, ACINQ, or anyone running an L402 server to change
anything. `payment_hash`, `preimage`, and the macaroon are already L402's
own values — this just shows them anchored.

## What's here

| Path | What it is |
|------|-----------|
| `l402/server.py` | A real, spec-faithful L402 server backed by `phoenixd`'s HTTP API — not Aperture. |
| `l402/client.py` | Drives the full `402` → pay → `Authorization` retry flow against a real payer `phoenixd` node. |
| `scripts/produce.py` | Derives `action_ref` per `action-ref-v1` (JCS RFC 8785 + SHA-256) from that run's real, captured output. |
| `verifier/verify.py` | Independent verifier: recomputes `action_ref`, re-checks `sha256(preimage) == payment_hash`, independently re-decodes and re-verifies the macaroon via `pymacaroons`, and confirms the matching `Anchored` event on Base mainnet. |
| `artifacts/` | The canonical instance: `manifest.json` (preimage, payment/macaroon evidence, envelope) and `anchor.json` (tx/block, once anchored). |
| `scripts/anchor.sh` | The equivalent `cast` command to anchor `action_ref`. |
| `PROVENANCE.md` | Exactly what is and isn't covered — including the one piece (Aperture) not run, and the macaroon-spec.md HMAC chain correction. Read it. |

## Reproduce

```bash
pip install fastapi uvicorn httpx pymacaroons

# 1. run two phoenixd testnet3 instances (merchant + payer), fund the payer
#    from a public testnet3 faucet, start l402/server.py on :8900

# 2. drive the real flow
python3 l402/client.py --payer-password <payer phoenixd http password>

# 3. derive action_ref from the captured run
python3 scripts/produce.py artifacts

# 4. anchor action_ref on Base mainnet (see scripts/anchor.sh)
bash scripts/anchor.sh

# 5. independently verify everything, including the macaroon and the on-chain event
python3 verifier/verify.py
```

## This instance

- `payment_hash`: `deac73759729aa8424260bb17f204574254373632474c8413d0dbb9496ee3ea8`
- `preimage`: `e3fc9bcc0a3eeb6e8f5d5cced66add83888bb51c3c1c73489162507d2b03f1b0`
  (real Lightning Network testnet3 payment, 50 sats + 4 sats routing fee)
- `action_ref`: `6422c5adbb2521e62f97722dcfee7c682968fe1cd4c889b113fa74e5e6343698`
- Anchor status: **pending** — not yet anchored on Base mainnet.

## License

MIT — see `LICENSE`.
