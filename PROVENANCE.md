# Provenance — read this before drawing any conclusion

This document states exactly what is real and what is not in this worked
example. Unlike most of this repo family (which anchor a *synthetic*
action against a target's real code), this one anchors a **real** payment
and a **real** credential — read the one thing that is genuinely out of
scope just as carefully as the rest.

## What is real

- A real L402 (Lightning HTTP 402) server (`l402/server.py`) and client
  (`l402/client.py`), written against
  [lightninglabs/L402](https://github.com/lightninglabs/L402)'s published
  `protocol-specification.md` and `macaroon-spec.md`.
- A real `402 Payment Required` challenge, with a real
  [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
  invoice created by a real `phoenixd` (ACINQ) daemon on Bitcoin testnet3.
- A real Lightning payment: a **second**, independent `phoenixd` testnet3
  instance — funded from a public testnet3 faucet, no pre-existing balance
  — paid that invoice over the real Lightning Network and received a real
  preimage back.
- `sha256(preimage) == payment_hash` — checked independently, twice (once
  before writing `scripts/produce.py`'s constants, once again by
  `verifier/verify.py`), not assumed from either phoenixd's or the
  server's own report.
- The retried request with `Authorization: L402 <macaroon>:<preimage>`
  received a real `200 OK` from `l402/server.py`. Negative controls were
  run and behaved per spec before this artifact was produced: a wrong
  preimage and a single-bit-tampered macaroon both got `401`; the same
  valid credential reused got `200` again (L402 is a stateless bearer
  credential — the spec does not require single-use, so this is not a
  replay bug).
- `action_ref` is derived exactly per `action-ref-v1`
  ([argentum-core/docs/spec/action-ref.md](https://github.com/giskard09/argentum-core/blob/master/docs/spec/action-ref.md)):
  SHA-256 of the RFC 8785 JCS canonicalization of the four preimage fields
  (`agent_id`, `action_type`, `scope`, `timestamp`). `scope` binds the
  exact `payment_hash` and resource path this credential was minted and
  verified for.
- The macaroon itself is minted and verified with
  [`pymacaroons`](https://github.com/ecordell/pymacaroons) — the Python
  reference implementation `macaroon-spec.md` names — not a hand-rolled
  binary encoder. `verifier/verify.py` independently re-decodes the
  macaroon with `pymacaroons` and checks its identifier, signature, and
  caveat against the declared values; it does not just string-compare
  manifest.json fields against themselves.
- **A real correction to the published spec, verified byte-for-byte.**
  `macaroon-spec.md` documents the HMAC chain as `sig_0 = HMAC(root_key,
  identifier)`. The real chain `pymacaroons` computes — and which
  `libmacaroons` and `gopkg.in/macaroon.v2` (so Aperture itself) also
  compute — derives a key first:
  ```
  derived_key = HMAC-SHA256(b"macaroons-key-generator", root_key)
  sig_0       = HMAC-SHA256(derived_key, identifier)
  ```
  Confirmed by computing both forms against `pymacaroons`' real output for
  the same `(root_key, identifier)`: the documented formula does not
  match; the key-derived formula matches exactly, with and without
  caveats chained on top. A macaroon minted per the doc's literal formula
  would not verify against `pymacaroons`, `libmacaroons`, or
  `gopkg.in/macaroon.v2` — and so would not verify against Aperture
  either. This repo's server and verifier both use the real (key-derived)
  chain, via `pymacaroons`, not the doc's formula.
- The on-chain anchor, once executed, is a real transaction on Base
  mainnet, independently checkable by anyone via `verifier/verify.py`.

## What is not covered — declared

- **Aperture, lightninglabs' own reference L402 proxy, was not run.**
  Its backend is `lndclient`-only (`sample-conf.yaml`: an `lnd` RPC
  host:port, TLS cert path, macaroon directory) — there is no
  configuration path to a different Lightning implementation. `phoenixd`
  is ACINQ's non-custodial Lightning server, a different implementation
  with its own REST API; it is not `lnd`, and no `lnd` node exists in our
  infrastructure. `l402/server.py` implements the published L402 spec
  directly against `phoenixd` instead — a legitimate path, since L402 is
  backend-agnostic by design (any node that can issue a BOLT11 invoice and
  learn the resulting preimage can back it), but it is **our own
  implementation of the spec, not a run of Aperture's code.**
- **Wavelength's own `waved`/`wavecli` stack (Ark client, swap engine, MCP
  tool surface) was not exercised.** This worked example targets the L402
  protocol specifically — which Lightning Labs' 2026-10-23 mainnet launch
  post describes Wavelength as using, and which Aperture (also Lightning
  Labs) implements — not Wavelength's wallet daemon itself. No `waved`
  binary was run, no Ark channel was boarded, no `wavecli` command was
  issued.
- **Testnet3, not Wavelength's signet.** Lightning Labs' own signet
  endpoints (`signet.wavelength.lightning.finance`) are Wavelength/Ark
  infrastructure; `phoenixd` supports only `mainnet` and `testnet`
  (`Chain.Testnet3` in its source, no signet, no regtest). The payment in
  this worked example is a real Lightning Network payment on Bitcoin
  testnet3 — a different public test network than the one Wavelength's
  own demo uses, chosen because it is what our actual backend (`phoenixd`)
  supports.
- No mainnet sats moved for the Lightning payment itself (testnet3 coins
  have no value). The on-chain anchor transaction is the one real-money
  step in this worked example, and it anchors a 32-byte digest only — it
  never touches the Lightning payment's funds.

## What this therefore does and does not show

- **Does show:** a real, end-to-end L402 challenge/pay/verify cycle,
  backed by real `phoenixd` nodes and a real (not fabricated) preimage,
  with `action_ref` derived from and bound to that specific payment and
  resource, and that derivation anchored on a public chain independent of
  either phoenixd instance, this server, or Lightning Labs' own
  infrastructure. It also shows a concrete, reproducible discrepancy
  between `macaroon-spec.md`'s documented HMAC chain and the chain its own
  named reference implementations actually compute.
- **Does not show:** that Lightning Labs, ACINQ, or anyone else has
  integrated, endorsed, or adopted `action_ref`. It is not a report that
  Aperture is broken (Aperture's own code, via `gopkg.in/macaroon.v2`,
  uses the correct key-derived chain — only `macaroon-spec.md`'s prose
  documents the simpler, non-matching formula). It does not exercise
  Wavelength's own Ark/swap/wallet stack, and the payment is on testnet3,
  not Wavelength's signet. No claim of adoption, no claim that this
  matches exactly how a production L402 deployment would be wired. If
  someone reads it as adoption, that reading is wrong.
