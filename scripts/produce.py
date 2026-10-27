#!/usr/bin/env python3
"""
Derives an action_ref (action-ref-v1, argentum-core) for a REAL L402
(lightninglabs/L402) payment-and-access event, and emits the artifacts
needed to anchor + independently verify it.

Unlike this repo family's usual worked examples, nothing here is synthetic:
l402/server.py and l402/client.py are a real, running L402 server and
client; l402/server.py's merchant invoice was created by a real phoenixd
(ACINQ) node on Bitcoin testnet3, l402/client.py's payer phoenixd node (a
separate instance, funded from a public testnet3 faucet) paid that invoice
over the real Lightning Network, and the resulting preimage satisfied the
server's own macaroon+preimage verification for a 200 response. The values
embedded below are that run's literal output -- see PROVENANCE.md for the
full, qualified statement of what is and is not covered.
"""
import hashlib
import json
import os
import sys

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "artifacts"
os.makedirs(OUT_DIR, exist_ok=True)


def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(s) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()


# --- The real, captured L402 event ----------------------------------------
# All values below are this run's literal output: curl/httpx transcripts
# against two real phoenixd testnet3 daemons and l402/server.py, verified
# (sha256(preimage) == payment_hash, macaroon signature chain, HTTP 200)
# before being written here. See PROVENANCE.md.
RESOURCE_PATH = "/premium-data"
PAYMENT_HASH = "deac73759729aa8424260bb17f204574254373632474c8413d0dbb9496ee3ea8"
PREIMAGE = "e3fc9bcc0a3eeb6e8f5d5cced66add83888bb51c3c1c73489162507d2b03f1b0"
MACAROON_B64 = (
    "AgEAAkIAAN6sc3WXKaqEJCYLsX8gRXQlQ3NjJHTIQT0Nu5SW7j6ojwAKzC1TssGMhAGgVY97SwB5"
    "mfR//aprE2pukvKiRxYAAh5zZXJ2aWNlcz1sNDAyLXdvcmtlZC1leGFtcGxlOjAAAAYgYhZuntIm"
    "EsE47rBZyaEaXI8xNrUkRExIRhfg4Xdq9xE="
)
MACAROON_SIGNATURE_HEX = "62166e9ed22612c138eeb059c9a11a5c8f3136b524444c484617e0e1776af711"
RECIPIENT_AMOUNT_SAT = 50
ROUTING_FEE_SAT = 4
MERCHANT_NODE_ID = "0335ffe8fdcc8c623be1789810ff47024d1e9700587d3c074ac27784949988f10f"
PAYER_NODE_ID = "023e1fb894a79e0304fee0958681f491ddc6221142520ff793a2a1c1a06d3badd3"
CHAIN = "testnet3"
SERVED_AT_UTC = "2026-10-27T13:53:00.000Z"

assert hashlib.sha256(bytes.fromhex(PREIMAGE)).hexdigest() == PAYMENT_HASH, \
    "preimage does not hash to the declared payment_hash -- do not anchor"

# --- The four required action-ref-v1 preimage fields ------------------------
# scope binds the exact payment_hash + resource this credential was minted
# and verified for -- the two things that, together, make the access event
# unambiguous (per action-ref.md's own "scope carries whatever the domain
# needs to disambiguate the action" convention, same role as keycard-
# action-ref-anchor's target_type/target_id).
timestamp = SERVED_AT_UTC
preimage_fields = {
    "agent_id": "worked-example.lightning-wavelength-action-ref-anchor",
    "action_type": "l402.resource_access_paid",
    "scope": f"l402:payment_hash:{PAYMENT_HASH}:resource:{RESOURCE_PATH}",
    "timestamp": timestamp,
}
jcs_payload = jcs(preimage_fields)
action_ref = sha256_hex(jcs_payload)

envelope = {
    "packet_version": "1.0",
    "action_ref": action_ref,
    "hash_algo": "sha256",
    "preimage_format": "jcs-rfc8785-v1",
    "preimage": preimage_fields,
    "capability": "l402_resource_access_paid",
    "l402": {
        "payment_hash": PAYMENT_HASH,
        "preimage": PREIMAGE,
        "macaroon_b64": MACAROON_B64,
        "macaroon_signature_hex": MACAROON_SIGNATURE_HEX,
        "resource": RESOURCE_PATH,
        "recipient_amount_sat": RECIPIENT_AMOUNT_SAT,
        "routing_fee_sat": ROUTING_FEE_SAT,
        "chain": CHAIN,
        "merchant_node_id": MERCHANT_NODE_ID,
        "payer_node_id": PAYER_NODE_ID,
    },
    "generated_at_utc": timestamp,
}

manifest = {
    "fixture_id": "lightning-wavelength-l402-worked-example",
    "spec": "action-ref-v1 (argentum-core, docs/spec/action-ref.md)",
    "preimage": preimage_fields,
    "jcs_payload": jcs_payload,
    "action_ref": action_ref,
    "anchor_ref_bytes32": "0x" + action_ref,
    "anchor_registry": "0x49fEcA52bC634a9Ab773226D16619deC547794aa",
    "anchor_chain": "Base mainnet (chainId 8453)",
    "envelope": envelope,
    "l402_server_source": "l402/server.py (this repo)",
    "l402_client_source": "l402/client.py (this repo)",
    "l402_spec_reference": (
        "lightninglabs/L402 protocol-specification.md + macaroon-spec.md. "
        "One correction applied against macaroon-spec.md's documented HMAC "
        "chain, verified against pymacaroons (the spec's own named Python "
        "reference implementation): the real chain derives a key first -- "
        "derived_key = HMAC-SHA256(b'macaroons-key-generator', root_key), "
        "sig_0 = HMAC-SHA256(derived_key, identifier) -- which the doc's "
        "sig_0 = HMAC(root_key, identifier) formula omits. A macaroon minted "
        "per the doc's literal formula would not verify against pymacaroons, "
        "libmacaroons, or gopkg.in/macaroon.v2 (so not against Aperture "
        "either). See PROVENANCE.md."
    ),
    "provenance": (
        "REAL, not synthetic. l402/server.py is a real, spec-faithful L402 "
        "server; its merchant invoice was created by a real phoenixd "
        "(ACINQ) testnet3 node. l402/client.py's payer is a separate real "
        "phoenixd testnet3 node, funded from a public testnet3 faucet, "
        "which paid that invoice over the real Lightning Network. The "
        "preimage above is this run's literal payment proof: "
        "sha256(preimage) == payment_hash, independently checked before "
        "being written here, and the server's own macaroon+preimage "
        "verification returned HTTP 200 for it. Aperture (lightninglabs' "
        "reference L402 proxy) was not run -- its lndclient backend does "
        "not support phoenixd, a different Lightning implementation. See "
        "PROVENANCE.md for the full statement, including why phoenixd and "
        "testnet3 (not Wavelength's own waved/Ark stack or signet)."
    ),
}

with open(os.path.join(OUT_DIR, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")

print("=== lightning-wavelength-action-ref-anchor : producer ===")
print(f"jcs_payload = {jcs_payload}")
print(f"action_ref  = {action_ref}")
print(f"payment_hash = {PAYMENT_HASH}")
print(f"preimage     = {PREIMAGE}")
print(f"anchor ref (bytes32) = 0x{action_ref}")
print(f"wrote {OUT_DIR}/manifest.json")
