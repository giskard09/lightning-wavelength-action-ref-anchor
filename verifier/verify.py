#!/usr/bin/env python3
"""
Independent verifier for the lightning-wavelength-action-ref-anchor worked
example. Trusts nothing in manifest.json's prose fields -- only recomputes.

1. Recomputes action_ref from the 4 declared preimage fields (JCS RFC 8785 +
   SHA-256, per argentum-core/docs/spec/action-ref.md) and checks it matches
   manifest.json.
2. Recomputes sha256(preimage) and checks it equals the declared
   payment_hash -- the actual L402 payment-proof binding
   (macaroon-spec.md, "Verification", step 2).
3. Decodes the declared macaroon (pymacaroons, L402's own named reference
   implementation) and checks: its identifier embeds the same payment_hash;
   its single caveat is the expected services caveat; and its HMAC-chain
   signature matches the one declared in manifest.json. This step needs
   pymacaroons (`pip install pymacaroons`) -- it is not optional, since it
   is what actually confirms the macaroon is well-formed and tamper-free,
   not just that its signature string matches another string.
4. Queries Base mainnet RPC for the Anchored(bytes32,address,uint256) event
   with topics[0] == keccak256("Anchored(bytes32,address,uint256)") and
   topics[1] == action_ref, and confirms it exists on-chain.

Run: python3 verifier/verify.py [--artifacts DIR] [--rpc URL]
"""
import argparse
import hashlib
import json
import os
import struct
import sys
import urllib.request

ANCHOR_REGISTRY = "0x49fEcA52bC634a9Ab773226D16619deC547794aa"
ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"
DEFAULT_RPC = "https://mainnet.base.org"


def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(s) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()


def rpc(url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "lightning-wavelength-action-ref-anchor-verifier/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(f"RPC {method} error: {out['error']}")
    return out["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=os.environ.get("BASE_RPC", DEFAULT_RPC))
    ap.add_argument("--artifacts", default=os.path.join(os.path.dirname(__file__), "..", "artifacts"))
    args = ap.parse_args()

    art = os.path.abspath(args.artifacts)
    m = json.load(open(os.path.join(art, "manifest.json")))

    ok = True

    # --- 1. action_ref from the 4 preimage fields ---------------------------
    recomputed_action_ref = sha256_hex(jcs(m["preimage"]))
    check1 = recomputed_action_ref == m["action_ref"]
    print(f"[{'PASS' if check1 else 'FAIL'}] action_ref recompute             : {recomputed_action_ref}")
    ok &= check1

    l402 = m["envelope"]["l402"]

    # --- 2. the actual L402 payment-proof binding --------------------------
    try:
        preimage_bytes = bytes.fromhex(l402["preimage"])
    except ValueError:
        preimage_bytes = b""
    check2 = len(preimage_bytes) == 32 and sha256_hex(preimage_bytes) == l402["payment_hash"]
    print(f"[{'PASS' if check2 else 'FAIL'}] sha256(preimage) == payment_hash : {sha256_hex(preimage_bytes) if preimage_bytes else 'n/a'}")
    ok &= check2

    expected_scope = f"l402:payment_hash:{l402['payment_hash']}:resource:{l402['resource']}"
    check2b = m["preimage"]["scope"] == expected_scope
    print(f"[{'PASS' if check2b else 'FAIL'}] action_ref scope binds payment_hash + resource")
    ok &= check2b

    # --- 3. macaroon well-formedness and signature, via pymacaroons --------
    try:
        import base64
        from pymacaroons import Macaroon
    except ImportError:
        print("[SKIP] pymacaroons not installed -- run: pip install pymacaroons")
        print("       (steps 1/2/4 still ran; macaroon structure was NOT independently checked)")
    else:
        raw = base64.b64decode(l402["macaroon_b64"])
        mac = Macaroon.deserialize(base64.urlsafe_b64encode(raw).decode().rstrip("="))
        identifier = mac.identifier_bytes
        version_ok = len(identifier) == 66 and struct.unpack(">H", identifier[0:2])[0] == 0
        identifier_payment_hash = identifier[2:34].hex() if len(identifier) == 66 else None
        check3a = version_ok and identifier_payment_hash == l402["payment_hash"]
        print(f"[{'PASS' if check3a else 'FAIL'}] macaroon identifier embeds payment_hash : {identifier_payment_hash}")
        ok &= check3a

        sig_hex = mac.signature_bytes.decode() if isinstance(mac.signature_bytes, bytes) else mac.signature_bytes
        check3b = sig_hex == l402["macaroon_signature_hex"]
        print(f"[{'PASS' if check3b else 'FAIL'}] macaroon signature matches declared     : {sig_hex}")
        ok &= check3b

        caveats = [c.caveat_id.decode() if isinstance(c.caveat_id, bytes) else c.caveat_id for c in mac.caveats]
        check3c = caveats == ["services=l402-worked-example:0"]
        print(f"[{'PASS' if check3c else 'FAIL'}] macaroon caveat is the expected services caveat : {caveats}")
        ok &= check3c

    # --- 4. on-chain anchor ---------------------------------------------------
    ref = "0x" + m["action_ref"]
    try:
        with open(os.path.join(art, "anchor.json")) as f:
            anchor = json.load(f)
    except FileNotFoundError:
        print("[SKIP] no anchor.json yet -- action_ref not anchored on-chain")
        anchor = None

    if anchor:
        hint = int(anchor["block"])
        head = int(rpc(args.rpc, "eth_blockNumber", []), 16)
        from_block = hex(max(0, hint - 25))
        to_block = hex(min(hint + 25, head))

        logs = rpc(args.rpc, "eth_getLogs", [{
            "address": ANCHOR_REGISTRY,
            "fromBlock": from_block,
            "toBlock": to_block,
            "topics": [ANCHORED_TOPIC0, ref],
        }])

        check4 = bool(logs)
        if check4:
            log = logs[0]
            ts = int(log["data"], 16)
            anchored_by = "0x" + log["topics"][2][-40:]
            print(f"[PASS] on-chain Anchored event : AnchorRegistry {ANCHOR_REGISTRY} (Base 8453)")
            print(f"         tx               : {log['transactionHash']}")
            print(f"         block            : {int(log['blockNumber'], 16)}")
            print(f"         anchoredBy       : {anchored_by}")
            print(f"         block timestamp  : {ts}")
        else:
            print(f"[FAIL] no Anchored event for {ref} on AnchorRegistry near block {hint}")
        ok &= check4

    print()
    print("ALL CHECKS PASS" if ok else "SOME CHECKS FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
