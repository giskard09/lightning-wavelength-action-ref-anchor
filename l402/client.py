#!/usr/bin/env python3
"""Drives the full L402 flow against l402/server.py, end to end, using two
real phoenixd testnet3 nodes: one as the client's payer wallet, one backing
the server's merchant invoice. Prints the real artifacts (invoice, macaroon,
preimage, response) needed for scripts/produce.py -- it does not fabricate
or pre-compute any of them.
"""
import argparse
import json
import sys

import httpx

RESOURCE_URL = "http://127.0.0.1:8900/premium-data"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--payer-url", default="http://127.0.0.1:9744")
    ap.add_argument("--payer-password", required=True)
    args = ap.parse_args()

    r1 = httpx.get(RESOURCE_URL)
    if r1.status_code != 402:
        print(f"expected 402, got {r1.status_code}: {r1.text}", file=sys.stderr)
        sys.exit(1)

    challenge = r1.headers["www-authenticate"]
    params = {}
    for part in challenge[len("L402 "):].split(", "):
        k, _, v = part.partition("=")
        params[k] = v.strip('"')
    macaroon_b64, invoice = params["macaroon"], params["invoice"]

    pay = httpx.post(
        f"{args.payer_url}/payinvoice",
        auth=("", args.payer_password),
        data={"invoice": invoice},
        timeout=30,
    )
    pay.raise_for_status()
    payment = pay.json()
    preimage_hex = payment["paymentPreimage"]

    r2 = httpx.get(RESOURCE_URL, headers={"Authorization": f"L402 {macaroon_b64}:{preimage_hex}"})

    result = {
        "challenge": {"macaroon_b64": macaroon_b64, "invoice": invoice},
        "payment": payment,
        "final_status": r2.status_code,
        "final_body": r2.json() if r2.status_code == 200 else r2.text,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
