#!/usr/bin/env python3
"""Minimal, spec-faithful L402 server (lightninglabs/L402), backed by phoenixd.

Not Aperture. phoenixd (ACINQ's non-custodial Lightning server) is not an lnd
node, so Aperture's lndclient-based backend cannot point at it. This
implements the published L402 protocol-specification.md and macaroon-spec.md
directly, using pymacaroons (named as L402's own Python reference
implementation) for macaroon minting/verification -- not Aperture's code,
and not a hand-rolled macaroon encoder.

One correction applied against the spec doc, verified byte-for-byte: the doc
gives sig_0 = HMAC(root_key, identifier). The real chain used by pymacaroons,
libmacaroons and gopkg.in/macaroon.v2 (so by Aperture itself) is:
    derived_key = HMAC-SHA256(b"macaroons-key-generator", root_key)
    sig_0       = HMAC-SHA256(derived_key, identifier)
A macaroon minted per the doc's literal formula would not verify against any
real macaroon library. pymacaroons does the derivation internally; this file
never computes raw HMAC itself, it only prepares the spec-shaped identifier
and caveats and lets the library do the chaining.
"""
import base64
import hashlib
import os
import struct
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from pymacaroons import Macaroon, Verifier
from pymacaroons.macaroon import MACAROON_V2
from pymacaroons.serializers import BinarySerializer

MERCHANT_URL = "http://127.0.0.1:9743"
MERCHANT_PW = "merchantpw_l402test"
PRICE_SAT = 50
RESOURCE_PATH = "/premium-data"
SERVICE_NAME = "l402-worked-example"

app = FastAPI()

# payment_hash (bytes) -> root_key (bytes). In-memory, single-process demo.
_root_keys: dict[bytes, bytes] = {}


def _b64std(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _mint_macaroon(payment_hash: bytes) -> Macaroon:
    """macaroon-spec.md 'Minting': version(2) || payment_hash(32) || token_id(32)."""
    root_key = os.urandom(32)
    token_id = os.urandom(32)
    identifier = struct.pack(">H", 0) + payment_hash + token_id
    m = Macaroon(location=None, identifier=identifier, key=root_key, version=MACAROON_V2)
    m = m.add_first_party_caveat(f"services={SERVICE_NAME}:0")
    _root_keys[payment_hash] = root_key
    return m


async def _create_invoice() -> tuple[str, bytes]:
    """Returns (bolt11, payment_hash_bytes) from the merchant phoenixd."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{MERCHANT_URL}/createinvoice",
            auth=("", MERCHANT_PW),
            data={
                "amountSat": str(PRICE_SAT),
                "description": f"L402 worked example: {RESOURCE_PATH}",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        payment_hash = bytes.fromhex(data["paymentHash"])
        return data["serialized"], payment_hash


def _verify_credential(macaroon_b64: str, preimage_hex: str) -> Optional[str]:
    """Returns None on success, or an error string. macaroon-spec.md Verification."""
    try:
        m = Macaroon.deserialize(
            base64.urlsafe_b64encode(base64.b64decode(macaroon_b64)).decode().rstrip("=")
        )
    except Exception as e:
        return f"malformed macaroon: {e}"

    identifier = m.identifier_bytes
    if len(identifier) != 66:
        return "malformed identifier"
    version = struct.unpack(">H", identifier[0:2])[0]
    if version != 0:
        return "unsupported identifier version"
    payment_hash = identifier[2:34]

    root_key = _root_keys.get(payment_hash)
    if root_key is None:
        return "unknown or revoked macaroon"

    try:
        preimage = bytes.fromhex(preimage_hex)
    except ValueError:
        return "malformed preimage"
    if len(preimage) != 32:
        return "malformed preimage length"
    if hashlib.sha256(preimage).digest() != payment_hash:
        return "invalid preimage"

    verifier = Verifier()
    verifier.satisfy_general(lambda cav: cav == f"services={SERVICE_NAME}:0")
    try:
        verifier.verify(m, root_key)
    except Exception as e:
        return f"signature/caveat verification failed: {e}"

    return None


@app.get(RESOURCE_PATH)
async def premium_data(request: Request, authorization: Optional[str] = Header(default=None)):
    if authorization is None:
        bolt11, payment_hash = await _create_invoice()
        macaroon = _mint_macaroon(payment_hash)
        macaroon_b64 = _b64std(BinarySerializer().serialize_raw(macaroon))
        challenge = f'L402 macaroon="{macaroon_b64}", invoice="{bolt11}"'
        return Response(
            status_code=402,
            headers={"WWW-Authenticate": challenge},
            content="payment required",
        )

    scheme, _, credential = authorization.partition(" ")
    if scheme.upper() != "L402" or ":" not in credential:
        return JSONResponse(status_code=401, content={"error": "malformed Authorization header"})
    macaroon_b64, _, preimage_hex = credential.partition(":")

    error = _verify_credential(macaroon_b64, preimage_hex)
    if error is not None:
        return JSONResponse(status_code=401, content={"error": error})

    return JSONResponse(
        status_code=200,
        content={
            "resource": RESOURCE_PATH,
            "data": "this is the premium resource, served after a real L402 payment",
            "served_at_unix": int(time.time()),
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8900, log_level="info")
