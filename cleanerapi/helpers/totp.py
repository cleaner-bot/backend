import hmac


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    hmac_digest = hmac.new(
        secret, counter.to_bytes(8, "big", signed=False), "sha1"
    ).digest()
    return str(truncate(hmac_digest))[-digits:]


def truncate(hmac_digest: bytes) -> int:
    offset = hmac_digest[-1] & 0b1111
    binary = (
        int.from_bytes(hmac_digest[offset : offset + 4], "big", signed=False)
        & 0x7FFFFFFF
    )
    return binary
