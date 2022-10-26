import base64

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64parse(data: str) -> bytes | None:
    try:
        return base64.b64decode(data)
    except ValueError:
        return None


def custom_b64encode(data: bytes, alphabet: str) -> str:
    encoded = base64.b64encode(data)
    translation = str.maketrans(alphabet, BASE64_ALPHABET)
    return encoded.decode().translate(translation)


def custom_b64decode(data: str, alphabet: str) -> bytes:
    translation = str.maketrans(alphabet, BASE64_ALPHABET)
    return base64.b64decode(data.translate(translation))
