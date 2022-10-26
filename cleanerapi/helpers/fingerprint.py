from hashlib import sha256

from sanic import Request


def fingerprint(request: Request, seed: str) -> bytes:
    headers = request.headers
    genes = []
    for header in (
        "accept",
        "accept-encoding",
        "accept-language",
        "host",
        "origin",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
    ):
        all_values: list[str] = headers.getall(header, [])
        genes.append(str(len(all_values)))
        genes.extend(all_values)

    for referer in headers.getall("referer", []):
        genes.append(referer.split("/")[2])

    genes.append(request.ip)
    genes.append(seed)

    print("fingerprint", genes)
    return sha256(b"\x00".join(x.encode() for x in genes)).digest()
