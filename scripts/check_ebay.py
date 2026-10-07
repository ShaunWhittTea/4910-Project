import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
from product_api import EbayApiError, EbayProductApiClient


def main() -> int:
    load_dotenv(PROJECT_ROOT / ".env")

    client_id = os.getenv("EBAY_CLIENT_ID", "").strip()
    client_secret = os.getenv("EBAY_CLIENT_SECRET", "").strip()

    if not client_id or not client_secret:
        print("Missing EBAY_CLIENT_ID or EBAY_CLIENT_SECRET in local .env.")
        return 1

    client = EbayProductApiClient(
        client_id,
        client_secret,
        sandbox=True,
    )

    query = " ".join(sys.argv[1:]).strip() or "thermos"

    try:
        products = client.search(query)
    except EbayApiError as exc:
        cause = exc.__cause__

        print(f"Adapter error: {exc}")

        if isinstance(cause, HTTPError):
            print(f"HTTP status: {cause.code}")
        elif isinstance(cause, URLError):
            print(f"Connection reason: {cause.reason}")
        elif cause is not None:
            print(f"Underlying error type: {type(cause).__name__}")
            print(f"Underlying error: {cause}")
        else:
            print("No underlying exception; adapter rejected the response.")

        return 1

    print(f"Sandbox request succeeded for query: {query!r}")
    print(f"Normalized USD products returned: {len(products)}")

    for product in products[:5]:
        print(
            f"{product.external_product_id} | "
            f"{product.title} | "
            f"${product.price_usd:.2f}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())