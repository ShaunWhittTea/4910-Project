import base64
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ExternalProduct:
    """Normalized product shape used by every external product provider."""

    external_product_id: str
    title: str
    description: str | None
    price_usd: float
    image_url: str | None
    availability: str = "AVAILABLE"


class ProductApiClient(Protocol):
    """One reusable interface for all external product API providers."""

    def search(self, query: str) -> list[ExternalProduct]:
        """Return products whose titles match the supplied query."""

    def get_by_external_id(
        self,
        external_product_id: str,
    ) -> ExternalProduct | None:
        """Return one product or None when it cannot be found."""


class FixtureProductApiClient:
    """
    Local development implementation.

    Replace or supplement this class later with an eBay/Etsy/etc. client
    that implements the same ProductApiClient interface.
    """

    def __init__(self) -> None:
        self._products = [
            ExternalProduct(
                external_product_id="fixture-headphones-01",
                title="Wireless Headphones",
                description="Over-ear Bluetooth headphones.",
                price_usd=24.99,
                image_url=None,
            ),
            ExternalProduct(
                external_product_id="fixture-thermos-01",
                title="Insulated Travel Thermos",
                description="Stainless-steel thermos for long hauls.",
                price_usd=19.99,
                image_url=None,
            ),
        ]

    def search(self, query: str) -> list[ExternalProduct]:
        normalized_query = query.strip().lower()

        if not normalized_query:
            return list(self._products)

        return [
            product
            for product in self._products
            if normalized_query in product.title.lower()
        ]

    def get_by_external_id(
        self,
        external_product_id: str,
    ) -> ExternalProduct | None:
        return next(
            (
                product
                for product in self._products
                if product.external_product_id == external_product_id
            ),
            None,
        )

class EbayApiError(RuntimeError):
    """An eBay request or response could not be processed."""


def _read_json(request: Request, *, timeout: float) -> dict:
    """Make one HTTP request and require a JSON object response."""
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise EbayApiError("eBay request failed") from exc

    if not isinstance(payload, dict):
        raise EbayApiError("eBay returned an unexpected response")

    return payload


class EbayProductApiClient:
    """Browse API client; constructing it does not contact eBay."""

    SCOPE = "https://api.ebay.com/oauth/api_scope"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        sandbox: bool = False,
        timeout: float = 10.0,
    ) -> None:
        if not client_id or not client_secret:
            raise ValueError("eBay client ID and secret are required")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        host = "api.sandbox.ebay.com" if sandbox else "api.ebay.com"
        self.base_url = f"https://{host}"
        self._access_token: str | None = None
        self._expires_at = 0.0

    def _token(self) -> str:
        if self._access_token and time.monotonic() < self._expires_at:
            return self._access_token

        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode("utf-8")
        ).decode("ascii")
        body = urlencode(
            {"grant_type": "client_credentials", "scope": self.SCOPE}
        ).encode("ascii")
        request = Request(
            f"{self.base_url}/identity/v1/oauth2/token",
            data=body,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        payload = _read_json(request, timeout=self.timeout)

        token = payload.get("access_token")
        try:
            expires_in = int(payload.get("expires_in", 0))
        except (TypeError, ValueError) as exc:
            raise EbayApiError("eBay returned an invalid token lifetime") from exc

        if not isinstance(token, str) or not token or expires_in <= 0:
            raise EbayApiError("eBay returned an invalid access token")

        self._access_token = token
        self._expires_at = time.monotonic() + max(0, expires_in - 60)
        return token

    def _get(self, path: str, *, params: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"

        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {self._token()}",
                "Accept": "application/json",
                "X-EBAY-C-MARKETPLACE-ID": "EBAY_US",
            },
            method="GET",
        )
        return _read_json(request, timeout=self.timeout)

    @staticmethod
    def _normalize(item: dict) -> ExternalProduct | None:
        if not isinstance(item, dict):
            return None

        item_id = item.get("itemId")
        title = item.get("title")
        price = item.get("price")
        if (
            not isinstance(item_id, str)
            or not item_id
            or not isinstance(title, str)
            or not title
            or not isinstance(price, dict)
            or price.get("currency") != "USD"
        ):
            return None

        try:
            price_usd = float(price["value"])
        except (KeyError, TypeError, ValueError):
            return None
        if price_usd < 0:
            return None

        image = item.get("image")
        image_url = image.get("imageUrl") if isinstance(image, dict) else None

        availability = "AVAILABLE"
        estimated = item.get("estimatedAvailabilities")
        if isinstance(estimated, list) and estimated:
            first = estimated[0]
            if (
                isinstance(first, dict)
                and first.get("estimatedAvailabilityStatus") == "OUT_OF_STOCK"
            ):
                availability = "UNAVAILABLE"

        description = item.get("shortDescription")
        if not isinstance(description, str):
            description = None

        return ExternalProduct(
            external_product_id=item_id,
            title=title,
            description=description,
            price_usd=price_usd,
            image_url=image_url if isinstance(image_url, str) else None,
            availability=availability,
        )

    def search(self, query: str) -> list[ExternalProduct]:
        query = query.strip()
        if not query:
            return []

        payload = self._get(
            "/buy/browse/v1/item_summary/search",
            params={"q": query, "limit": 25, "fieldgroups": "EXTENDED"},
        )
        summaries = payload.get("itemSummaries", [])
        if not isinstance(summaries, list):
            raise EbayApiError("eBay returned invalid search results")

        return [
            product
            for item in summaries
            if (product := self._normalize(item)) is not None
        ]

    def get_by_external_id(
        self,
        external_product_id: str,
    ) -> ExternalProduct | None:
        if not external_product_id.strip():
            return None

        try:
            payload = self._get(
                f"/buy/browse/v1/item/{quote(external_product_id, safe='')}"
            )
        except EbayApiError as exc:
            if isinstance(exc.__cause__, HTTPError) and exc.__cause__.code == 404:
                return None
            raise

        product = self._normalize(payload)
        if product is None:
            raise EbayApiError("eBay returned an unsupported or invalid item")
        return product