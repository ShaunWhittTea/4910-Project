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