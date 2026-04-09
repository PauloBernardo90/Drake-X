"""Target data model.

Targets are produced exclusively by :func:`drake_x.scope.parse_target`. They
are immutable on the API surface (we use :class:`pydantic.BaseModel` rather
than dataclasses purely for serialization, validation, and JSON-schema use).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..constants import ALL_TARGET_TYPES


class Target(BaseModel):
    """A normalized scan target.

    For URL targets, ``canonical`` is the **resource-level** form — the full
    URL including any query string the user supplied — while ``host`` and
    :meth:`host_canonical` give a host-level form for tools that only operate
    on hosts (nmap, sslscan, whois, dig). Tools that operate on URLs
    (curl, whatweb, nikto) should use ``canonical`` so they probe exactly the
    resource the user asked about.
    """

    model_config = ConfigDict(frozen=True)

    raw: str = Field(..., description="The user-supplied input, exactly as given.")
    canonical: str = Field(
        ...,
        description=(
            "Canonicalized form. For URL targets this includes scheme, host, "
            "explicit port, path, and query string."
        ),
    )
    target_type: str = Field(
        ...,
        description="One of: ipv4, ipv6, cidr, domain, url.",
    )
    host: str = Field(..., description="The host or network address derived from the input.")

    cidr_prefix: int | None = Field(default=None, description="Prefix length for CIDR targets.")
    url_scheme: str | None = Field(default=None, description="URL scheme for URL targets.")
    url_port: int | None = Field(default=None, description="URL port if explicit in input.")
    url_path: str | None = Field(default=None, description="URL path if URL target.")
    url_query: str | None = Field(
        default=None,
        description="URL query string (without leading '?') if present.",
    )
    url_fragment: str | None = Field(
        default=None,
        description="URL fragment (without leading '#') if present.",
    )

    def is_network(self) -> bool:
        return self.target_type in {"ipv4", "ipv6", "cidr"}

    def is_web(self) -> bool:
        return self.target_type in {"url", "domain"}

    @property
    def display(self) -> str:
        return self.canonical

    @property
    def host_canonical(self) -> str:
        """Host-level canonical form, useful for tools that don't speak URLs.

        For URL targets this is ``scheme://host[:port]`` with no path or
        query. For non-URL targets it is identical to :attr:`canonical`.
        """
        if self.target_type != "url":
            return self.canonical
        base = f"{self.url_scheme}://{self.host}" if self.url_scheme else self.host
        if self.url_port:
            base = f"{base}:{self.url_port}"
        return base

    def model_post_init(self, __context: object) -> None:  # pragma: no cover - trivial
        if self.target_type not in ALL_TARGET_TYPES:
            raise ValueError(f"Unknown target_type: {self.target_type}")
