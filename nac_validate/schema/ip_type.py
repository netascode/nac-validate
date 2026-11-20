# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""``ip(type=...)``: the form of an IP value.

Yamale's ``ip()`` accepts an address with or without a prefix length. ``type``
restricts it to comma-separated forms:

- ``address``: an address without prefix length, e.g. ``10.0.0.1``
- ``interface``: a host address with prefix length, e.g. ``10.0.0.1/24``. The
  network address and the IPv4 broadcast address of the subnet
  (``10.0.0.0/24``, ``10.0.0.255/24``) are not host addresses, nor is the
  IPv6 subnet-router anycast address (``2001:db8::/64``), except on IPv4 /31
  and /32 and IPv6 /127 and /128 subnets
- ``network``: a network, an address with prefix length and no host bits set,
  e.g. ``10.0.0.0/24``

Prefix lengths must be numbers, netmasks (``10.0.0.1/255.255.255.0``) are not
accepted.
"""

import ipaddress
from typing import Any

from yamale.validators import Ip, Validator

from .base import Extension, Scope
from .values import split_fields, valid_fields
from .walker import DataNode

TYPES = {
    "address": "an IP address",
    "interface": "an IP host address with prefix length",
    "network": "an IP network",
}


def _types(validator: Validator) -> list[str]:
    """Return the forms of a valid ``type`` keyword."""
    return split_fields(validator.kwargs["type"])


def _not_host(interface: ipaddress.IPv4Interface | ipaddress.IPv6Interface) -> str:
    """Return why the address is not a host address of its subnet, "" if it is."""
    network = interface.network
    # Point-to-point links and single addresses have no reserved addresses
    if network.prefixlen >= network.max_prefixlen - 1:
        return ""
    # Compared as integers, as an IPv6 zone is part of the address only
    address = int(interface.ip)
    if address == int(network.network_address):
        if network.version == 6:
            return "it is the subnet-router anycast address"
        return "it is the network address"
    if network.version == 4 and address == int(network.broadcast_address):
        return "it is the broadcast address"
    return ""


def _expected(types: list[str]) -> str:
    """Describe the allowed forms, e.g. ``an IP address or an IP network``."""
    return " or ".join(TYPES[t] for t in types)


class IpType(Extension):
    keywords = ("type",)
    validator_types = (Ip,)

    def check_schema(self, validator: Validator) -> list[str]:
        value = validator.kwargs["type"]
        if valid_fields(value) and all(t in TYPES for t in split_fields(value)):
            return []
        return [
            "type must be comma-separated IP forms of "
            f"{', '.join(TYPES)}, not {value!r}"
        ]

    def accepts(self, validator: Validator, value: Any) -> bool:
        return self._check_value(value, _types(validator)) is None

    def check(self, node: DataNode, scope: Scope) -> list[str]:
        message = self._check_value(node.value, _types(node.validator))
        return [] if message is None else [message]

    @staticmethod
    def _check_value(value: Any, types: list[str]) -> str | None:
        try:
            # Parsed as Yamale does, which also accepts integers as addresses
            interface = ipaddress.ip_interface(value)
        except (ValueError, TypeError):
            # Merged data that is not valid may hold anything
            return None
        text = str(value)
        expected = _expected(types)
        # An integer is an address without prefix length
        _, slash, length = text.partition("/")
        if not slash:
            if "address" in types:
                return None
            return f"'{text}' is not {expected}, it has no prefix length"
        if types == ["address"]:
            return f"'{text}' is not {expected}, it has a prefix length"
        if not (length.isascii() and length.isdigit()):
            return (
                f"'{text}' is not {expected}, prefix length {length} must be a "
                "number, not a netmask"
            )
        not_host = _not_host(interface)
        if "interface" in types and not not_host:
            return None
        network = interface.network
        if "network" in types and int(interface.ip) == int(network.network_address):
            return None
        if "interface" in types:
            return f"'{text}' is not {expected}, {not_host}"
        return f"'{text}' is not {expected}, host bits are set (network is {network})"
