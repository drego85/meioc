"""Bounded RFC 9989 policy discovery and identifier alignment for analysis.

Reference: https://www.rfc-editor.org/rfc/rfc9989.html, sections 4.7-4.10.
This module evaluates DNS policy; it does not deliver mail or send reports.
"""

from __future__ import annotations

import re
import time
from typing import Callable
from urllib.parse import urlsplit

from dns_backend import DNSLookupError


POLICIES = {"none", "quarantine", "reject"}
KNOWN_TAGS = {"v", "p", "sp", "np", "psd", "t", "aspf", "adkim", "rua", "ruf", "fo"}


def report_uri_valid(value: str) -> bool:
    """Recognize syntactically usable reporting URIs without contacting them."""
    try:
        parsed = urlsplit(value.split("!", 1)[0])
        if not parsed.scheme or re.search(r"\s|%(?![0-9a-fA-F]{2})", value):
            return False
        if parsed.scheme.lower() == "mailto":
            return bool(re.fullmatch(r"[^@\s]+@[^@\s]+", parsed.path))
        return bool(parsed.netloc or parsed.path)
    except ValueError:
        return False


def parse_policy(record: str) -> tuple[dict[str, str], list[str]]:
    """Parse version, defaults and invalid-tag recovery per RFC 9989."""
    fields = record.strip().split(";")
    if not re.fullmatch(r"v\s*=\s*DMARC1", fields[0].strip()):
        raise ValueError("Invalid DMARC version or position")
    tags = {"v": "DMARC1"}
    warnings = []
    for field in fields[1:]:
        if not field.strip():
            continue
        match = re.fullmatch(r"\s*([A-Za-z]+)\s*=\s*([\x20-\x3a\x3c-\x7e]+)", field)
        if not match:
            warnings.append("Ignored malformed DMARC tag")
            continue
        name, value = match.group(1), match.group(2).strip()
        if name not in KNOWN_TAGS:
            warnings.append(f"Ignored unknown or obsolete tag: {name}")
            continue
        if name in tags:
            raise ValueError(f"Duplicate DMARC tag: {name}")
        tags[name] = value
    for name, default, allowed in (
        ("aspf", "r", {"r", "s"}), ("adkim", "r", {"r", "s"}),
        ("psd", "u", {"u", "y", "n"}), ("t", "n", {"y", "n"}),
    ):
        if name in tags and tags[name] not in allowed:
            warnings.append(f"Invalid {name}; using {default}")
            tags[name] = default
        tags.setdefault(name, default)
    tags.setdefault("p", "none")
    if any(name in tags and tags[name] not in POLICIES for name in ("p", "sp", "np")):
        if any(report_uri_valid(uri.strip()) for uri in tags.get("rua", "").split(",")):
            tags["p"] = "none"
            tags.pop("sp", None)
            tags.pop("np", None)
            warnings.append("Invalid policy recovered as p=none because rua is usable")
        else:
            raise ValueError("Invalid policy without a usable rua URI")
    return tags, warnings


def tree_names(domain: str) -> list[str]:
    """Return at most eight tree-walk names, including the initial domain."""
    labels = domain.lower().rstrip(".").encode("idna").decode("ascii").split(".")
    if any(not label or len(label) > 63 for label in labels) or len(".".join(labels)) > 253:
        raise ValueError("Invalid DMARC domain")
    parents = labels[-7:] if len(labels) >= 8 else labels[1:]
    return [".".join(labels)] + [".".join(parents[index:]) for index in range(len(parents))]


class PolicyResolver:
    """Share cached DNS evidence and one time/query budget within an analysis."""

    def __init__(self, txt_lookup: Callable, exists_lookup: Callable, timeout: float = 10):
        self.txt_lookup = txt_lookup
        self.exists_lookup = exists_lookup
        self.deadline = time.monotonic() + timeout
        self.cache: dict[str, tuple[str, dict[str, str]] | None] = {}
        self.warnings: list[str] = []
        self.queries: list[str] = []
        self.organizations: dict[str, str] = {}

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or len(self.queries) >= 64:
            raise DNSLookupError("DMARC evaluation budget exhausted")
        return remaining

    def lookup(self, domain: str) -> tuple[str, dict[str, str]] | None:
        if domain not in self.cache:
            timeout = self.remaining()
            self.queries.append(f"_dmarc.{domain}")
            values = self.txt_lookup(f"_dmarc.{domain}", timeout)
            records = [value.decode("ascii", errors="replace") for value in values
                       if re.match(rb"^\s*v\s*=\s*DMARC1(?:\s*;|\s*$)", value)]
            self.cache[domain] = None
            if len(records) > 1:
                self.warnings.append(f"Multiple DMARC records ignored at {domain}")
            elif records:
                try:
                    tags, warnings = parse_policy(records[0])
                    self.warnings.extend(f"{domain}: {warning}" for warning in warnings)
                    self.cache[domain] = (records[0], tags)
                except ValueError as error:
                    self.warnings.append(f"{domain}: {error}")
        return self.cache[domain]

    def walk(self, domain: str) -> list[tuple[str, str, dict[str, str]]]:
        found = []
        for name in tree_names(domain):
            record = self.lookup(name)
            if record:
                raw, tags = record
                found.append((name, raw, tags))
                if tags["psd"] in {"n", "y"}:
                    break
        return found

    def organization(self, domain: str) -> str:
        if domain in self.organizations:
            return self.organizations[domain]
        found = self.walk(domain)
        result = found[-1][0] if found else domain
        for name, raw, tags in found:
            if tags["psd"] == "n":
                result = name
                break
            if tags["psd"] == "y" and name != domain:
                result = ".".join(domain.split(".")[-len(name.split(".")) - 1:])
                break
        self.organizations[domain] = result
        return result

    def discover(self, domain: str) -> tuple[str | None, str]:
        direct = self.lookup(domain)
        if direct:
            return direct[0], domain
        found = self.walk(domain)
        if not found:
            return None, domain
        organization = self.organization(domain)
        selected = next((item for item in found if item[0] == organization), found[-1])
        return selected[1], selected[0]

    def aligned(self, identity: str | None, author: str, mode: str) -> bool:
        if not identity:
            return False
        identity = identity.lower().rstrip(".")
        if identity == author:
            return True
        if mode == "s":
            return False
        return self.organization(identity) == self.organization(author)

    def effective_policy(self, author: str, owner: str, tags: dict[str, str]) -> tuple[str, str]:
        selected = tags["p"]
        if author != owner:
            selected = tags.get("sp", selected)
            if "np" in tags:
                timeout = self.remaining()
                self.queries.append(author)
                if not self.exists_lookup(author, timeout):
                    selected = tags["np"]
        effective = selected
        if tags["t"] == "y":
            effective = {"reject": "quarantine", "quarantine": "none", "none": "none"}[selected]
        return selected, effective
