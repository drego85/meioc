"""Small DNS backend with bounded timeouts for pyspf and dkimpy."""

from __future__ import annotations

import ipaddress
import time
from pathlib import Path
from typing import Any

from dnslib import DNSError, DNSRecord, QTYPE, RCODE


class DNSLookupError(RuntimeError):
    """Raised when every configured recursive resolver fails."""


class DNSNameNotFound(DNSLookupError):
    """Distinguish NXDOMAIN from an existing name with no requested records."""


def validated_dns_response(request: DNSRecord, packet: bytes) -> DNSRecord:
    """Reject replies that do not match this DNS transaction and question."""
    response = DNSRecord.parse(packet)
    if (
        response.header.id != request.header.id
        or not response.header.qr
        or response.header.opcode != request.header.opcode
        or response.questions != request.questions
    ):
        raise DNSLookupError("DNS response does not match the request")
    return response


def configured_nameservers() -> list[str]:
    """Read usable recursive resolvers from the system resolver file."""
    nameservers = []
    try:
        lines = Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0].lower() != "nameserver":
            continue
        try:
            nameservers.append(str(ipaddress.ip_address(fields[1])))
        except ValueError:
            continue
    return list(dict.fromkeys(nameservers))


def send_dns_request(request: DNSRecord, nameserver: str, timeout: float) -> DNSRecord:
    """Try UDP, then TCP when UDP times out or returns a truncated response."""
    deadline = time.monotonic() + timeout
    try:
        packet = request.send(
            nameserver, timeout=max(timeout / 2, 0.1),
            ipv6=ipaddress.ip_address(nameserver).version == 6,
        )
        response = validated_dns_response(request, packet)
        if not response.header.tc:
            return response
    except OSError:
        pass
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS UDP and TCP budget exhausted")
    packet = request.send(
        nameserver, tcp=True, timeout=remaining,
        ipv6=ipaddress.ip_address(nameserver).version == 6,
    )
    response = validated_dns_response(request, packet)
    if response.header.tc:
        raise DNSLookupError("Truncated TCP DNS response")
    return response


def resolve_records(
    name: str, qtype: str, timeout: float, raise_on_nxdomain: bool = False
) -> list[Any]:
    """Resolve records through system nameservers within an overall deadline."""
    nameservers = configured_nameservers()
    if not nameservers:
        raise DNSLookupError("No nameserver is configured in /etc/resolv.conf")

    deadline = time.monotonic() + timeout
    errors = []
    request = DNSRecord.question(name.rstrip("."), qtype)
    for index, nameserver in enumerate(nameservers):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempt_timeout = remaining / (len(nameservers) - index)
        try:
            response = send_dns_request(request, nameserver, attempt_timeout)
            if response.header.rcode == RCODE.NXDOMAIN:
                if raise_on_nxdomain:
                    raise DNSNameNotFound(name)
                return []
            if response.header.rcode != RCODE.NOERROR:
                errors.append(f"{nameserver}: {RCODE[response.header.rcode]}")
                continue
            return list(response.rr) + list(response.auth) + list(response.ar)
        except DNSNameNotFound:
            raise
        except (DNSLookupError, DNSError, OSError, ValueError) as error:
            errors.append(f"{nameserver}: {error}")
    detail = "; ".join(errors) or "deadline exceeded"
    raise DNSLookupError(detail)


def spf_dns_lookup(
    name: str, qtype: str, strict: bool = True, timeout: float = 10
) -> list[tuple[tuple[str, str], Any]]:
    """Return DNS records in the callback format expected by pyspf."""
    del strict
    results = []
    for record in resolve_records(name, qtype, timeout):
        record_type = QTYPE[record.rtype]
        value = spf_record_value(record_type, record.rdata)
        if value is not None:
            results.append(((str(record.rname).rstrip("."), record_type), value))
    return results


def spf_record_value(record_type: str, value: Any) -> Any:
    """Convert a dnslib value to pyspf's DNS cache representation."""
    if record_type in {"A", "AAAA"}:
        return str(value)
    if record_type == "MX":
        return value.preference, str(value.label).rstrip(".")
    if record_type in {"PTR", "CNAME"}:
        return str(value.label).rstrip(".")
    if record_type in {"TXT", "SPF"}:
        return tuple(value.data)
    return None


def txt_dns_records(name: str, timeout: float = 10) -> list[bytes]:
    """Return TXT records while following a bounded CNAME chain."""
    current = name.rstrip(".")
    visited = set()
    deadline = time.monotonic() + timeout
    while current not in visited and len(visited) < 5:
        visited.add(current)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DNSLookupError("deadline exceeded")
        records = resolve_records(current, "TXT", remaining)
        cname = None
        text_records = []
        for record in records:
            record_type = QTYPE[record.rtype]
            owner = str(record.rname).rstrip(".")
            if record_type == "TXT" and owner.lower() == current.lower():
                text_records.append(b"".join(record.rdata.data))
            if record_type == "CNAME" and owner.lower() == current.lower():
                cname = str(record.rdata.label).rstrip(".")
        if text_records:
            return text_records
        if not cname:
            return []
        current = cname
    raise DNSLookupError("CNAME chain is too long or contains a loop")


def mx_dns_hosts(name: str, timeout: float = 10) -> list[str]:
    """Return the normalized MX hosts published for a domain."""
    domain = name.rstrip(".").lower()
    hosts = []
    for record in resolve_records(domain, "MX", timeout):
        record_type = QTYPE[record.rtype]
        owner = str(record.rname).rstrip(".").lower()
        if record_type == "MX" and owner == domain:
            hosts.append(str(record.rdata.label).rstrip(".").lower())
    return list(dict.fromkeys(hosts))


def dkim_dns_lookup(name: bytes, timeout: float = 10) -> bytes | None:
    """Return the first TXT key record in the format expected by dkimpy."""
    records = txt_dns_records(name.decode("ascii"), timeout)
    return records[0] if records else None


def domain_exists(name: str, timeout: float = 10) -> bool:
    """Treat NODATA as existence and only NXDOMAIN as non-existence."""
    try:
        resolve_records(name, "A", timeout, raise_on_nxdomain=True)
        return True
    except DNSNameNotFound:
        return False
