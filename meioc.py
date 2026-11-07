#!/usr/bin/env python3
"""Extract SOC-relevant indicators and authentication evidence from EML/MSG files."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

import tldextract
from bs4 import BeautifulSoup

from dns_backend import (
    DNSLookupError,
    dkim_dns_lookup,
    domain_exists,
    mx_dns_hosts,
    spf_dns_lookup,
    txt_dns_records,
)
from dmarc_policy import PolicyResolver, parse_policy


VERSION = "2.2.0"
DEFAULT_MAX_SIZE_MB = 50
DNS_TIMEOUT_SECONDS = 10
MSG_COMPOUND_FILE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
HEADER_NAME_WITH_SPACE = re.compile(
    rb"^([A-Za-z0-9!#$%&'*+\-.^_`|~]+)[ \t]+:", re.MULTILINE
)
URL_PATTERN = re.compile(r"(?:(?:https?|ftp)://)[^\s<>\"']+", re.IGNORECASE)
ENVELOPE_FROM_PATTERN = re.compile(
    r"envelope-from\s*(?:[=:]\s*|\s+)<?([^>\s;)]+)", re.IGNORECASE
)
HELO_PATTERN = re.compile(r"\bhelo[= ]([^\s;)]+)", re.IGNORECASE)
SMTP_HELO_PATTERN = re.compile(r"smtp\.helo\s*=\s*([^;\s]+)", re.IGNORECASE)
SMTP_PRA_PATTERN = re.compile(r"smtp\.pra\s*=\s*([^;\s]+)", re.IGNORECASE)
SPF_IDENTITY_PATTERN = re.compile(r"\bidentity\s*=\s*([a-z]+)", re.IGNORECASE)
AUTH_RESULT_PATTERN = {
    "spf": re.compile(r"(?:^|;)\s*spf\s*=\s*([a-z]+)", re.IGNORECASE),
    "dkim": re.compile(r"(?:^|;)\s*dkim\s*=\s*([a-z]+)", re.IGNORECASE),
    "dmarc": re.compile(r"(?:^|;)\s*dmarc\s*=\s*([a-z]+)", re.IGNORECASE),
}
SMTP_MAILFROM_PATTERN = re.compile(
    r"smtp\.mailfrom\s*=\s*<?([^;>\s]+)", re.IGNORECASE
)
CLIENT_IP_PATTERN = re.compile(r"client-ip\s*=\s*([^;\s]+)", re.IGNORECASE)
HEADER_D_PATTERN = re.compile(r"header\.d\s*=\s*([^;\s]+)", re.IGNORECASE)
HEADER_FROM_PATTERN = re.compile(r"header\.from\s*=\s*([^;\s]+)", re.IGNORECASE)
DKIM_TAG_PATTERN = re.compile(
    r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)", re.IGNORECASE
)
TRAILING_URL_PUNCTUATION = ".,;:!?"
RECEIVED_CLAUSE_NAMES = ("from", "by", "via", "with", "id", "for")

# Use the PSL snapshot bundled with tldextract. Authentication DNS remains live.
DOMAIN_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def ordered_unique(values: Iterable[str]) -> list[str]:
    """Return non-empty unique strings in first-seen order."""
    return list(dict.fromkeys(value for value in values if value))


def normalize_malformed_headers(raw_message: bytes) -> bytes:
    """Fix whitespace before header colons without changing the message body."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        header, found, body = raw_message.partition(separator)
        if found:
            normalized = HEADER_NAME_WITH_SPACE.sub(rb"\1:", header)
            return normalized + found + body
    return HEADER_NAME_WITH_SPACE.sub(rb"\1:", raw_message)


def extract_single_address(header: Any) -> str | None:
    """Extract the first normalized mailbox from an email header."""
    if header is None:
        return None
    try:
        if getattr(header, "addresses", None):
            return header.addresses[0].addr_spec.lower()
        address = parseaddr(str(header))[1]
        return address.lower() if address else None
    except (AttributeError, TypeError, ValueError):
        return None


def extract_addresses(headers: Iterable[Any]) -> list[str]:
    """Extract normalized mailboxes from one or more email headers."""
    values = [str(header) for header in headers if header is not None]
    addresses = (address.lower() for _, address in getaddresses(values) if address)
    return ordered_unique(addresses)


def extract_headers(message: Message) -> dict[str, Any]:
    """Extract message headers useful to a SOC analyst."""
    def multiple(name: str) -> list[str]:
        return extract_addresses(message.get_all(name, []))

    return {
        "from": extract_single_address(message.get("From")),
        "sender": extract_single_address(message.get("Sender")),
        "x_sender": extract_single_address(message.get("X-Sender")),
        "to": multiple("To"),
        "cc": multiple("Cc"),
        "bcc": multiple("Bcc"),
        "envelope_to": multiple("Envelope-To"),
        "delivered_to": multiple("Delivered-To"),
        "return_path": extract_single_address(message.get("Return-Path")),
        "subject": str(message.get("Subject")) if message.get("Subject") else None,
        "date": str(message.get("Date")) if message.get("Date") else None,
        "user_agent": (
            str(message.get("User-Agent")) if message.get("User-Agent") else None
        ),
        "x_mailer": str(message.get("X-Mailer")) if message.get("X-Mailer") else None,
        "x_originating_ip": clean_originating_ip(message.get("X-Originating-IP")),
    }


def clean_originating_ip(value: Any) -> str | None:
    """Normalize X-Originating-IP without treating it as a relay indicator."""
    return str(value).strip().strip("[]") if value else None


def find_ip_addresses(value: str) -> list[str]:
    """Find valid IPv4 and IPv6 addresses in a Received header fragment."""
    candidates = re.findall(r"\[[^]]+\]|\([^)]*\)|[^\s]+", value)
    addresses: list[str] = []
    for candidate in candidates:
        for token in re.split(r"[\[\](),]", candidate):
            token = token.strip().removeprefix("IPv6:").split("%", 1)[0]
            token = token.rstrip(";")
            try:
                addresses.append(str(ipaddress.ip_address(token)))
            except ValueError:
                continue
    return ordered_unique(addresses)


def split_received_timestamp(value: str) -> tuple[str, str | None]:
    """Split a Received timestamp at a semicolon outside comments/literals."""
    parenthesis_depth = 0
    bracket_depth = 0
    quoted = False
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == '"' and parenthesis_depth == 0 and bracket_depth == 0:
            quoted = not quoted
            continue
        if quoted:
            continue
        if character == "(" and bracket_depth == 0:
            parenthesis_depth += 1
        elif character == ")" and parenthesis_depth:
            parenthesis_depth -= 1
        elif character == "[" and parenthesis_depth == 0:
            bracket_depth += 1
        elif character == "]" and bracket_depth:
            bracket_depth -= 1
        elif character == ";" and parenthesis_depth == 0 and bracket_depth == 0:
            return value[:index].strip(), value[index + 1:].strip() or None
    return value.strip(), None


def received_clause_positions(value: str) -> list[tuple[int, int, str]]:
    """Locate top-level RFC 5321 trace keywords without reading comments."""
    positions: list[tuple[int, int, str]] = []
    parenthesis_depth = 0
    bracket_depth = 0
    quoted = False
    escaped = False
    index = 0
    lowered = value.lower()
    while index < len(value):
        character = value[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if character == '"' and parenthesis_depth == 0 and bracket_depth == 0:
            quoted = not quoted
            index += 1
            continue
        if quoted:
            index += 1
            continue
        if character == "(" and bracket_depth == 0:
            parenthesis_depth += 1
            index += 1
            continue
        if character == ")" and parenthesis_depth:
            parenthesis_depth -= 1
            index += 1
            continue
        if character == "[" and parenthesis_depth == 0:
            bracket_depth += 1
            index += 1
            continue
        if character == "]" and bracket_depth:
            bracket_depth -= 1
            index += 1
            continue
        if parenthesis_depth or bracket_depth:
            index += 1
            continue

        matched = None
        for keyword in RECEIVED_CLAUSE_NAMES:
            end = index + len(keyword)
            if lowered[index:end] != keyword:
                continue
            before_ok = index == 0 or not (
                value[index - 1].isalnum() or value[index - 1] in "-_"
            )
            after_ok = end == len(value) or not (
                value[end].isalnum() or value[end] in "-_"
            )
            if before_ok and after_ok:
                matched = (index, end, keyword)
                break
        if matched:
            if positions or not value[:index].strip():
                positions.append(matched)
                index = matched[1]
                continue
        index += 1
    return positions


def parse_received_header(value: str) -> dict[str, str | None]:
    """Parse common top-level Received clauses while preserving raw evidence."""
    body, timestamp = split_received_timestamp(value)
    positions = received_clause_positions(body)
    clauses: dict[str, str | None] = {name: None for name in RECEIVED_CLAUSE_NAMES}
    for position, (start, end, keyword) in enumerate(positions):
        value_end = positions[position + 1][0] if position + 1 < len(positions) else len(body)
        clause_value = body[end:value_end].strip()
        if clauses[keyword] is None and clause_value:
            clauses[keyword] = clause_value
    clauses["date"] = timestamp
    return clauses


def extract_relays(message: Message, exclude_private: bool) -> dict[str, Any]:
    """Extract Received hops and IP indicators in chronological order."""
    hops: list[dict[str, Any]] = []
    all_ips: list[str] = []
    for raw_header in reversed(message.get_all("Received", [])):
        header = " ".join(str(raw_header).split())
        clauses = parse_received_header(header)
        source = clauses["from"]
        ips = find_ip_addresses(source or "")
        hops.append(
            {
                "from": source,
                "by": clauses["by"],
                "via": clauses["via"],
                "with": clauses["with"],
                "id": clauses["id"],
                "for": clauses["for"],
                "date": clauses["date"],
                "ips": ips,
                "raw": header,
            }
        )
        all_ips.extend(ips)

    relay_ips = ordered_unique(all_ips)
    if exclude_private:
        relay_ips = [ip for ip in relay_ips if ipaddress.ip_address(ip).is_global]
    return {"hops": hops, "ips": relay_ips}


def extract_delivery_identity(message: Message) -> dict[str, str | None]:
    """Infer the SMTP identity and IP at the receiving boundary."""
    reported_identity = extract_reported_identity(message)
    if reported_identity:
        return reported_identity

    envelope_sender = (
        extract_single_address(message.get("Return-Path"))
        or extract_single_address(message.get("X-Envelope-From"))
    )
    client_ip = None
    helo = None

    for raw_header in message.get_all("Received", []):
        header = " ".join(str(raw_header).split())
        source = parse_received_header(header)["from"]
        if not source:
            continue
        global_ips = [
            ip for ip in find_ip_addresses(source)
            if ipaddress.ip_address(ip).is_global
        ]
        if not global_ips:
            continue
        client_ip = global_ips[0]
        helo_match = HELO_PATTERN.search(source)
        helo = helo_match.group(1) if helo_match else infer_source_hostname(source)
        envelope_match = ENVELOPE_FROM_PATTERN.search(header)
        if envelope_match:
            envelope_sender = (
                normalize_smtp_mailbox(envelope_match.group(1)) or envelope_sender
            )
        break

    return {
        "mail_from": envelope_sender,
        "client_ip": client_ip,
        "helo": helo,
        "source": "received",
    }


def recipient_domains(message: Message) -> list[str]:
    """Return recipient domains in SMTP-envelope then message-header order."""
    addresses = []
    for header_name in ("Envelope-To", "Delivered-To", "To", "Cc"):
        addresses.extend(extract_addresses(message.get_all(header_name, [])))
        if addresses:
            break
    return ordered_unique(
        domain for address in addresses if (domain := mailbox_domain(address))
    )


def envelope_sender(message: Message) -> str | None:
    """Return the best available RFC 5321 MAIL FROM identity."""
    for header_name in ("Return-Path", "X-Envelope-From"):
        address = extract_single_address(message.get(header_name))
        if address:
            return address
    candidates = sorted(
        spf_report_candidates(message),
        key=lambda item: item["preference"],
        reverse=True,
    )
    return select_reported_mail_from(candidates, None)


def session_mail_from(message: Message, client_ip: str) -> str | None:
    """Accept reported envelope evidence only for an unambiguous source session."""
    occurrences = sum(
        client_ip in find_ip_addresses(parse_received_header(str(value))["from"] or "")
        for value in message.get_all("Received", [])
    )
    if occurrences != 1:
        return None
    identities = {
        candidate["mail_from"] for candidate in spf_report_candidates(message)
        if candidate.get("client_ip", "") == client_ip and candidate.get("mail_from")
        and candidate.get("identity") != "pra"
    }
    domains = {mailbox_domain(value) for value in identities}
    mailboxes = {value for value in identities if "@" in value}
    if len(domains) != 1 or len(mailboxes) > 1:
        return None
    return next(iter(mailboxes or identities))


def extract_recipient_mx_identity(
    message: Message, timeout: float = DNS_TIMEOUT_SECONDS
) -> dict[str, str | None] | None:
    """Find the sender identity at the recipient domain's published MX edge."""
    deadline = time.monotonic() + timeout
    published_mx_hosts = set()
    for domain in recipient_domains(message):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        published_mx_hosts.update(mx_dns_hosts(domain, remaining))
    if not published_mx_hosts:
        return None

    for raw_header in reversed(message.get_all("Received", [])):
        header = " ".join(str(raw_header).split())
        clauses = parse_received_header(header)
        receiver = infer_source_hostname(clauses["by"] or "")
        if not receiver or receiver.lower() not in published_mx_hosts:
            continue
        recipient = extract_single_address(clauses["for"])
        if recipient and mailbox_domain(recipient) not in recipient_domains(message):
            continue
        source = clauses["from"] or ""
        global_ips = [
            ip for ip in find_ip_addresses(source)
            if ipaddress.ip_address(ip).is_global
        ]
        if not global_ips:
            continue
        envelope_match = ENVELOPE_FROM_PATTERN.search(header)
        mail_from = None
        if envelope_match:
            mail_from = normalize_smtp_mailbox(envelope_match.group(1))
        # Bind reported envelope evidence to this session's source IP.
        mail_from = mail_from or session_mail_from(message, global_ips[0])
        return {
            "mail_from": mail_from,
            "client_ip": global_ips[0],
            "helo": infer_source_hostname(source) if mail_from else None,
            "source": "recipient-mx",
            "receiver": receiver.lower(),
            "reason": None if mail_from else "MAIL FROM is unavailable for the selected MX session.",
        }
    return None


def extract_reported_identity(message: Message) -> dict[str, str | None] | None:
    """Extract the SMTP identity observed by the original receiving system."""
    received_ips = {
        ip
        for header in message.get_all("Received", [])
        for ip in find_ip_addresses(parse_received_header(str(header))["from"] or "")
    }
    candidates = sorted(
        spf_report_candidates(message),
        key=lambda item: item["preference"],
        reverse=True,
    )
    for candidate in candidates:
        client_ip = candidate.get("client_ip")
        if not client_ip:
            continue
        client_ip = client_ip.strip("[]")
        try:
            if not ipaddress.ip_address(client_ip).is_global:
                continue
        except ValueError:
            continue
        if client_ip not in received_ips:
            continue
        mail_from = session_mail_from(message, client_ip)
        # Split headers without an IP are usable only if all MAIL FROM reports agree.
        if not mail_from and not candidate.get("mail_from"):
            identities = {
                item["mail_from"] for item in candidates
                if item.get("identity") == "mailfrom" and item.get("mail_from")
            }
            if len(identities) == 1 and sum(
                client_ip in find_ip_addresses(parse_received_header(str(value))["from"] or "")
                for value in message.get_all("Received", [])
            ) == 1:
                mail_from = next(iter(identities))
        return {
            "mail_from": mail_from,
            "client_ip": client_ip,
            "helo": candidate.get("helo") if mail_from else None,
            "source": candidate["header"],
        }
    return None


def select_reported_mail_from(
    candidates: list[dict[str, Any]], result: str | None
) -> str | None:
    """Select MAIL FROM evidence, preferring the matching SPF result."""
    for require_matching_result in (True, False):
        for candidate in candidates:
            if candidate.get("identity") != "mailfrom":
                continue
            if not candidate.get("mail_from"):
                continue
            if require_matching_result and candidate.get("result") != result:
                continue
            return candidate["mail_from"]
    return None


def infer_source_hostname(source: str) -> str | None:
    """Infer the hostname following the Received header's from keyword."""
    match = re.match(r"from\s+([^\s(]+)", source, re.IGNORECASE)
    candidate = match.group(1) if match else source.split(" ", 1)[0]
    if not candidate or candidate.lower() in {"unknown", "localhost"}:
        return None
    return candidate.strip("[]")


def parse_authentication_result(
    message: Message, method: str
) -> dict[str, Any] | None:
    """Read an authentication result reported by a receiving mail system."""
    if method == "spf":
        candidates = spf_report_candidates(message)
        if not candidates:
            return None
        selected = max(candidates, key=lambda item: item["preference"])
        return {
            key: value
            for key, value in selected.items()
            if key != "preference"
        }

    pattern = AUTH_RESULT_PATTERN[method]
    for header_name in ("Authentication-Results",):
        for value in message.get_all(header_name, []):
            text = " ".join(str(value).split())
            match = pattern.search(text)
            if not match:
                continue
            prefix = text.split(";", 1)[0].strip()
            authserv_id = prefix if prefix and "=" not in prefix else None
            segment_end = text.find(";", match.end())
            text = text[match.end():segment_end if segment_end >= 0 else None]
            return {
                "result": match.group(1).lower(),
                "source": "header",
                "independent": False,
                "authserv_id": authserv_id,
                "header": header_name.lower(),
                "mail_from": normalize_smtp_mailbox(
                    regex_value(SMTP_MAILFROM_PATTERN, text)
                ),
                "client_ip": regex_value(CLIENT_IP_PATTERN, text),
                "header_domain": regex_value(HEADER_D_PATTERN, text),
                "header_from": regex_value(HEADER_FROM_PATTERN, text),
            }
    return None


def normalize_smtp_mailbox(value: str | None) -> str | None:
    """Normalize wrappers around an SMTP mailbox or bare identity domain."""
    if value is None:
        return None
    candidate = value.strip()
    wrappers = (("<", ">"), ('"', '"'), ("'", "'"), ("(", ")"))
    changed = True
    while candidate and changed:
        changed = False
        for opening, closing in wrappers:
            if candidate.startswith(opening) and candidate.endswith(closing):
                candidate = candidate[1:-1].strip()
                changed = True
                break
    # Some Received/Received-SPF syntaxes leave a single parenthesis in the
    # regular-expression capture (for example envelope-from=(user@example)).
    candidate = candidate.strip("<>()").strip()
    if not candidate:
        return None
    parsed = parseaddr(candidate)[1]
    return (parsed or candidate).lower()


def spf_report_candidates(message: Message) -> list[dict[str, Any]]:
    """Return reported SPF results ranked by RFC 7208 identity relevance."""
    candidates: list[dict[str, Any]] = []
    for value in message.get_all("Authentication-Results", []):
        text = " ".join(str(value).split())
        prefix = text.split(";", 1)[0].strip()
        authserv_id = prefix if prefix and "=" not in prefix else None
        matches = list(AUTH_RESULT_PATTERN["spf"].finditer(text))
        for match in matches:
            segment_end = text.find(";", match.end())
            segment = text[match.start(): segment_end if segment_end >= 0 else None]
            mail_from = normalize_smtp_mailbox(
                regex_value(SMTP_MAILFROM_PATTERN, segment)
            )
            helo = regex_value(SMTP_HELO_PATTERN, segment)
            pra = regex_value(SMTP_PRA_PATTERN, segment)
            if mail_from:
                identity = "mailfrom"
            elif helo:
                identity = "helo"
            elif pra:
                identity = "pra"
            else:
                identity = None
            preference = {"mailfrom": 40, "helo": 30, None: 20, "pra": 10}[identity]
            candidates.append(
                {
                    "result": match.group(1).lower(),
                    "source": "header",
                    "independent": False,
                    "authserv_id": authserv_id,
                    "header": "authentication-results",
                    "identity": identity,
                    "mail_from": mail_from,
                    "helo": helo,
                    "client_ip": regex_value(CLIENT_IP_PATTERN, segment),
                    "header_domain": None,
                    "header_from": None,
                    "preference": preference,
                }
            )

    for value in message.get_all("Received-SPF", []):
        text = " ".join(str(value).split())
        match = re.match(r"\s*([a-z]+)", text, re.IGNORECASE)
        if not match:
            continue
        identity = (regex_value(SPF_IDENTITY_PATTERN, text) or "").lower() or None
        mail_from = normalize_smtp_mailbox(
            regex_value(SMTP_MAILFROM_PATTERN, text)
            or regex_value(ENVELOPE_FROM_PATTERN, text)
        )
        helo = regex_value(SMTP_HELO_PATTERN, text) or regex_value(HELO_PATTERN, text)
        if identity == "mailfrom" or (mail_from and identity != "pra"):
            preference = 35
        elif identity == "helo" or helo:
            preference = 25
        elif identity == "pra":
            preference = 5
        else:
            preference = 15
        candidates.append(
            {
                "result": match.group(1).lower(),
                "source": "header",
                "independent": False,
                "authserv_id": None,
                "header": "received-spf",
                "identity": identity,
                "mail_from": mail_from,
                "helo": helo,
                "client_ip": regex_value(CLIENT_IP_PATTERN, text),
                "header_domain": None,
                "header_from": None,
                "preference": preference,
            }
        )
    return candidates


def regex_value(pattern: re.Pattern[str], value: str) -> str | None:
    """Return the first captured value from a regular expression."""
    match = pattern.search(value)
    return match.group(1) if match else None


def extract_dkim_signatures(message: Message) -> list[dict[str, str | None]]:
    """Extract relevant tags from every DKIM signature."""
    signatures = []
    for value in message.get_all("DKIM-Signature", []):
        tags = {
            key.lower(): item.strip()
            for key, item in DKIM_TAG_PATTERN.findall(str(value))
        }
        signatures.append(
            {
                "domain": tags.get("d"),
                "selector": tags.get("s"),
                "identity": tags.get("i"),
                "algorithm": tags.get("a"),
            }
        )
    return signatures


def mailbox_domain(value: str | None) -> str | None:
    """Return the lower-case domain from a mailbox or bare domain identity."""
    if not value:
        return None
    candidate = value.strip().strip("<>").lower()
    return candidate.rsplit("@", 1)[-1].rstrip(".") or None


def organizational_domain(domain: str | None) -> str | None:
    """Return the PSL-based organizational domain used for relaxed alignment."""
    if not domain:
        return None
    extracted = DOMAIN_EXTRACTOR(domain)
    return extracted.top_domain_under_public_suffix or domain


def domain_alignment(identity_domain: str | None, header_from: str | None) -> dict[str, Any]:
    """Calculate strict and relaxed RFC 7489 identifier alignment."""
    strict = bool(identity_domain and header_from and identity_domain == header_from)
    identity_org = organizational_domain(identity_domain)
    header_org = organizational_domain(header_from)
    relaxed = bool(identity_org and header_org and identity_org == header_org)
    return {
        "identity_domain": identity_domain,
        "header_from_domain": header_from,
        "strict": strict,
        "relaxed": relaxed,
    }


def authentication_boolean(result: str | None) -> bool | None:
    """Map an authentication result to true, false, or indeterminate."""
    if result == "pass":
        return True
    if result in {
        "not_available",
        "not_verifiable",
        "signed_unverified",
        "temperror",
    }:
        return None
    return False


def add_alignment_assessment(
    message: Message, spf_result: dict[str, Any], dkim_result: dict[str, Any]
) -> None:
    """Annotate SPF and DKIM results with authentication and alignment."""
    header_from = mailbox_domain(extract_single_address(message.get("From")))
    identity = spf_result.get("identity", {})
    spf_domain = mailbox_domain(identity.get("mail_from") or identity.get("helo"))
    spf_result["authenticated"] = authentication_boolean(spf_result.get("result"))
    spf_result["alignment"] = domain_alignment(spf_domain, header_from)

    signatures = dkim_result.get("signatures", [])
    for signature in signatures:
        signature["alignment"] = domain_alignment(
            mailbox_domain(signature.get("domain")), header_from
        )
    domains = [mailbox_domain(item.get("domain")) for item in signatures]
    reported = dkim_result.get("reported") or dkim_result
    if not domains and reported.get("header_domain"):
        domains.append(mailbox_domain(reported["header_domain"]))
    alignments = [domain_alignment(domain, header_from) for domain in domains]
    dkim_result["authenticated"] = authentication_boolean(dkim_result.get("result"))
    dkim_result["alignment"] = {
        "header_from_domain": header_from,
        "strict": any(item["strict"] for item in alignments),
        "relaxed": any(item["relaxed"] for item in alignments),
    }


def dkim_without_original_bytes(message: Message) -> dict[str, Any]:
    """Report DKIM presence when converted MSG lacks original MIME bytes."""
    signatures = extract_dkim_signatures(message)
    if not signatures:
        return {
            "result": "none",
            "source": "message",
            "independent": True,
            "signatures": [],
            "reason": "No DKIM-Signature header is present.",
        }
    return {
        "result": "not_verifiable",
        "source": "converted_message",
        "independent": False,
        "signatures": signatures,
        "reason": (
            "The MSG container does not preserve the original RFC 5322 bytes "
            "required for DKIM verification."
        ),
    }


def offline_authentication(
    message: Message, original_mime_available: bool = True
) -> dict[str, Any]:
    """Report authentication evidence without making DNS queries."""
    identity = extract_delivery_identity(message)
    spf_result = parse_authentication_result(message, "spf")
    if spf_result is None:
        spf_result = {
            "result": "not_available",
            "source": "none",
            "independent": False,
            "reason": "No SPF result is present in the message headers.",
        }
    spf_result["identity"] = identity

    signatures = extract_dkim_signatures(message)
    dkim_result = parse_authentication_result(message, "dkim")
    if dkim_result is None:
        if not original_mime_available:
            dkim_result = dkim_without_original_bytes(message)
        else:
            dkim_result = {
                "result": "signed_unverified" if signatures else "none",
                "source": "signature" if signatures else "none",
                "independent": False,
                "reason": (
                    "A signature is present but DNS verification is disabled."
                    if signatures
                    else "No DKIM signature or reported result is present."
                ),
            }
    dkim_result["signatures"] = signatures
    add_alignment_assessment(message, spf_result, dkim_result)
    dmarc_result = parse_authentication_result(message, "dmarc") or {
        "result": "not_available",
        "source": "none",
        "independent": False,
        "reason": "No DMARC result is present and DNS verification is disabled.",
    }
    return {
        "mode": "offline",
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
    }


def online_authentication(
    message: Message, raw_message: bytes, original_mime_available: bool = True
) -> dict[str, Any]:
    """Perform independent SPF and DKIM verification using live DNS."""
    spf_result = verify_spf_online(message)
    spf_result["reported"] = parse_authentication_result(message, "spf")
    dkim_result = (
        verify_dkim_online(message, raw_message)
        if original_mime_available
        else dkim_without_original_bytes(message)
    )
    dkim_result["reported"] = parse_authentication_result(message, "dkim")
    add_alignment_assessment(message, spf_result, dkim_result)
    dmarc_result = verify_dmarc_online(message, spf_result, dkim_result)
    dmarc_result["reported"] = parse_authentication_result(message, "dmarc")
    return {
        "mode": "online",
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
    }


def find_dmarc_record(
    header_from: str, resolver: PolicyResolver | None = None
) -> tuple[str | None, str]:
    """Discover RFC 9989 policy using a shared bounded DNS tree walk."""
    resolver = resolver or PolicyResolver(txt_dns_records, domain_exists, DNS_TIMEOUT_SECONDS)
    return resolver.discover(header_from)


def parse_dmarc_tags(record: str) -> dict[str, str]:
    """Return RFC 9989 tags after defaults and recoverable-error handling."""
    return parse_policy(record)[0]


def verify_dmarc_online(
    message: Message, spf_result: dict[str, Any], dkim_result: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate DMARC using independently verified aligned identifiers."""
    header_from = mailbox_domain(extract_single_address(message.get("From")))
    if (
        not header_from or len(message.get_all("From", [])) != 1
        or len(extract_addresses(message.get_all("From", []))) != 1
    ):
        return {
            "result": "not_available",
            "source": "message",
            "independent": True,
            "reason": "A valid RFC 5322 From domain is required.",
        }
    resolver = PolicyResolver(txt_dns_records, domain_exists, DNS_TIMEOUT_SECONDS)
    try:
        record, policy_domain = find_dmarc_record(header_from, resolver)
    except DNSLookupError as error:
        return dmarc_error("temperror", header_from, str(error))
    except ValueError as error:
        return dmarc_error("permerror", header_from, str(error))
    if record is None:
        result = dmarc_no_record(header_from)
        result.update(standard="RFC9989", warnings=resolver.warnings, queries=resolver.queries)
        return result

    try:
        tags = parse_dmarc_tags(record)
        resolver.cache[policy_domain] = (record, tags)
        policy, effective_policy = resolver.effective_policy(header_from, policy_domain, tags)
        spf_domain = mailbox_domain(spf_result.get("identity", {}).get("mail_from"))
        if str(message.get("Return-Path", "")).strip() == "<>":
            spf_domain = mailbox_domain(spf_result.get("identity", {}).get("helo"))
        # Do not reuse PSL alignment or a different signature's verification.
        alignment_errors = []

        def assess(identity_domain, verified, mode):
            strict = bool(identity_domain and identity_domain == header_from)
            relaxed = strict
            if verified and not strict and mode == "r":
                try:
                    relaxed = resolver.aligned(identity_domain, header_from, mode)
                except DNSLookupError as error:
                    alignment_errors.append(str(error))
                    relaxed = None
            return {
                "identity_domain": identity_domain, "header_from_domain": header_from,
                "strict": strict, "relaxed": relaxed, "basis": "dns-tree",
            }

        spf_result["alignment"] = assess(spf_domain, spf_result.get("authenticated"), tags["aspf"])
        spf_pass = bool(spf_result.get("authenticated") and spf_result["alignment"][
            "strict" if tags["aspf"] == "s" else "relaxed"
        ])
        dkim_pass = False
        for signature in dkim_result.get("signatures", []):
            signature["alignment"] = assess(
                mailbox_domain(signature.get("domain")), signature.get("verified"), tags["adkim"]
            )
            dkim_pass |= bool(signature.get("verified") and signature["alignment"][
                "strict" if tags["adkim"] == "s" else "relaxed"
            ])
        dkim_result["alignment"] = {
            "header_from_domain": header_from, "basis": "dns-tree",
            "strict": any(item["alignment"]["strict"] for item in dkim_result.get("signatures", [])),
            "relaxed": any(item["alignment"]["relaxed"] for item in dkim_result.get("signatures", [])),
        }
        if alignment_errors and not (spf_pass or dkim_pass):
            raise DNSLookupError("; ".join(alignment_errors))
        # Do not start additional DNS walks solely to populate diagnostics.
        author_org = resolver.organizations.get(header_from)
    except DNSLookupError as error:
        return dmarc_error("temperror", header_from, str(error))
    except ValueError as error:
        return dmarc_error("permerror", header_from, str(error))
    spf_mode = "strict" if tags.get("aspf") == "s" else "relaxed"
    dkim_mode = "strict" if tags.get("adkim") == "s" else "relaxed"
    if not (spf_pass or dkim_pass):
        if spf_result.get("result") == "temperror" or dkim_result.get("result") == "temperror":
            return dmarc_error("temperror", header_from, "Authentication DNS lookup failed.")
        if spf_result.get("result") in {"not_available", "not_verifiable"} or dkim_result.get(
            "result"
        ) == "not_verifiable":
            return dmarc_error("not_available", header_from, "Authentication evidence is incomplete.")
    return {
        "result": "pass" if spf_pass or dkim_pass else "fail",
        "source": "dns",
        "independent": True,
        "header_from_domain": header_from,
        "organizational_domain": author_org,
        "policy_domain": policy_domain,
        "record": record,
        "standard": "RFC9989",
        "policy": policy,
        "effective_policy": effective_policy,
        "test_mode": tags["t"] == "y",
        "warnings": resolver.warnings,
        "queries": resolver.queries,
        "alignment_mode": {"spf": spf_mode, "dkim": dkim_mode},
        "aligned_via": [
            method for method, passed in (("spf", spf_pass), ("dkim", dkim_pass))
            if passed
        ],
    }


def dmarc_no_record(header_from: str) -> dict[str, Any]:
    """Build the result used when neither author nor organizational policy exists."""
    return {
        "result": "none",
        "source": "dns",
        "independent": True,
        "header_from_domain": header_from,
        "organizational_domain": None,
        "record": None,
        "reason": "No DMARC record was found.",
    }


def dmarc_error(result: str, header_from: str, reason: str) -> dict[str, Any]:
    """Build a consistent DMARC DNS error result."""
    return {
        "result": result,
        "source": "dns",
        "independent": True,
        "header_from_domain": header_from,
        "organizational_domain": None,
        "standard": "RFC9989",
        "reason": reason,
    }


def make_spf_dns_lookup(spf_module: Any):
    """Adapt the bounded resolver to pyspf's callback and error types."""
    def dns_lookup(name: str, qtype: str, strict: bool, timeout: float):
        try:
            return spf_dns_lookup(name, qtype, strict, timeout)
        except DNSLookupError as error:
            raise spf_module.TempError(f"DNS: {error}") from error

    return dns_lookup


def verify_spf_online(message: Message) -> dict[str, Any]:
    """Evaluate SPF for the receiving-boundary IP and MAIL FROM identity."""
    import spf
    try:
        identity = extract_recipient_mx_identity(message) or extract_delivery_identity(
            message
        )
    except DNSLookupError:
        identity = extract_delivery_identity(message)
    client_ip = identity["client_ip"]
    mail_from = identity["mail_from"]
    helo = identity["helo"]
    if not client_ip or not (mail_from or helo):
        return {
            "result": "not_available",
            "source": "dns",
            "independent": True,
            "identity": identity,
            "reason": "A client IP and MAIL FROM or HELO identity are required.",
        }

    sender = mail_from or f"postmaster@{helo}"
    original_lookup = spf.DNSLookup
    try:
        spf.DNSLookup = make_spf_dns_lookup(spf)
        result, explanation = spf.check2(
            i=client_ip,
            s=sender,
            h=helo or "unknown",
            timeout=DNS_TIMEOUT_SECONDS,
            querytime=DNS_TIMEOUT_SECONDS,
        )
        return {
            "result": result.lower(),
            "source": "dns",
            "independent": True,
            "identity": identity,
            "explanation": explanation,
        }
    except Exception as error:  # pyspf exposes resolver-specific exception types
        return {
            "result": "temperror",
            "source": "dns",
            "independent": True,
            "identity": identity,
            "reason": f"{type(error).__name__}: {error}",
        }
    finally:
        spf.DNSLookup = original_lookup


def make_dkim_dns_lookup(
    dkim_module: Any,
    queried_keys: dict[str, bytes | None],
    dns_errors: dict[str, str],
):
    """Adapt the bounded resolver to dkimpy while retaining diagnostics."""
    def dns_lookup(name: bytes, timeout: float = DNS_TIMEOUT_SECONDS):
        key_name = name.decode("ascii").rstrip(".").lower()
        try:
            value = dkim_dns_lookup(name, timeout)
            queried_keys[key_name] = value
            return value
        except DNSLookupError as error:
            dns_errors[key_name] = str(error)
            raise dkim_module.DnsTimeoutError(str(error)) from error

    return dns_lookup


def verify_dkim_online(message: Message, raw_message: bytes) -> dict[str, Any]:
    """Verify all DKIM signatures over the unmodified message bytes."""
    import dkim

    signatures = extract_dkim_signatures(message)
    if not signatures:
        return {
            "result": "none",
            "source": "message",
            "independent": True,
            "signatures": [],
            "reason": "No DKIM-Signature header is present.",
        }

    verifier = dkim.DKIM(raw_message, timeout=DNS_TIMEOUT_SECONDS)
    queried_keys: dict[str, bytes | None] = {}
    dns_errors: dict[str, str] = {}
    dns_lookup = make_dkim_dns_lookup(dkim, queried_keys, dns_errors)

    checks = []
    for index, signature in enumerate(signatures):
        check: dict[str, Any] = dict(signature)
        try:
            check["verified"] = bool(verifier.verify(idx=index, dnsfunc=dns_lookup))
            if not check["verified"]:
                key_name = dkim_key_name(check)
                if key_name in dns_errors:
                    check["reason"] = "dns_error"
                    check["error"] = dns_errors[key_name]
                else:
                    check["reason"] = dkim_failure_reason(check, queried_keys)
        except Exception as error:  # dkimpy exposes resolver-specific exceptions
            check["verified"] = False
            if dkim_key_name(check) in dns_errors:
                check["reason"] = "dns_error"
            check["error"] = f"{type(error).__name__}: {error}"
        checks.append(check)

    return {
        "result": dkim_overall_result(checks),
        "source": "dns",
        "independent": True,
        "signatures": checks,
    }


def dkim_overall_result(checks: list[dict[str, Any]]) -> str:
    """Aggregate signatures without collapsing DNS uncertainty into failure."""
    if any(item["verified"] for item in checks):
        return "pass"
    if any(item.get("reason") == "dns_error" for item in checks):
        return "temperror"
    return "fail"


def dkim_failure_reason(
    signature: dict[str, Any], queried_keys: dict[str, bytes | None]
) -> str:
    """Explain common DKIM verification failures using the queried key record."""
    key_name = dkim_key_name(signature)
    if not key_name:
        return "signature_missing_domain_or_selector"
    if key_name not in queried_keys:
        return "signature_did_not_verify"
    key_record = queried_keys[key_name]
    if key_record is None:
        return "public_key_not_found"
    text = key_record.decode("ascii", errors="replace")
    if re.search(r"(?:^|;)\s*p\s*=\s*(?:;|$)", text):
        return "public_key_revoked"
    return "signature_did_not_verify"


def dkim_key_name(signature: dict[str, Any]) -> str:
    """Build the DNS owner name for a parsed DKIM signature."""
    domain = signature.get("domain")
    selector = signature.get("selector")
    return f"{selector}._domainkey.{domain}".lower() if domain and selector else ""


def extract_urls_from_text(content: str) -> list[str]:
    """Extract ordinary, non-defanged URLs from plain text."""
    return [clean_url(match.group(0)) for match in URL_PATTERN.finditer(content)]


def clean_url(value: str) -> str:
    """Remove punctuation commonly attached to a URL in prose."""
    value = value.rstrip(TRAILING_URL_PUNCTUATION)
    while value.endswith(")") and value.count("(") < value.count(")"):
        value = value[:-1]
    return value


def extract_urls_from_html(content: str) -> list[str]:
    """Extract supported absolute URLs from security-relevant HTML attributes."""
    soup = BeautifulSoup(content, "html.parser")
    base_tag = soup.find("base", href=True)
    base = str(base_tag.get("href")) if base_tag else ""
    attributes = {
        "a": "href",
        "form": "action",
        "iframe": "src",
        "img": "src",
        "link": "href",
        "script": "src",
    }
    urls = []
    for tag_name, attribute in attributes.items():
        for tag in soup.find_all(tag_name, **{attribute: True}):
            candidate = str(tag.get(attribute)).strip()
            try:
                resolved = urljoin(base, candidate) if base else candidate
            except ValueError:
                continue
            if is_supported_url(resolved):
                urls.append(clean_url(resolved))
    urls.extend(extract_urls_from_text(soup.get_text(" ")))
    return urls


def is_supported_url(value: str) -> bool:
    """Accept absolute HTTP(S)/FTP URLs and reject mailto and script values."""
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in {"http", "https", "ftp"}
            and bool(parsed.hostname)
            and "[.]" not in parsed.netloc
        )
    except ValueError:
        return False


def extract_indicators(message: Message) -> dict[str, Any]:
    """Extract URLs, registrable domains, and attachment hashes."""
    urls: list[str] = []
    attachments: list[dict[str, Any]] = []
    for part in message.walk():
        content_type = part.get_content_type()
        if content_type in {"text/plain", "text/html"}:
            try:
                content = part.get_content()
                if content_type == "text/plain":
                    urls.extend(extract_urls_from_text(content))
                else:
                    urls.extend(extract_urls_from_html(content))
            except (LookupError, TypeError, UnicodeError, ValueError):
                pass

        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            if payload is not None:
                attachments.append(
                    hash_attachment(str(filename), payload, part.get_content_type())
                )

    urls = ordered_unique(url for url in urls if is_supported_url(url))
    domains = ordered_unique(extract_domain(url) for url in urls)
    return {"urls": urls, "domains": domains, "attachments": attachments}


def extract_domain(url: str) -> str:
    """Return a registrable domain, but never promote an IP to a domain IoC."""
    hostname = urlsplit(url).hostname
    if not hostname:
        return ""
    try:
        ipaddress.ip_address(hostname)
        return ""
    except ValueError:
        extracted = DOMAIN_EXTRACTOR(hostname)
        return extracted.top_domain_under_public_suffix or (extracted.domain or "")


def hash_attachment(
    filename: str, payload: bytes, content_type: str
) -> dict[str, Any]:
    """Calculate common IoC hashes for one decoded attachment payload."""
    return {
        "filename": filename,
        "content_type": content_type,
        "size": len(payload),
        "md5": hashlib.md5(payload).hexdigest(),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def analyze_bytes(
    raw_message: bytes,
    filename: str,
    exclude_private_ip: bool,
    online_auth: bool,
) -> dict[str, Any]:
    """Analyze raw RFC 5322 bytes and return a schema v2 report."""
    if not raw_message:
        raise ValueError("The email file is empty.")
    parser_input = normalize_malformed_headers(raw_message)
    message = BytesParser(policy=policy.default).parsebytes(parser_input)
    return analyze_message(
        message,
        raw_message,
        filename,
        exclude_private_ip,
        online_auth,
        source_format="eml",
        original_mime_available=True,
    )


def analyze_message(
    message: Message,
    verification_bytes: bytes,
    filename: str,
    exclude_private_ip: bool,
    online_auth: bool,
    source_format: str,
    original_mime_available: bool,
) -> dict[str, Any]:
    """Analyze a parsed message while retaining source-format capabilities."""
    authentication = (
        online_authentication(message, verification_bytes, original_mime_available)
        if online_auth
        else offline_authentication(message, original_mime_available)
    )
    return {
        "schema_version": 2,
        "source_format": source_format,
        "filename": os.path.basename(filename),
        "headers": extract_headers(message),
        "relays": extract_relays(message, exclude_private_ip),
        "authentication": authentication,
        "indicators": extract_indicators(message),
    }


def analyze_msg_bytes(
    raw_message: bytes,
    filename: str,
    exclude_private_ip: bool,
    online_auth: bool,
    maximum_converted_bytes: int,
) -> dict[str, Any]:
    """Convert an Outlook MSG container into the common in-memory model."""
    if not raw_message.startswith(MSG_COMPOUND_FILE_SIGNATURE):
        raise ValueError("The .msg file is not a valid CFBF compound document.")
    try:
        import extract_msg

        with extract_msg.openMsg(raw_message) as outlook_message:
            converted = outlook_message.asEmailMessage()
            converted_bytes = converted.as_bytes(policy=policy.default)
    except Exception as error:
        raise ValueError(
            f"Unable to parse Outlook MSG: {type(error).__name__}: {error}"
        ) from error
    if len(converted_bytes) > maximum_converted_bytes:
        raise ValueError(
            f"Converted MSG is {len(converted_bytes)} bytes; "
            f"the configured limit is {maximum_converted_bytes} bytes."
        )
    message = BytesParser(policy=policy.default).parsebytes(converted_bytes)
    return analyze_message(
        message,
        converted_bytes,
        filename,
        exclude_private_ip,
        online_auth,
        source_format="msg",
        original_mime_available=False,
    )


def analyze_file(
    filename: str,
    exclude_private_ip: bool = False,
    online_auth: bool = True,
    max_size_mb: int = DEFAULT_MAX_SIZE_MB,
) -> dict[str, Any]:
    """Read and analyze an EML or MSG file subject to a size limit."""
    path = Path(filename)
    size = path.stat().st_size
    maximum = max_size_mb * 1024 * 1024
    if size > maximum:
        raise ValueError(
            f"Email is {size} bytes; the configured limit is {maximum} bytes."
        )
    with path.open("rb") as email_file:
        raw_message = email_file.read(maximum + 1)
    if len(raw_message) > maximum:
        raise ValueError("Email exceeds the configured size limit while reading.")
    if path.suffix.lower() == ".msg":
        return analyze_msg_bytes(
            raw_message,
            str(path),
            exclude_private_ip,
            online_auth,
            maximum_converted_bytes=maximum,
        )
    return analyze_bytes(raw_message, str(path), exclude_private_ip, online_auth)


def compact_alignment(authentication: dict[str, Any]) -> str:
    """Reduce strict/relaxed alignment flags to one readable value."""
    alignment = authentication.get("alignment", {})
    if alignment.get("strict"):
        return "strict"
    if alignment.get("relaxed"):
        return "relaxed"
    return "none"


def compact_authentication(authentication: dict[str, Any]) -> dict[str, Any]:
    """Keep authentication outcome and alignment without diagnostic detail."""
    result = {"result": authentication.get("result", "not_available")}
    if "alignment" in authentication:
        result["alignment"] = compact_alignment(authentication)
    policy = authentication.get("policy")
    if policy:
        result["policy"] = policy
    aligned_via = authentication.get("aligned_via")
    if aligned_via:
        result["aligned_via"] = aligned_via
    return result


def compact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Build the concise default report used by SOC triage workflows."""
    headers = report["headers"]
    relays = report["relays"]
    authentication = report["authentication"]
    indicators = report["indicators"]
    output: dict[str, Any] = {
        "schema_version": report["schema_version"],
        "format": "compact",
        "source_format": report["source_format"],
        "filename": report["filename"],
    }

    for name in (
        "from",
        "sender",
        "x_sender",
        "to",
        "cc",
        "bcc",
        "envelope_to",
        "delivered_to",
        "return_path",
        "subject",
        "date",
        "user_agent",
        "x_mailer",
        "x_originating_ip",
    ):
        if headers.get(name) not in (None, [], ""):
            output[name] = headers[name]

    output.update(
        {
            "relays": ordered_unique(
                hop.get("from") for hop in relays["hops"] if hop.get("from")
            ),
            "relay_ips": relays["ips"],
            "spf": compact_authentication(authentication["spf"]),
            "dkim": compact_authentication(authentication["dkim"]),
            "dmarc": compact_authentication(authentication["dmarc"]),
            "urls": indicators["urls"],
            "domains": indicators["domains"],
            "attachments": indicators["attachments"],
        }
    )
    return output


def write_report(
    report: dict[str, Any], destination: str | None, verbose: bool = False
) -> None:
    """Write a JSON report to stdout or to the selected file."""
    output = report if verbose else compact_report(report)
    serialized = json.dumps(output, ensure_ascii=False, indent=2)
    if destination:
        Path(destination).write_text(serialized + "\n", encoding="utf-8")
        print(f"[!] Output saved in: {destination}", file=sys.stderr)
    else:
        print(serialized)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Extract SOC-relevant indicators from an EML or Outlook MSG."
    )
    parser.add_argument("filename", help="EML or MSG file to analyze")
    parser.add_argument(
        "-x",
        "--exclude-private-ip",
        action="store_true",
        help="Exclude non-global IPs from the relay indicator list",
    )
    parser.add_argument(
        "--offline-auth",
        action="store_true",
        help="Do not query DNS; only report authentication evidence from headers",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit the complete diagnostic report instead of the concise SOC view",
    )
    parser.add_argument("-o", "--output", help="Write the JSON report to this file")
    parser.add_argument(
        "--max-size-mb",
        type=int,
        default=DEFAULT_MAX_SIZE_MB,
        help=f"Maximum accepted input size (default: {DEFAULT_MAX_SIZE_MB} MiB)",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the Meioc command-line interface."""
    arguments = build_parser().parse_args(argv)
    if arguments.max_size_mb <= 0:
        print("meioc: error: --max-size-mb must be positive", file=sys.stderr)
        return 2
    try:
        report = analyze_file(
            arguments.filename,
            exclude_private_ip=arguments.exclude_private_ip,
            online_auth=not arguments.offline_auth,
            max_size_mb=arguments.max_size_mb,
        )
        write_report(report, arguments.output, verbose=arguments.verbose)
    except (OSError, ValueError) as error:
        print(f"meioc: error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
