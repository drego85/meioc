"""Regression tests for Meioc's EML analysis."""

import sys
import types
import unittest
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

import meioc


def parse_message(raw_message: bytes):
    """Parse test bytes with the same policy used by Meioc."""
    return BytesParser(policy=policy.default).parsebytes(raw_message)


class ParsingTests(unittest.TestCase):
    def test_normalization_never_changes_body(self):
        raw_message = b"Subject : Test\r\n\r\nBody field : keep this\r\n"
        normalized = meioc.normalize_malformed_headers(raw_message)
        self.assertEqual(
            normalized,
            b"Subject: Test\r\n\r\nBody field : keep this\r\n",
        )

    def test_empty_message_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            meioc.analyze_bytes(b"", "empty.eml", False, False)

    def test_addresses_are_ordered_and_deduplicated(self):
        message = parse_message(
            b"To: First <first@example.com>, Second <second@example.com>\r\n"
            b"To: First <first@example.com>\r\n\r\n"
        )
        headers = meioc.extract_headers(message)
        self.assertEqual(
            headers["to"], ["first@example.com", "second@example.com"]
        )

    def test_compact_report_omits_empty_headers_and_diagnostics(self):
        full = {
            "schema_version": 2,
            "source_format": "eml",
            "filename": "sample.eml",
            "headers": {
                "from": "sender@example.org",
                "sender": None,
                "x_sender": None,
                "to": ["analyst@example.net"],
                "cc": [],
                "bcc": [],
                "envelope_to": [],
                "delivered_to": [],
                "return_path": "bounce@example.org",
                "subject": "Test",
                "date": None,
                "user_agent": None,
                "x_mailer": None,
                "x_originating_ip": None,
            },
            "relays": {
                "hops": [
                    {
                        "from": "mail.example.org ([192.0.2.1])",
                        "by": "mx.example.net",
                        "raw": "complete diagnostic header",
                    }
                ],
                "ips": ["192.0.2.1"],
            },
            "authentication": {
                "mode": "online",
                "spf": {
                    "result": "fail",
                    "reason": "verbose reason",
                    "alignment": {"strict": True, "relaxed": True},
                },
                "dkim": {
                    "result": "none",
                    "alignment": {"strict": False, "relaxed": False},
                },
                "dmarc": {"result": "none", "record": None},
            },
            "indicators": {"urls": [], "domains": [], "attachments": []},
        }
        compact = meioc.compact_report(full)
        self.assertNotIn("sender", compact)
        self.assertNotIn("headers", compact)
        self.assertNotIn("authentication", compact)
        self.assertEqual(compact["relays"], ["mail.example.org ([192.0.2.1])"])
        self.assertEqual(compact["spf"], {"result": "fail", "alignment": "strict"})
        self.assertNotIn("reason", compact["spf"])

    def test_invalid_msg_container_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "valid CFBF"):
            meioc.analyze_msg_bytes(
                b"not a compound document",
                "invalid.msg",
                exclude_private_ip=False,
                online_auth=False,
                maximum_converted_bytes=1024,
            )

    def test_msg_adapter_uses_common_attachment_pipeline(self):
        converted = EmailMessage()
        converted["From"] = "sender@example.org"
        converted["Subject"] = "MSG attachment"
        converted.set_content("Body")
        converted.add_attachment(
            b"payload",
            maintype="application",
            subtype="octet-stream",
            filename="sample.bin",
        )

        class FakeOutlookMessage:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def asEmailMessage(self):
                return converted

        with patch("extract_msg.openMsg", return_value=FakeOutlookMessage()):
            report = meioc.analyze_msg_bytes(
                meioc.MSG_COMPOUND_FILE_SIGNATURE + b"fixture",
                "sample.msg",
                exclude_private_ip=False,
                online_auth=False,
                maximum_converted_bytes=1024 * 1024,
            )

        self.assertEqual(report["source_format"], "msg")
        self.assertEqual(
            report["indicators"]["attachments"][0]["filename"], "sample.bin"
        )
        self.assertEqual(report["indicators"]["attachments"][0]["size"], 7)


class RelayAndAuthenticationTests(unittest.TestCase):
    raw_message = (
        b"Return-Path: <sender@example.org>\r\n"
        b"Received: from receiver.local by receiver.local with LMTP; "
        b"Fri, 1 Jan 2026 00:00:01 +0000\r\n"
        b"Received: from [193.168.175.40] (helo=mail.example.org) by receiver.local "
        b"(envelope-from <sender@example.org>); Fri, 1 Jan 2026 00:00:00 +0000\r\n"
        b"From: Sender <visible@example.net>\r\n"
        b"To: analyst@example.com\r\n\r\nHello"
    )

    def test_spf_identity_uses_mail_from_and_receiving_boundary_ip(self):
        identity = meioc.extract_delivery_identity(parse_message(self.raw_message))
        self.assertEqual(identity["mail_from"], "sender@example.org")
        self.assertEqual(identity["client_ip"], "193.168.175.40")
        self.assertEqual(identity["helo"], "mail.example.org")

    def test_received_parser_extracts_top_level_clauses(self):
        header = (
            "from mail.example.org ([192.0.2.1]) "
            "by mx.example.net (comment with by and from words) "
            "with ESMTP id ABC123 for <user@example.net>; "
            "Fri, 1 Jan 2026 00:00:00 +0000"
        )
        parsed = meioc.parse_received_header(header)
        self.assertEqual(parsed["from"], "mail.example.org ([192.0.2.1])")
        self.assertEqual(parsed["by"], "mx.example.net (comment with by and from words)")
        self.assertEqual(parsed["with"], "ESMTP")
        self.assertEqual(parsed["id"], "ABC123")
        self.assertEqual(parsed["for"], "<user@example.net>")
        self.assertEqual(parsed["date"], "Fri, 1 Jan 2026 00:00:00 +0000")

    def test_received_parser_does_not_invent_qmail_from_clause(self):
        parsed = meioc.parse_received_header(
            "(qmail 20947 invoked from network); 30 Oct 2019 14:33:38 +0600"
        )
        self.assertIsNone(parsed["from"])
        self.assertEqual(parsed["date"], "30 Oct 2019 14:33:38 +0600")

    def test_received_parser_supports_by_only_hop(self):
        parsed = meioc.parse_received_header(
            "by mail.example.net with SMTP id abc for <user@example.org>; "
            "Fri, 1 Jan 2026 00:00:00 +0000"
        )
        self.assertIsNone(parsed["from"])
        self.assertEqual(parsed["by"], "mail.example.net")
        self.assertEqual(parsed["with"], "SMTP")

    def test_online_spf_returns_the_real_rfc_result(self):
        calls = []
        fake_spf = types.ModuleType("spf")

        def check2(**kwargs):
            calls.append(kwargs)
            return "softfail", "domain discourages this sender"

        fake_spf.check2 = check2
        fake_spf.DNSLookup = object()
        fake_spf.TempError = RuntimeError
        with patch.dict(sys.modules, {"spf": fake_spf}):
            result = meioc.verify_spf_online(parse_message(self.raw_message))

        self.assertEqual(result["result"], "softfail")
        self.assertEqual(calls[0]["i"], "193.168.175.40")
        self.assertEqual(calls[0]["s"], "sender@example.org")

    def test_reported_client_ip_wins_over_provider_relay(self):
        message = parse_message(
            b"Authentication-Results: mx.example; spf=fail "
            b"smtp.mailfrom=sender.example client-ip=195.81.20.238\r\n"
            b"Received: from provider.example ([40.107.5.110]) by mx.example\r\n"
            b"Received: from sender.example ([195.81.20.238]) by provider.example\r\n"
            b"Return-Path: <sender@sender.example>\r\n\r\n"
        )
        identity = meioc.extract_delivery_identity(message)
        self.assertEqual(identity["client_ip"], "195.81.20.238")
        self.assertEqual(identity["mail_from"], "sender.example")
        self.assertEqual(identity["source"], "authentication-results")

    def test_reported_authentication_is_not_marked_independent(self):
        message = parse_message(
            b"Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.org; "
            b"dkim=pass header.d=example.org\r\n\r\n"
        )
        result = meioc.offline_authentication(message)
        self.assertEqual(result["spf"]["result"], "pass")
        self.assertFalse(result["spf"]["independent"])
        self.assertEqual(result["dkim"]["result"], "pass")
        self.assertEqual(result["dkim"]["authserv_id"], "mx.example")

    def test_mailfrom_spf_wins_over_legacy_pra_result(self):
        message = parse_message(
            b"Authentication-Results: mx.example; "
            b"spf=None smtp.pra=sender@example.org; "
            b"spf=Pass smtp.mailfrom=sender@example.org\r\n"
            b"Received-SPF: None (mx.example: no PRA policy) identity=pra; "
            b"client-ip=52.101.70.30; envelope-from=\"sender@example.org\"\r\n"
            b"Received-SPF: Pass (mx.example: sender permitted) identity=mailfrom; "
            b"client-ip=52.101.70.30; envelope-from=\"sender@example.org\"\r\n"
            b"Received: from mail.example.org ([52.101.70.30]) by mx.example\r\n"
            b"Return-Path: <sender@example.org>\r\n\r\n"
        )

        reported = meioc.parse_authentication_result(message, "spf")
        identity = meioc.extract_delivery_identity(message)

        self.assertEqual(reported["result"], "pass")
        self.assertEqual(reported["identity"], "mailfrom")
        self.assertEqual(reported["mail_from"], "sender@example.org")
        self.assertEqual(identity["mail_from"], "sender@example.org")
        self.assertEqual(identity["client_ip"], "52.101.70.30")
        self.assertEqual(identity["source"], "received-spf")

    def test_mailfrom_and_client_ip_can_come_from_separate_spf_headers(self):
        message = parse_message(
            b"Authentication-Results: spf=fail (sender IP is 85.159.115.48) "
            b"smtp.mailfrom=viscapitalventure.com; dkim=none\r\n"
            b"Received-SPF: Fail (domain does not designate sender) "
            b"receiver=protection.outlook.com; client-ip=85.159.115.48; "
            b"helo=workteam.esvacloud.com;\r\n"
            b"Received: from workteam.esvacloud.com (85.159.115.48) "
            b"by protection.outlook.com\r\n"
            b"X-Envelope-From: <sender@viscapitalventure.com>\r\n"
            b"From: Sender <sender@viscapitalventure.com>\r\n\r\n"
        )

        identity = meioc.extract_delivery_identity(message)

        self.assertEqual(identity["mail_from"], "viscapitalventure.com")
        self.assertEqual(identity["client_ip"], "85.159.115.48")
        self.assertEqual(identity["helo"], "workteam.esvacloud.com")
        self.assertEqual(identity["source"], "received-spf")

        fake_spf = types.ModuleType("spf")
        calls = []

        def check2(**kwargs):
            calls.append(kwargs)
            return "fail", "SPF fail - not authorized"

        fake_spf.check2 = check2
        fake_spf.DNSLookup = object()
        fake_spf.TempError = RuntimeError
        with patch.dict(sys.modules, {"spf": fake_spf}):
            result = meioc.verify_spf_online(message)

        self.assertEqual(result["result"], "fail")
        self.assertEqual(calls[0]["i"], "85.159.115.48")
        self.assertEqual(calls[0]["s"], "viscapitalventure.com")

    def test_online_spf_uses_recipient_mx_ingress_before_forwarder(self):
        message = parse_message(
            b"Received: from workteam.esvacloud.com (85.159.115.48) "
            b"by protection.outlook.com\r\n"
            b"Received: from outlook.example (40.107.200.81) "
            b"by workteam.esvacloud.com\r\n"
            b"Received-SPF: Fail; client-ip=85.159.115.48; "
            b"helo=workteam.esvacloud.com;\r\n"
            b"Authentication-Results: spf=fail "
            b"smtp.mailfrom=viscapitalventure.com\r\n"
            b"X-Envelope-From: <sender@viscapitalventure.com>\r\n"
            b"From: Sender <sender@viscapitalventure.com>\r\n"
            b"To: Recipient <user@cherrybank.it>\r\n\r\n"
        )
        fake_spf = types.ModuleType("spf")
        calls = []

        def check2(**kwargs):
            calls.append(kwargs)
            return "pass", "sender SPF authorized"

        fake_spf.check2 = check2
        fake_spf.DNSLookup = object()
        fake_spf.TempError = RuntimeError
        with patch.object(
            meioc, "mx_dns_hosts", return_value=["workteam.esvacloud.com"]
        ):
            with patch.dict(sys.modules, {"spf": fake_spf}):
                result = meioc.verify_spf_online(message)

        self.assertEqual(result["result"], "pass")
        self.assertEqual(calls[0]["i"], "40.107.200.81")
        self.assertEqual(calls[0]["s"], "sender@viscapitalventure.com")
        self.assertEqual(calls[0]["h"], "outlook.example")
        self.assertEqual(result["identity"]["source"], "recipient-mx")

    def test_smtp_mailbox_wrappers_are_normalized(self):
        variants = (
            '"sender@example.org"',
            "<sender@example.org>",
            "(sender@example.org)",
            '("sender@example.org")',
            "(sender@example.org",
        )
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(
                    meioc.normalize_smtp_mailbox(value),
                    "sender@example.org",
                )

    def test_result_only_header_has_no_false_authserv_id(self):
        message = parse_message(
            b"Authentication-Results: dkim=none header.d=none; dmarc=none\r\n\r\n"
        )
        result = meioc.parse_authentication_result(message, "dkim")
        self.assertIsNone(result["authserv_id"])

    def test_dkim_verification_receives_unmodified_bytes(self):
        raw_message = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=one.example; s=first; b=x\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; d=two.example; s=second; b=y\r\n"
            b"Subject : malformed but signed\r\n\r\nBody field : unchanged\r\n"
        )
        captured = []
        fake_dkim = types.ModuleType("dkim")

        class FakeDKIM:
            def __init__(self, message, timeout):
                captured.append((message, timeout))

            def verify(self, idx=0, dnsfunc=None):
                self.dnsfunc = dnsfunc
                return idx == 1

        fake_dkim.DKIM = FakeDKIM
        with patch.dict(sys.modules, {"dkim": fake_dkim}):
            result = meioc.verify_dkim_online(
                parse_message(meioc.normalize_malformed_headers(raw_message)),
                raw_message,
            )

        self.assertIs(captured[0][0], raw_message)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(
            [item["verified"] for item in result["signatures"]],
            [False, True],
        )

    def test_converted_msg_dkim_is_not_cryptographically_verified(self):
        message = parse_message(
            b"From: Sender <sender@example.org>\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=mail; b=x\r\n"
            b"\r\nBody"
        )
        result = meioc.dkim_without_original_bytes(message)
        self.assertEqual(result["result"], "not_verifiable")
        self.assertFalse(result["independent"])
        self.assertEqual(result["signatures"][0]["domain"], "example.org")

    def test_online_msg_authentication_never_calls_dkim_verifier(self):
        message = parse_message(
            b"From: Sender <sender@example.org>\r\n"
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=mail; b=x\r\n"
            b"\r\nBody"
        )
        spf_result = {
            "result": "not_available",
            "identity": {"mail_from": None, "helo": None},
        }
        with patch.object(meioc, "verify_spf_online", return_value=spf_result):
            with patch.object(
                meioc,
                "verify_dmarc_online",
                return_value={"result": "none"},
            ):
                with patch.object(meioc, "verify_dkim_online") as verify_dkim:
                    result = meioc.online_authentication(
                        message,
                        b"reconstructed MIME",
                        original_mime_available=False,
                    )

        verify_dkim.assert_not_called()
        self.assertEqual(result["dkim"]["result"], "not_verifiable")

    def test_revoked_dkim_key_has_an_explicit_reason(self):
        signature = {"selector": "mail", "domain": "example.org"}
        keys = {"mail._domainkey.example.org": b"v=DKIM1; p="}
        self.assertEqual(
            meioc.dkim_failure_reason(signature, keys),
            "public_key_revoked",
        )

    def test_dkim_dns_error_is_not_collapsed_into_fail(self):
        checks = [
            {"verified": False, "reason": "public_key_revoked"},
            {"verified": False, "reason": "dns_error"},
        ]
        self.assertEqual(meioc.dkim_overall_result(checks), "temperror")

    def test_spf_authentication_and_alignment_are_independent(self):
        message = parse_message(
            b"From: PayPal <sender@comune.melendugno.le.it>\r\n\r\n"
        )
        spf_result = {
            "result": "fail",
            "identity": {"mail_from": "sender@comune.melendugno.le.it"},
        }
        dkim_result = {"result": "none", "signatures": []}
        meioc.add_alignment_assessment(message, spf_result, dkim_result)
        self.assertFalse(spf_result["authenticated"])
        self.assertTrue(spf_result["alignment"]["strict"])
        self.assertTrue(spf_result["alignment"]["relaxed"])
        self.assertFalse(dkim_result["alignment"]["relaxed"])

    def test_relaxed_alignment_uses_psl_organizational_domain(self):
        alignment = meioc.domain_alignment(
            "bounce.melendugno.le.it", "comune.melendugno.le.it"
        )
        self.assertFalse(alignment["strict"])
        self.assertTrue(alignment["relaxed"])
        self.assertEqual(
            meioc.organizational_domain("comune.melendugno.le.it"),
            "melendugno.le.it",
        )

    def test_dmarc_requires_authentication_and_alignment(self):
        message = parse_message(
            b"From: PayPal <sender@comune.melendugno.le.it>\r\n\r\n"
        )
        spf_result = {
            "result": "fail",
            "authenticated": False,
            "alignment": {"strict": True, "relaxed": True},
        }
        dkim_result = {"result": "none", "signatures": []}
        record = "v=DMARC1; p=reject; aspf=r; adkim=r"
        with patch.object(
            meioc,
            "find_dmarc_record",
            return_value=(record, "melendugno.le.it"),
        ):
            result = meioc.verify_dmarc_online(message, spf_result, dkim_result)
        self.assertEqual(result["result"], "fail")
        self.assertEqual(result["aligned_via"], [])

    def test_dmarc_passes_with_authenticated_aligned_spf(self):
        message = parse_message(
            b"From: Sender <sender@example.org>\r\n\r\n"
        )
        spf_result = {
            "authenticated": True,
            "alignment": {"strict": True, "relaxed": True},
        }
        dkim_result = {"signatures": []}
        with patch.object(
            meioc,
            "find_dmarc_record",
            return_value=("v=DMARC1; p=none", "example.org"),
        ):
            result = meioc.verify_dmarc_online(message, spf_result, dkim_result)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["aligned_via"], ["spf"])

    def test_dmarc_dkim_alignment_must_belong_to_verified_signature(self):
        message = parse_message(
            b"From: Sender <sender@example.org>\r\n\r\n"
        )
        spf_result = {
            "authenticated": False,
            "alignment": {"strict": False, "relaxed": False},
        }
        dkim_result = {
            "signatures": [
                {"verified": True, "alignment": {"relaxed": False}},
                {"verified": False, "alignment": {"relaxed": True}},
            ]
        }
        with patch.object(
            meioc,
            "find_dmarc_record",
            return_value=("v=DMARC1; p=reject", "example.org"),
        ):
            result = meioc.verify_dmarc_online(message, spf_result, dkim_result)
        self.assertEqual(result["result"], "fail")


class IndicatorTests(unittest.TestCase):
    def test_html_filters_non_urls_and_resolves_base(self):
        html = """
        <base href="https://example.com/root/">
        <a href="page">relative</a>
        <a href="mailto:user@example.com">mail</a>
        <a href="javascript:alert(1)">script</a>
        <img src="https://cdn.example.net/image.png">
        """
        self.assertEqual(
            meioc.extract_urls_from_html(html),
            [
                "https://example.com/root/page",
                "https://cdn.example.net/image.png",
            ],
        )

    def test_ip_url_does_not_create_a_domain_indicator(self):
        self.assertEqual(meioc.extract_domain("http://198.51.100.7/payload"), "")

    def test_attachment_payload_is_hashed_once_into_stable_fields(self):
        result = meioc.hash_attachment("sample.bin", b"payload", "application/octet-stream")
        self.assertEqual(result["size"], 7)
        self.assertEqual(
            result["sha256"],
            "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
        )


class LocalCorpusTests(unittest.TestCase):
    def test_optional_local_corpus_parses_without_network(self):
        corpus = Path(__file__).parents[1] / "sourceemail"
        samples = sorted(corpus.glob("*.eml"))
        if not samples:
            self.skipTest("Local sourceemail corpus is not present")
        for sample in samples:
            with self.subTest(sample=sample.name):
                report = meioc.analyze_file(str(sample), online_auth=False)
                self.assertEqual(report["schema_version"], 2)

    def test_optional_msg_fixture_uses_common_pipeline(self):
        sample = Path(__file__).parents[1] / "sourceemail" / "test1.msg"
        if not sample.exists():
            self.skipTest("Local MSG fixture is not present")
        report = meioc.analyze_file(str(sample), online_auth=False)
        self.assertEqual(report["source_format"], "msg")
        self.assertEqual(report["headers"]["subject"], "Segnalazione phishing")
        self.assertGreater(len(report["relays"]["hops"]), 0)
        self.assertIn("urls", report["indicators"])


if __name__ == "__main__":
    unittest.main()
