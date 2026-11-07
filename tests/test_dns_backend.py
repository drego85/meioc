"""Synthetic DNS transaction tests; no network access is required."""

import unittest
from unittest.mock import patch

from dnslib import DNSRecord, RCODE

import dns_backend


class DNSResponseTests(unittest.TestCase):
    def test_domain_nodata_exists_but_nxdomain_does_not(self):
        for rcode, expected in ((RCODE.NOERROR, True), (RCODE.NXDOMAIN, False)):
            with self.subTest(rcode=rcode), patch.object(
                dns_backend, "configured_nameservers", return_value=["127.0.0.1"]
            ), patch.object(dns_backend, "send_dns_request") as send:
                reply = DNSRecord.question("example.org").reply()
                reply.header.rcode = rcode
                send.return_value = reply
                self.assertEqual(dns_backend.domain_exists("example.org"), expected)

    def test_matching_reply_is_accepted(self):
        request = DNSRecord.question("example.org", "TXT")
        self.assertEqual(
            dns_backend.validated_dns_response(request, request.reply().pack()).q,
            request.q,
        )

    def test_unrelated_replies_are_rejected(self):
        request = DNSRecord.question("example.org", "TXT")
        replies = []
        reply = request.reply()
        reply.header.id ^= 1
        replies.append(reply)
        reply = request.reply()
        reply.header.qr = 0
        replies.append(reply)
        reply = request.reply()
        reply.questions = DNSRecord.question("other.example", "TXT").questions
        replies.append(reply)
        reply = request.reply()
        reply.questions = DNSRecord.question("example.org", "MX").questions
        replies.append(reply)
        for reply in replies:
            with self.subTest(reply=str(reply)), self.assertRaises(dns_backend.DNSLookupError):
                dns_backend.validated_dns_response(request, reply.pack())

    def test_tcp_fallback_is_also_validated(self):
        request = DNSRecord.question("example.org", "TXT")
        truncated = request.reply()
        truncated.header.tc = 1
        wrong = request.reply()
        wrong.header.id ^= 1
        with patch.object(DNSRecord, "send", side_effect=[truncated.pack(), wrong.pack()]):
            with self.assertRaises(dns_backend.DNSLookupError):
                dns_backend.send_dns_request(request, "127.0.0.1", 1)
