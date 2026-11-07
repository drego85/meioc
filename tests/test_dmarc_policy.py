"""RFC 9989 examples and failure cases using synthetic DNS evidence."""

import unittest
from unittest.mock import Mock, patch
from email import policy
from email.parser import BytesParser

import meioc
from dmarc_policy import PolicyResolver, parse_policy, tree_names
from dns_backend import DNSLookupError


class PolicyTests(unittest.TestCase):
    def test_aligned_spf_pass_survives_dkim_alignment_dns_error(self):
        message = BytesParser(policy=policy.default).parsebytes(
            b"From: sender@example.org\r\n\r\n"
        )
        spf = {"authenticated": True, "result": "pass",
               "identity": {"mail_from": "sender@example.org"}}
        def lookup(name, timeout):
            if name == "_dmarc.example.org":
                return [b"v=DMARC1; p=reject"]
            raise DNSLookupError("timeout")
        with patch.object(meioc, "txt_dns_records", side_effect=lookup):
            result = meioc.verify_dmarc_online(message, spf, {
                "signatures": [{"verified": True, "domain": "other.example"}]
            })
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["aligned_via"], ["spf"])

    def test_null_reverse_path_can_use_helo_for_dmarc(self):
        message = BytesParser(policy=policy.default).parsebytes(
            b"From: sender@example.org\r\nReturn-Path: <>\r\n\r\n"
        )
        spf = {"authenticated": True, "result": "pass", "identity": {
            "mail_from": None, "helo": "example.org"
        }}
        with patch.object(meioc, "txt_dns_records", return_value=[b"v=DMARC1; p=none"]):
            result = meioc.verify_dmarc_online(message, spf, {"signatures": []})
        self.assertEqual(result["result"], "pass")

    def test_multiple_from_mailboxes_are_not_evaluated(self):
        message = BytesParser(policy=policy.default).parsebytes(
            b"From: one@example.org, two@other.example\r\n\r\n"
        )
        result = meioc.verify_dmarc_online(message, {}, {"signatures": []})
        self.assertEqual(result["result"], "not_available")

    def test_invalid_author_record_allows_parent_discovery(self):
        resolver = self.resolver({
            "mail.example.org": ["v=DMARC1; p=invalid"],
            "example.org": ["v=DMARC1; p=reject; psd=n"],
        })
        self.assertEqual(resolver.discover("mail.example.org")[1], "example.org")

    def test_evaluation_budget_stops_queries(self):
        resolver = self.resolver({})
        resolver.deadline = 0
        with self.assertRaises(DNSLookupError):
            resolver.discover("example.org")
        resolver.txt_lookup.assert_not_called()

    def resolver(self, records, exists=True):
        lookup = Mock(side_effect=lambda name, timeout: [
            value.encode() for value in records.get(name.removeprefix("_dmarc."), [])
        ])
        return PolicyResolver(lookup, Mock(return_value=exists))

    def test_missing_p_defaults_to_none(self):
        self.assertEqual(parse_policy("v=DMARC1")[0]["p"], "none")

    def test_optional_invalid_tags_use_defaults(self):
        tags, warnings = parse_policy("v=DMARC1; aspf=bad; adkim=bad; t=bad; psd=bad")
        self.assertEqual((tags["aspf"], tags["adkim"], tags["t"], tags["psd"]),
                         ("r", "r", "n", "u"))
        self.assertEqual(len(warnings), 4)

    def test_invalid_policy_with_reporting_recovers(self):
        tags, warnings = parse_policy("v=DMARC1; p=bad; sp=bad; rua=mailto:Reports@example.org")
        self.assertEqual(tags["p"], "none")
        self.assertNotIn("sp", tags)
        self.assertTrue(warnings)

    def test_invalid_policy_without_reporting_is_unusable(self):
        with self.assertRaises(ValueError):
            parse_policy("v=DMARC1; p=bad; rua=not-a-uri")

    def test_unknown_and_obsolete_tags_are_ignored(self):
        tags, warnings = parse_policy("v=DMARC1; custom=one; pct=10; ri=bad")
        self.assertNotIn("pct", tags)
        self.assertNotIn("custom", tags)
        self.assertEqual(len(warnings), 3)

    def test_bad_versions_and_duplicates_are_rejected(self):
        for value in ("v=dmarc1", "p=none; v=DMARC1", "v=DMARC1; p=none; p=reject"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_policy(value)

    def test_deep_walk_uses_eight_queries(self):
        domain = "a.b.c.d.e.f.g.h.i.j.k.example.com"
        resolver = self.resolver({})
        resolver.discover(domain)
        self.assertEqual(len(resolver.queries), 8)
        self.assertEqual(tree_names(domain)[1], "g.h.i.j.k.example.com")

    def test_organization_uses_highest_record_not_psl(self):
        resolver = self.resolver({
            "mail.example.com": ["v=DMARC1; p=none"],
            "example.com": ["v=DMARC1; p=reject"],
        })
        self.assertEqual(resolver.organization("a.mail.example.com"), "example.com")
        self.assertEqual(resolver.discover("a.mail.example.com")[1], "example.com")

    def test_direct_policy_wins_without_defining_organization(self):
        resolver = self.resolver({
            "mail.example.com": ["v=DMARC1; p=reject"],
            "example.com": ["v=DMARC1; p=none"],
        })
        self.assertEqual(resolver.discover("mail.example.com")[1], "mail.example.com")
        self.assertEqual(resolver.organization("mail.example.com"), "example.com")

    def test_psd_n_stops_walk(self):
        resolver = self.resolver({"mail.example.com": ["v=DMARC1; psd=n"]})
        self.assertEqual(resolver.organization("a.mail.example.com"), "mail.example.com")
        self.assertNotIn("_dmarc.example.com", resolver.queries)

    def test_psd_y_prevents_alignment_between_sibling_organizations(self):
        resolver = self.resolver({"bank.example": ["v=DMARC1; psd=y; p=reject"]})
        self.assertEqual(resolver.organization("mail.giant.bank.example"), "giant.bank.example")
        self.assertFalse(resolver.aligned("mail.mega.bank.example", "giant.bank.example", "r"))
        self.assertEqual(resolver.discover("giant.bank.example")[1], "bank.example")

    def test_multiple_records_are_discarded_and_parent_search_continues(self):
        resolver = self.resolver({
            "mail.example.com": ["v=DMARC1; p=none", "v=DMARC1; p=reject"],
            "example.com": ["v=DMARC1; p=reject"],
        })
        self.assertEqual(resolver.discover("mail.example.com")[1], "example.com")
        self.assertTrue(resolver.warnings)

    def test_cache_reuses_shared_parents(self):
        resolver = self.resolver({"example.com": ["v=DMARC1"]})
        self.assertTrue(resolver.aligned("mail.example.com", "example.com", "r"))
        resolver.organization("mail.example.com")
        self.assertEqual(resolver.queries.count("_dmarc.example.com"), 1)

    def test_strict_alignment_does_not_query_dns(self):
        resolver = self.resolver({})
        self.assertFalse(resolver.aligned("mail.example.com", "example.com", "s"))
        self.assertEqual(resolver.queries, [])

    def test_np_and_test_mode_do_not_change_authentication(self):
        resolver = self.resolver({}, exists=False)
        tags = parse_policy("v=DMARC1; p=none; sp=quarantine; np=reject; t=y")[0]
        self.assertEqual(resolver.effective_policy("absent.example.com", "example.com", tags),
                         ("reject", "quarantine"))
        resolver.exists_lookup.assert_called_once()

    def test_existing_domain_uses_sp(self):
        resolver = self.resolver({}, exists=True)
        tags = parse_policy("v=DMARC1; p=none; sp=quarantine; np=reject")[0]
        self.assertEqual(resolver.effective_policy("mail.example.com", "example.com", tags),
                         ("quarantine", "quarantine"))

    def test_dns_failure_is_not_no_policy(self):
        resolver = self.resolver({})
        resolver.txt_lookup.side_effect = DNSLookupError("timeout")
        with self.assertRaises(DNSLookupError):
            resolver.discover("example.org")

    def test_online_evaluation_uses_tree_alignment_and_subdomain_policy(self):
        records = {"example.org": [b"v=DMARC1; p=none; sp=reject; psd=n"]}
        message = BytesParser(policy=policy.default).parsebytes(
            b"From: sender@mail.example.org\r\n\r\n"
        )
        spf = {"authenticated": True, "result": "pass",
               "identity": {"mail_from": "bounce@example.org"}}
        with patch.object(meioc, "txt_dns_records", side_effect=lambda name, timeout:
                          records.get(name.removeprefix("_dmarc."), [])):
            result = meioc.verify_dmarc_online(message, spf, {"signatures": []})
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["policy"], "reject")
        self.assertEqual(result["standard"], "RFC9989")
