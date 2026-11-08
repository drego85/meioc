# Authentication details

This reference explains how to interpret Meioc's authentication results and how
the analyzed SMTP session is selected. For installation and everyday commands,
see the [README](../README.md).

Live DNS verification is enabled by default.

## SPF and SMTP sessions

For SPF, Meioc evaluates the SMTP envelope sender (`MAIL FROM`/`Return-Path`),
not the visible `From` header. It resolves the recipient domain's current MX
records and, when that edge is present in the `Received` chain, evaluates the
IP that connected to the published MX, provided that the MAIL FROM identity is
available in that hop or in SPF evidence explicitly bound to the same client IP.
The final Return-Path is not assumed to describe an earlier SMTP session. If the
selected MX session lacks envelope evidence, SPF is `not_available`. This prevents a downstream forwarding
hop, such as an antispam gateway delivering into a mailbox provider, from being
mistaken for the original sender. If the MX edge cannot be identified, Meioc
falls back to the `client-ip` recorded by the receiving infrastructure and then
to the first global source IP at the receiving boundary. The complete RFC
result is retained: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`,
or `permerror`.

SPF reports include `scope` (`mailfrom` or `helo`) and the checked `domain`,
including in compact output. A HELO result does not authenticate the visible
From domain and is not used as MAIL FROM authentication by DMARC. An explicitly
null Return-Path (`<>`) uses the RFC 7208 postmaster/HELO identity as `mailfrom`.
When verification is unavailable, no checked identity is asserted. Offline
reports label the identity only when explicitly present in the reported result.

Recipient discovery uses the first available header group in this order:
`Envelope-To`, `Delivered-To`, `To`, `Cc`. Current MX records are a reconstruction
aid, not proof of the historical route. The verbose report identifies the chosen
session and any missing evidence.

Receiver SPF prose such as MXFilter's `domain of ... designates ...` and
`has no SPF policy when checking ...` is accepted as SMTP identity evidence
when it matches the MAIL FROM property, authentication service, and a unique
Received source session. Conflicting IPs or envelope identities remain
unavailable. Meioc then evaluates SPF using current DNS independently of the
receiver's reported pass/fail result.

An `ESMTPA`/`ESMTPSA` submission followed only by local delivery is reported as
SPF `not_available` with reason `authenticated_submission_only`. The client IP
is not treated as the outbound relay. A newer external SMTP transfer remains
eligible for SPF evaluation. The verbose report preserves the submission
protocol, receiver, and client IP. SMTP AUTH does not imply SPF or DMARC pass;
DMARC still requires aligned authentication, or reports incomplete evidence
when no external session is available (and `none` if no policy applies).

Authentication and alignment are reported separately. A message can therefore
have `authenticated: false` while still having strict or relaxed alignment when
the unauthenticated `MAIL FROM` domain matches the visible `From` domain.

## DKIM verification

For DKIM, every `DKIM-Signature` is checked against the original, unmodified
message bytes. The overall result is `pass` when at least one signature verifies;
DNS uncertainty is preserved as `temperror` instead of being reported as a
cryptographic failure.

Outlook MSG containers do not necessarily preserve the original serialized MIME
bytes. Meioc therefore never performs DKIM cryptographic verification on the
reconstructed message: a preserved signature is reported as `not_verifiable`.
SPF and DMARC can still be evaluated when the MSG retains usable transport
headers such as `Received` and `Return-Path`; otherwise they are reported as
unavailable.

## DMARC policy evaluation

DMARC policy evaluation follows [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html).
The dedicated `dmarc_policy.py` module uses bounded DNS tree walks, cached per
analysis, for policy discovery and authenticated identifier alignment. It handles
`psd`, inherited `sp`/`np`, optional `p`, recoverable tag errors, and test mode `t`.
The verbose report distinguishes the published policy from its effective test-mode
policy and includes discovery queries and warnings. Unknown/obsolete tags are
ignored. DNS errors remain indeterminate unless another aligned method passes.
NODATA and NXDOMAIN are distinguished when selecting `np`.

Meioc evaluates evidence and policies; it does not deliver mail or generate DMARC
reports. Reconstructed SPF is scoped to the selected SMTP session and may differ
from the final receiver's reported result. Offline alignment remains a PSL-based
diagnostic, without independent DMARC DNS evaluation.

## Current and reported results

The `reported` object contains evidence copied from `Authentication-Results` or
`Received-SPF`. It is deliberately marked separately from the independent DNS
check. Interpreting these recorded results assumes the analyst trusts the infrastructure
that added them.

DNS records can change after message delivery. For old messages, compare the
current independent result with `reported`; a disagreement does not by itself
prove that the original receiving system was wrong.

## Offline analysis

Use `--offline-auth` to suppress DNS queries. In that mode, Meioc reports only
header evidence and signature presence; it never labels an unverified signature
as valid.


## Verbose JSON schema v2

With `--verbose`, schema version 2 groups headers, relays, authentication, and
indicators. This abbreviated example illustrates the structure; optional fields
and detailed DNS evidence are omitted:

```json
{
  "schema_version": 2,
  "source_format": "eml",
  "filename": "suspicious.eml",
  "headers": {
    "from": "sender@example.org",
    "to": ["analyst@example.net"],
    "return_path": "bounce@example.org"
  },
  "relays": {
    "hops": [
      {
        "from": "mail.example.org ([192.0.2.10])",
        "by": "mx.example.net",
        "with": "ESMTP",
        "ips": ["192.0.2.10"],
        "raw": "from mail.example.org ... by mx.example.net ..."
      }
    ],
    "ips": ["192.0.2.10"]
  },
  "authentication": {
    "mode": "online",
    "spf": {
      "result": "pass",
      "scope": "mailfrom",
      "domain": "example.org",
      "source": "dns",
      "independent": true,
      "authenticated": true,
      "identity": {
        "mail_from": "bounce@example.org",
        "client_ip": "192.0.2.10",
        "helo": "mail.example.org",
        "source": "received"
      },
      "alignment": {
        "identity_domain": "example.org",
        "header_from_domain": "example.org",
        "strict": true,
        "relaxed": true
      },
      "reported": null
    },
    "dkim": {
      "result": "pass",
      "source": "dns",
      "independent": true,
      "authenticated": true,
      "signatures": [
        {
          "domain": "example.org",
          "selector": "mail",
          "algorithm": "rsa-sha256",
          "verified": true
        }
      ],
      "alignment": {
        "header_from_domain": "example.org",
        "strict": true,
        "relaxed": true
      },
      "reported": null
    },
    "dmarc": {
      "result": "pass",
      "source": "dns",
      "independent": true,
      "standard": "RFC9989",
      "header_from_domain": "example.org",
      "organizational_domain": null,
      "policy_domain": "example.org",
      "policy": "reject",
      "effective_policy": "reject",
      "test_mode": false,
      "aligned_via": ["spf", "dkim"],
      "reported": null
    }
  },
  "indicators": {
    "urls": ["https://example.org/login"],
    "domains": ["example.org"],
    "attachments": []
  }
}
```

Fields that are unavailable are represented by `null`, empty arrays, or an
explicit authentication result such as `not_available`; a DNS error is reported
as `temperror`, not collapsed into `false`.
