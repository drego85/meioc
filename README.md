# Meioc

![Version](https://img.shields.io/badge/version-2.2-blue)
![GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen)

**Meioc** (Mail Extractor IoC) analyzes RFC 5322 `.eml` messages and Microsoft
Outlook `.msg` containers, and emits a deterministic JSON report for SOC and
incident-response workflows.

## What it extracts

- sender and recipient headers;
- the relay chain and IP addresses found only in `Received` headers;
- ordinary HTTP, HTTPS, and FTP URLs (defanged URLs are intentionally ignored);
- registrable domains derived from those URLs;
- attachment name, media type, size, MD5, SHA-1, and SHA-256;
- independent SPF and DKIM results obtained through DNS;
- SPF/DKIM results reported by the receiving infrastructure, when present.

Meioc does not extract email addresses from the message body or standalone IP
addresses outside the `Received` chain.

## Authentication model

Live DNS verification is enabled by default.

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

Recipient discovery uses the first available header group in this order:
`Envelope-To`, `Delivered-To`, `To`, `Cc`. Current MX records are a reconstruction
aid, not proof of the historical route. The verbose report identifies the chosen
session and any missing evidence.

Authentication and alignment are reported separately. A message can therefore
have `authenticated: false` while still having strict or relaxed alignment when
the unauthenticated `MAIL FROM` domain matches the visible `From` domain.

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

The `reported` object contains evidence copied from `Authentication-Results` or
`Received-SPF`. It is deliberately marked separately from the independent DNS
check because such headers are trustworthy only when added by infrastructure
under the analyst's control.

DNS records can change after message delivery. For old messages, compare the
current independent result with `reported`; a disagreement does not by itself
prove that the original receiving system was wrong.

Use `--offline-auth` to suppress DNS queries. In that mode, Meioc reports only
header evidence and signature presence; it never labels an unverified signature
as valid.

## Installation

```bash
git clone https://github.com/drego85/meioc.git
cd meioc
python3 -m venv venv
source venv/bin/activate
python3 -m pip install .
meioc --version
```

Python 3.10 or newer is required. Dependencies are declared once in
`requirements.txt` and used by the package build. Both `meioc suspicious.eml`
and `python3 meioc.py suspicious.eml` are supported.

To build a wheel and source distribution:

```bash
python3 -m pip install build
python3 -m build
```

Local email samples in `sourceemail/` must never be committed or distributed.
Package artifacts explicitly exclude email samples.

## Usage

Run the default analysis, including live SPF and DKIM verification:

```bash
python3 meioc.py suspicious.eml
```

MSG files use the same command and output format:

```bash
python3 meioc.py suspicious.msg
```

Write the JSON report to a file:

```bash
python3 meioc.py suspicious.eml --output report.json
```

The default output is a concise SOC view. Use `--verbose` when the complete
relay clauses, raw `Received` headers, authentication identities, DNS evidence,
alignment flags, and diagnostic reasons are needed:

```bash
python3 meioc.py suspicious.eml --verbose
```

Analyze without DNS and exclude non-global relay IPs from the indicator list:

```bash
python3 meioc.py suspicious.eml --offline-auth --exclude-private-ip
```

Options:

- `-x`, `--exclude-private-ip`: keep only globally routable relay IP indicators;
- `--offline-auth`: do not make SPF/DKIM DNS queries;
- `--verbose`: emit the complete diagnostic report instead of the concise view;
- `-o`, `--output`: write JSON to the selected path;
- `--max-size-mb`: reject messages above this size (default: 50 MiB);
- `-v`, `--version`: print the Meioc version.

## Compact JSON output

The default report keeps the analyst-facing facts and omits null headers and
diagnostic evidence:

```json
{
  "schema_version": 2,
  "format": "compact",
  "source_format": "eml",
  "filename": "suspicious.eml",
  "from": "sender@example.org",
  "to": ["analyst@example.net"],
  "relays": ["mail.example.org ([192.0.2.10])"],
  "relay_ips": ["192.0.2.10"],
  "spf": {"result": "fail", "alignment": "strict"},
  "dkim": {"result": "none", "alignment": "none"},
  "dmarc": {"result": "none"},
  "urls": ["https://example.org/login"],
  "domains": ["example.org"],
  "attachments": []
}
```

Authentication remains distinct from alignment: `result: fail` with
`alignment: strict` is valid and means the identifiers match but the sending IP
was not authorized.

## Verbose JSON schema v2

With `--verbose`, version 2 groups all diagnostic values:

```json
{
  "schema_version": 2,
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
      "header_from_domain": "example.org",
      "organizational_domain": "example.org",
      "policy_domain": "example.org",
      "policy": "reject",
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

## Tests

```bash
python3 -m unittest discover -s tests -v
```

If the ignored local `sourceemail` directory is present, the suite also parses
every `.eml` file in that corpus without performing network requests.

## License

Meioc is distributed under the GNU General Public License v3.0.
