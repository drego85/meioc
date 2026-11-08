# Meioc

![Version](https://img.shields.io/badge/version-2.2.0-blue)
![GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen)

**Meioc** (Mail Extractor IoC) analyzes RFC 5322 `.eml` messages and Microsoft
Outlook `.msg` containers and extracts indicators of compromise into JSON for
SOC and threat-intelligence workflows.

## What it extracts

- sender and recipient headers;
- the relay chain and IP addresses found only in `Received` headers;
- ordinary HTTP, HTTPS, and FTP URLs (defanged URLs are intentionally ignored);
- registrable domains derived from those URLs;
- attachment name, media type, size, MD5, SHA-1, and SHA-256;
- independent SPF, DKIM, and DMARC results using current DNS;
- receiver-reported authentication results in verbose output, when present.

Meioc does not extract email addresses from the message body or standalone IP
addresses outside the `Received` chain.

## Authentication

- SPF, DKIM, and DMARC use live DNS by default.
- Authentication and domain alignment are reported separately.
- Current DNS results may differ from results recorded at delivery.
- DKIM signatures in reconstructed MSG messages cannot be cryptographically verified.
- Use `--verbose` for diagnostics and `--offline-auth` to disable DNS queries.

See [authentication details](docs/authentication.md) for result interpretation
and SMTP session reconstruction.

## Installation

```bash
git clone https://github.com/drego85/meioc.git
cd meioc
python3 -m venv venv
source venv/bin/activate
python3 -m pip install .
meioc --version
```

Python 3.10 or newer is required. Use a fresh virtual environment when upgrading
from older versions that used Py3DNS, to avoid DNS package conflicts.
You can also run `python3 meioc.py` directly from the repository.

## Usage

Analyze an email with live SPF, DKIM, and DMARC verification:

```bash
meioc suspicious.eml
```

MSG files use the same command and output format:

```bash
meioc suspicious.msg
```

Write the JSON report to a file:

```bash
meioc suspicious.eml --output report.json
```

Use `--verbose` for the full diagnostic report:

```bash
meioc suspicious.eml --verbose
```

Analyze without DNS and exclude non-global relay IPs from the indicator list:

```bash
meioc suspicious.eml --offline-auth --exclude-private-ip
```

Options:

- `-x`, `--exclude-private-ip`: keep only globally routable relay IP indicators;
- `--offline-auth`: disable DNS queries and report available header evidence;
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
  "spf": {"result": "fail", "scope": "mailfrom", "domain": "example.org", "alignment": "strict"},
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

## Development

```bash
python3 -m unittest discover -s tests -v
```

Tests use synthetic fixtures and do not require network access. When available,
the ignored `sourceemail/` directory adds local EML/MSG corpus checks. Never
commit real email samples or include them in package artifacts.

To build a wheel and source distribution:

```bash
python3 -m pip install build
python3 -m build
```

## Contributing and Supporting the Project

There are three ways you can contribute to the development of **meioc**:

1. **Development Contributions**:

   Please ensure that your code follows best practices and includes relevant tests.

2. **Donation Support**:

   If you find this project useful and would like to support its development, you can also make a donation via [Buy Me a Coffee](https://buymeacoffee.com/andreadraghetti). Your support is greatly appreciated and helps to keep this project going!

   [![Buy Me a Coffee](https://img.shields.io/badge/-Buy%20Me%20a%20Coffee-orange?logo=buy-me-a-coffee&logoColor=white&style=flat-square)](https://buymeacoffee.com/andreadraghetti)

3. **Share the Project**:

   Sharing Meioc with colleagues, friends, and anyone interested in email analysis and threat intelligence helps the project grow and reach more practitioners in the community.

## License

Meioc is distributed under the GNU General Public License v3.0.
