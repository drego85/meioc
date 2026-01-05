#!/usr/bin/env python3
# This file is part of Meioc.
#
# Meioc was made with ♥ by Andrea Draghetti
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 3 (the ``GPL'').
#
import os
import re
import spf
import json
import dkim
import email
import hashlib
import warnings
import argparse
import ipaddress
import encodings
import tldextract
from email import policy
from bs4 import BeautifulSoup
from email.utils import parseaddr
from email.utils import getaddresses
from email import message_from_bytes
from email.message import EmailMessage

encodings.aliases.aliases["cp_850"] = "cp850"
warnings.simplefilter(action="ignore", category=FutureWarning)

# Precompile the regex pattern for email extraction
email_regex = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)


# Safely extracts a single email address from a structured or unstructured email header.
def extract_email_address(header):
    if header is None:
        return None

    try:
        # For structured headers like 'From', 'Sender', etc.
        if hasattr(header, "addresses") and header.addresses:
            return header.addresses[0].addr_spec.lower()

        # For unstructured headers like 'Return-Path'
        name, addr = parseaddr(str(header))
        if addr:
            return addr.lower()

    except Exception:
        pass

    return None


# Safely extracts multiple email addresses from a structured or unstructured email header.
def extract_multiple_email_addresses(header):
    if header is None:
        return None

    try:
        # Structured header: use .addresses
        if hasattr(header, "addresses") and header.addresses:
            raw = [addr.addr_spec.lower() for addr in header.addresses]

        else:
            # Unstructured: parse using getaddresses (handles comma-separated lists)
            parsed = getaddresses([str(header)])
            raw = [addr.lower() for name, addr in parsed if addr]

        if raw:
            # Remove duplicates and enumerate
            return {i: email for i, email in enumerate(set(raw))}
    except Exception:
        pass

    return None


def normalize_headers(raw_email_bytes):
    """
    Normalize email headers by fixing spaces before ':' in a bytes-like email,
    while preserving multi-line header continuation.
    
    Args:
        raw_email_bytes (bytes): Raw email in bytes-like format.
    Returns:
        bytes: Normalized email in bytes-like format.
    """

    raw_email = raw_email_bytes.decode("utf-8", errors="replace")
    
    lines = raw_email.splitlines()
    normalized_lines = []
    for i, line in enumerate(lines):
        if line.startswith((' ', '\t')):
            normalized_lines.append(line)
        else:
            if ": " in line or ":" in line:
                header, sep, value = line.partition(":")
                header = header.strip()
                normalized_lines.append(f"{header}:{value}")
            else:
                normalized_lines.append(line)
    
    normalized_email = "\n".join(normalized_lines)
    return normalized_email.encode("utf-8")

def email_analysis(filename, exclude_private_ip, check_spf, check_dkim, file_output):
    urls_list = []
    hops_list = []
    hops_list_ip = []
    domains_list = []
    attachments_ist = []
    hops_list_ip_public = []

    result_meioc = {
        "filename": os.path.basename(filename),
        "from": None,
        "sender": None,
        "x-sender": None,
        "to": None,
        "cc": None,
        "bcc": None,
        "envelope-to": None,
        "delivered-to": None,
        "return-path": None,
        "subject": None,
        "date": None,
        "user-agent": None,
        "x-mailer": None,
        "x-originating-ip": None,
        "relay_full": None,
        "relay_ip": None,
        "spf": None,
        "dkim": None,
        "urls": None,
        "domains": None,
        "attachments": None
    }

    # Open E-mail
    with open(filename, "rb") as email_file:
        raw_email_content = email_file.read()

    # Parsing E-mail
    if raw_email_content:
        raw_email_content_normalized = normalize_headers(raw_email_content)
        parsed_email = message_from_bytes(raw_email_content_normalized, policy=policy.default)

    if parsed_email:

        #
        # Header analysis
        #

        if parsed_email["Date"]:
            result_meioc["date"] = parsed_email["Date"]

        result_meioc["from"] = extract_email_address(parsed_email.get("From"))

        result_meioc["sender"] = extract_email_address(parsed_email.get("Sender"))

        result_meioc["x-sender"] = extract_email_address(parsed_email.get("X-Sender"))

        result_meioc["bcc"] = extract_email_address(parsed_email.get("Bcc"))

        result_meioc["delivered-to"] = extract_multiple_email_addresses(parsed_email.get("Delivered-To"))

        result_meioc["return-path"] = extract_email_address(parsed_email.get("Return-Path"))

        result_meioc["to"] = extract_multiple_email_addresses(parsed_email.get("To"))

        result_meioc["cc"] = extract_multiple_email_addresses(parsed_email.get("Cc"))

        result_meioc["envelope-to"] = extract_multiple_email_addresses(parsed_email.get("Envelope-to"))

        result_meioc["user-agent"] = parsed_email.get("User-Agent")

        result_meioc["x-mailer"] = parsed_email.get("X-Mailer")

        x_orig = parsed_email.get("X-Originating-IP")
        if x_orig:
            result_meioc["x-originating-ip"] = x_orig.replace("[", "").replace("]", "")

        if parsed_email["Subject"]:
            result_meioc["subject"] = parsed_email["Subject"]
        #
        # Identify each relay
        #
        received = parsed_email.get_all("Received")
        if received:
            received.reverse()
            for line in received:
                hops = re.findall("from\s+(.*?)\s+by(.*?)(?:(?:with|via)(.*?)(?:id|$)|id|$)", line, re.DOTALL | re.X)
                for hop in hops:

                    # Fix for email servers that attach the IPv6 label directly to the IP address (e.g. "IPv6:::1")
                    if "[IPv6:" in hop[0]:
                        hop = (hop[0].replace("[IPv6:", "[IPv6: ", 1),) + hop[1:]

                    # https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
                    IPV4SEG  = r'(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
                    IPV4ADDR = r'(?:(?:' + IPV4SEG + r'\.){3,3}' + IPV4SEG + r')'
                    IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
                    IPV6GROUPS = (
                        r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
                        r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
                        r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
                        r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
                        r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
                        r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
                        r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
                        IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
                        r':(?:(?::' + IPV6SEG + r'){1,7}|:)',                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
                        r'fe80:(?::' + IPV6SEG + r'){0,4}%[0-9a-zA-Z]{1,}',       # fe80::7:8%eth0     fe80::7:8%1  (link-local IPv6 addresses with zone index)
                        r'::(?i:ffff(?::0{1,4}){0,1}:){0,1}[^\s:]' + IPV4ADDR,     # ::255.255.255.255  ::ffff:255.255.255.255  ::ffff:0:255.255.255.255 (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
                        r'(?:' + IPV6SEG + r':){1,4}:[^\s:]' + IPV4ADDR,          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
                    )
                    IPV6ADDR = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match

                    # ipv4_address = re.findall(r"\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b", hop[0])
                    # ipv4_address = re.findall(r"[0-9]+(?:\.[0-9]+){3}", hop[0], re.DOTALL | re.X)
                    ipv4_address = re.findall(IPV4ADDR, hop[0], re.DOTALL | re.X)
    
                    ipv6_address = re.findall(IPV6ADDR, hop[0], re.DOTALL | re.X)

                    if ipv4_address:
                        for ipv4 in ipv4_address:
                            if ipaddress.ip_address(ipv4):
                                hops_list_ip.append(ipv4)
                                if not ipaddress.ip_address(ipv4).is_private:
                                    hops_list_ip_public.append(ipv4)

                    if ipv6_address:
                        for ipv6 in ipv6_address:
                            if ipaddress.ip_address(ipv6):
                                hops_list_ip.append(ipv6)

                                if not ipaddress.ip_address(ipv6).is_private:
                                    hops_list_ip_public.append(ipv6)

                    if hop[0]:
                        hops_list.append(hop[0])

        if hops_list:
            result_meioc["relay_full"] = dict(zip(range(len(hops_list)), hops_list))

        if hops_list_ip:
            if exclude_private_ip:
                result_meioc["relay_ip"] = dict(zip(range(len(hops_list_ip_public)), hops_list_ip_public))
            else:
                result_meioc["relay_ip"] = dict(zip(range(len(hops_list_ip)), hops_list_ip))

        #
        # Body analysis
        #
        for part in parsed_email.walk():
            # Extracts each URL identified in the e-mail in text/plain format
            if part.get_content_type() == "text/plain":
                # Regex is based on what Diego Perini shared:
                # https://gist.github.com/dperini/729294
                url_regex = r'(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+(?:[a-z\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?(?:[/?#][^\s>]*)?'
                urls_list.extend(re.findall(url_regex, part.get_content(), re.UNICODE | re.IGNORECASE | re.MULTILINE))
            
            # Extracts each URL identified in the e-mail in text/html format
            if part.get_content_type() == "text/html":
                # The try/except is necessary, if the body of the e-mail contains an incorrect or unencoded HTML code the script freeezes.
                try:
                    soup = BeautifulSoup(part.get_content(), "html.parser")
                    tags = soup.find_all("a", href=True)

                    # Handling the cases when a <base> tag is present.
                    # If this is the case, we must prefix all the URLs by the value of <base>.
                    tag_base = soup.find_all("base")
                    if tag_base:
                        # In browsers, it is the first <base> tag that is applied.
                        base = tag_base[0].get("href")
                    else:
                        base = ''

                    for url in tags:
                        urls_list.append(base + url.get("href"))
                except:
                    pass

            # Extracts information from each file attached to the e-mail
            if part.get_filename():
                if part.get_payload(decode=True):
                    filename = part.get_filename()
                    filemd5 = hashlib.md5(part.get_payload(decode=True)).hexdigest()
                    filesha1 = hashlib.sha1(part.get_payload(decode=True)).hexdigest()
                    filesha256 = hashlib.sha256(part.get_payload(decode=True)).hexdigest()

                    attachments_ist.append({"filename": filename, "MD5": filemd5, "SHA1": filesha1,
                                            "SHA256": filesha256})

        # Identify each domain reported in the e-mail body
        for url in urls_list:
            analyzed_domain = tldextract.extract(url).top_domain_under_public_suffix
            if analyzed_domain:
                domains_list.append(analyzed_domain)

        # Remove Duplicate from List
        urls_list = list(set(urls_list))
        domains_list = list(set(domains_list))

        if urls_list:
            result_meioc["urls"] = dict(zip(range(len(urls_list)), urls_list))
            result_meioc["domains"] = dict(zip(range(len(domains_list)), domains_list))

        if attachments_ist:
            result_meioc["attachments"] = attachments_ist

        #
        # Verify the SPF record if requested
        #
        if check_spf:
            test_spf = False
            mail_from = result_meioc.get("from")
            domain_from = mail_from.split("@")[1]
            for ip in hops_list_ip_public:
                if not test_spf and mail_from:
                    try:
                        result_spf = spf.check(ip, mail_from, domain_from)[0]
                        if result_spf == "pass":
                            test_spf = True
                    except:
                        pass

            result_meioc["spf"] = test_spf

        #
        # Verify the DKIM record if requested
        #
        if check_dkim:
            test_dkim = False
            try:
                dkim_result = dkim.verify(raw_email_content_normalized)
                if dkim_result:
                    test_dkim = True
            except:
                pass

            result_meioc["dkim"] = test_dkim


        if file_output:
            with open(file_output, "w") as f:
                json.dump(result_meioc, f, indent=4)
            print("[!] Output saved in: %s" % file_output)
        else:
            print(json.dumps(result_meioc, indent=4))


def main():
    version = "1.4"
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Analyze an e-mail (.eml format)")
    parser.add_argument("-x", "--exclude-private-ip", action="store_true", dest="excprip",
                        help="Exclude private IPs from the report")
    parser.add_argument("-s", "--spf", action="store_true", dest="spf",
                        help="Check SPF Records")
    parser.add_argument("-d", "--dkim", action="store_true", dest="dkim",
                        help="Check DKIM Records")
    parser.add_argument("-o", "--output", dest="file_output",
                        help="Write output to <file>")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + version)

    arguments = parser.parse_args()

    if arguments.filename:
        email_analysis(arguments.filename, arguments.excprip, arguments.spf ,arguments.dkim, arguments.file_output)


if __name__ == "__main__":
    main()
