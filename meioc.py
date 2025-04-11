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
import hashlib
import warnings
import argparse
import ipaddress
import encodings
import tldextract
from typing import Union, Dict
from bs4 import BeautifulSoup
from email.utils import parseaddr
from email.message import Message
from email import message_from_bytes, policy
from pathlib import Path
import tools.msgtoeml

# what mail message formats are supported
supported_mail_message_format = [
    ".eml",
    ".msg"
]

tld_cache = tldextract.TLDExtract()
encodings.aliases.aliases["cp_850"] = "cp850"
warnings.simplefilter(action="ignore", category=FutureWarning)

# Global Meioc context
hops_list = []
hops_list_ip = []
hops_list_ip_public = []
urls_list = []
domains_list = []
attachments_ist = []

# Precompile the regex pattern for email extraction
email_regex = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)

def real_email_sender(mail_from: str) -> Union[str, None]:
    """
    Read mail message and return real email. 
    A sender obfuscation technique involves entering two e-mails. Only the last one is the real one. Example:
    
    Sender Name: Mario Rossi <rossi.mario@big-society.com>
    Sender Mail: spoof@example.com
    From values is: "Mario Rossi <rossi.mario@big-society.com>" <spoof@example.com>

    Args:
        mail_from (string) : raw mail_from user.
    Returns:
        str or None : parsed correct mail from user or none.
    """
    try:
        _, email_address = parseaddr(mail_from)
        return email_address.lower() if email_address else None
    except:
        return None

def normalize_headers(raw_email_bytes: bytes) -> bytes:
    """
    Normalize email headers by fixing spaces before ':' in a bytes-like email,
    while preserving multi-line header continuation.
    
    Args:
        raw_email_bytes (bytes) : Raw email in bytes-like format.
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

def load_mail_file(filename: str, suffix: str) -> bytes:
    """ 
    Load supported email file.

    Args:
        filename (str) : email to load.
        suffix   (str) : email suffix
    Returns:
        bytes: email in bytes-like format.
    """
    mail : str
    if suffix == ".msg":
        mail = tools.msgtoeml.load(filename).as_string().encode()
    else:
        with open(filename, "rb") as fd:
            mail = fd.read()
    return mail

def header_analysis(meioc: Dict, parsed_email: Message) -> None:
    """
        Parse email headers.

        Args:
            meioc        (dict)   : meioc result dictonary
            parsed_email (Message): parsed email 
        Returns:
            None
    """
    
    if parsed_email["Date"]:
        meioc["date"] = parsed_email["Date"]

    if parsed_email["From"]:
        mail_from = real_email_sender(parsed_email["From"])

        if mail_from:
            meioc["from"] = mail_from

    if parsed_email["Sender"]:
        mail_sender = real_email_sender(parsed_email["Sender"])

        if mail_sender:
            meioc["sender"] = mail_sender

    if parsed_email["X-Sender"]:
        mail_xsender = real_email_sender(parsed_email["X-Sender"])

        if mail_xsender:
            meioc["x-sender"] = mail_xsender

    if parsed_email["To"]:
        mail_to = email_regex.findall(parsed_email["To"])
        if mail_to:
            # Convert to lower, remove possible duplicates, and create a numbered dictionary
            mail_to = {i: x.lower() for i, x in enumerate(set(mail_to))}
            meioc["to"] = mail_to

    if parsed_email["Bcc"]:
        meioc["bcc"] = parsed_email["Bcc"].lower()

    if parsed_email["Cc"]:
        mail_cc_list = []
        for mail in parsed_email["Cc"].split(","):
            mail_cc = real_email_sender(mail)

            if mail_cc:
                mail_cc_list.append(mail_cc)

        if mail_cc_list:
            # Convert to lower, remove possible duplicates, and create a numbered dictionary
            mail_cc_list = {i: x.lower() for i, x in enumerate(set(mail_cc_list))}
            meioc["cc"] = mail_cc_list

    if parsed_email["Envelope-to"]:

        mail_envelopeto = email_regex.findall(parsed_email["Envelope-to"])

        if mail_envelopeto:
            # Convert to lower, remove possible duplicates, and create a numbered dictionary
            mail_envelopeto = {i: x.lower() for i, x in enumerate(set(mail_envelopeto))}
            meioc["envelope-to"] = mail_envelopeto

    if parsed_email["Delivered-To"]:
        meioc["delivered-to"] = parsed_email["Delivered-To"].lower()

    if parsed_email["Return-Path"]:
        mail_returnpath = real_email_sender(parsed_email["Return-Path"])

        if mail_returnpath:
            meioc["return-path"] = mail_returnpath

    if parsed_email["User-Agent"]:
        meioc["user-agent"] = parsed_email["User-Agent"]

    if parsed_email["X-Mailer"]:
        meioc["x-mailer"] = parsed_email["X-Mailer"]

    if parsed_email["X-Originating-IP"]:
        # Usually the IP is in square brackets, I remove them if present.
        mail_xorigip = parsed_email["X-Originating-IP"].replace("[", "").replace("]", "")
        meioc["x-originating-ip"] = mail_xorigip

    if parsed_email["Subject"]:
        meioc["subject"] = parsed_email["Subject"]

def relays_analysis(meioc: Dict, parsed_email: Message, exclude_private_ip: bool):
    """
        Parse available relays.

        Args:
            meioc        (dict)       : meioc result dictonary
            parsed_email (Message)    : parsed email
            exclude_private_ip (bool) : private ip exclusion check
        Returns:
            None 
    """
    global hops_list, hops_list_ip, hops_list_ip_public

    received = parsed_email.get_all("Received")
    if received:
        received.reverse()
        for line in received:
            hops = re.findall(r"from\s+(.*?)\s+by(.*?)(?:(?:with|via)(.*?)(?:id|$)|id|$)", line, re.DOTALL | re.X)
            for hop in hops:

                ipv4_address = re.findall(r"[0-9]+(?:\.[0-9]+){3}", hop[0], re.DOTALL | re.X)
                # https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
                ipv6_address = re.findall(
                    r"(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}:[^\s:](?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:](?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:fe80:(?::(?:(?:[0-9a-fA-F]){1,4})){0,4}%[0-9a-zA-Z]{1,})|(?::(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,7}|:))|(?:(?:(?:[0-9a-fA-F]){1,4}):(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,6}))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,2}(?::(?:(?:[0-9a-fA-F]){1,4})){1,5})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,3}(?::(?:(?:[0-9a-fA-F]){1,4})){1,4})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}(?::(?:(?:[0-9a-fA-F]){1,4})){1,3})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,5}(?::(?:(?:[0-9a-fA-F]){1,4})){1,2})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,6}:(?:(?:[0-9a-fA-F]){1,4}))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,7}:)|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){7,7}(?:(?:[0-9a-fA-F]){1,4}))",
                    hop[0], re.DOTALL | re.X)

                if ipv4_address:
                    for ipv4 in ipv4_address:
                        if ipaddress.ip_address(ipv4):
                            hops_list_ip.append(ipv4)
                            if not ipaddress.ip_address(ipv4).is_private:
                                hops_list_ip_public.append(ipv4)

                if ipv6_address:
                    for ipv6 in ipv6_address:
                        if ipaddress.ip_address(ipv6) and not "6::":
                            hops_list_ip.append(ipv6)

                            if not ipaddress.ip_address(ipv6).is_private:
                                hops_list_ip_public.append(ipv6)

                if hop[0]:
                    hops_list.append(hop[0])

    if hops_list:
        meioc["relay_full"] = dict(zip(range(len(hops_list)), hops_list))

    if hops_list_ip:
        if exclude_private_ip:
            meioc["relay_ip"] = dict(zip(range(len(hops_list_ip_public)), hops_list_ip_public))
        else:
            meioc["relay_ip"] = dict(zip(range(len(hops_list_ip)), hops_list_ip))

def body_analysis(meioc: Dict, parsed_email: Message) -> None:
    """
        Parse mail body.

        Args:
            meioc        (dict)   : meioc result dictonary
            parsed_email (Message): parsed email 
        Returns:
            None
    """
    global urls_list, domains_list, attachments_ist

    # TODO: Need test cases to validate urls/domains
    for part in parsed_email.walk():
        print(part.get_content_type())
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
        analyzeddomain = tld_cache(url).registered_domain
        if analyzeddomain:
            domains_list.append(analyzeddomain)

    # Remove Duplicate from List
    urls_list = list(set(urls_list))
    domains_list = list(set(domains_list))

    if urls_list:
        meioc["urls"] = dict(zip(range(len(urls_list)), urls_list))
        meioc["domains"] = dict(zip(range(len(domains_list)), domains_list))

    if attachments_ist:
        meioc["attachments"] = attachments_ist

def verify_spf(meioc: Dict, check_spf: bool) -> None:
    """
        Verify SPF record.

        Args:
            meioc     (dict) : meioc result dictonary
            check_spf (bool) : SPF verification check 
        Returns:
            None
    """
    if check_spf:
        test_spf = False
        result_spf = ""
        for ip in hops_list_ip_public:
            if not test_spf and meioc["from"]:
                try:
                    domain_from = meioc["from"].split("@")[1]
                    result_spf = spf.check2(ip, meioc["from"], domain_from)[0]
                except:
                    pass

                if result_spf == "pass":
                    test_spf = True
                else:
                    test_spf = False

        meioc["spf"] = test_spf

def verify_dkim(meioc: Dict, check_dkim: bool, raw_email_content_normalized: bytes) -> None:
    """ 
        Verify DKIM record.

        Args:
            meioc       (dict) : meioc result dictonary
            check_dkim  (str)  : DKIM verification check
            raw_email_content_normalized (bytes) : normalized email in bytes
        Returns:
            None
    """
    if check_dkim:
        test_dkim = False
        try:
            dkim_result = dkim.verify(raw_email_content_normalized)
            if dkim_result:
                test_dkim = True
        except:
            pass

        meioc["dkim"] = test_dkim

def email_analysis(filename: str, exclude_private_ip: bool, check_spf: bool, check_dkim: bool, file_output: str) -> None:
    """
        Execute a full email analysis.

        Args:
            filename            (str)  : meioc result dictonary
            exclude_private_ip  (bool) : private ip check
            check_spf           (bool) : SPF verification check
            check_dkim          (bool) : DKIM verification check
            file_output         (str)  : result output dump to file 
        Returns:
            None
    """

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

    mail_ext = Path(filename).suffixes[-1]
    if mail_ext in supported_mail_message_format:
        # Open E-mail
        raw_email_content = load_mail_file(filename, mail_ext)

        # Parsing E-mail
        raw_email_content_normalized = normalize_headers(raw_email_content)
        parsed_email = message_from_bytes(raw_email_content_normalized, policy=policy.default)

        if parsed_email:
            #
            # Headers analysis
            #
            header_analysis(result_meioc, parsed_email)
            #
            # Identify each relay
            #
            relays_analysis(result_meioc, parsed_email, exclude_private_ip)
            #
            # Body analysis
            #
            body_analysis(result_meioc, parsed_email)
            #
            # Verify the SPF record if requested
            #
            verify_spf(result_meioc, check_spf)
            #
            # Verify the DKIM record if requested
            #
            verify_dkim(result_meioc, check_dkim, raw_email_content_normalized)

            if file_output:
                with open(file_output, "w") as f:
                    json.dump(result_meioc, f, indent=4)
                print("[!] Output saved in: %s" % file_output)
            else:
                print(json.dumps(result_meioc, indent=4))
    else:
        raise Exception("unsupported email message")

def main():
    version = "1.5"
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Analyze an e-mail (.eml/.msg format)")
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