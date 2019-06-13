#!/usr/bin/python3
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
import hashlib
import warnings
import argparse
import ipaddress
import encodings
import tldextract
from email import policy
from bs4 import BeautifulSoup
from email.parser import BytesParser

warnings.simplefilter(action="ignore", category=FutureWarning)
tldcache = tldextract.TLDExtract(cache_file="./.tld_set")
encodings.aliases.aliases["cp_850"] = "cp850"


def email_analysis(filename, exclude_private_ip, check_spf):
    urlList = []
    hopList = []
    hopListIP = []
    domainList = []
    hopListIPnoPrivate = []

    with open(filename, "rb") as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    if msg:
        # A sender obfuscation technique involves entering two e-mails. Only the last one is the real one. Example:
        #
        # Sender Name: Mario Rossi <rossi.mario@example.com>
        # Sender Mail: spoof@example.com

        if msg["From"]:
            mail_from = re.findall("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", msg["From"], re.IGNORECASE)

            if mail_from:
                mail_from = mail_from[-1]
            else:
                mail_from = ""
        else:
            mail_from = ""

        if msg["Sender"]:
            mail_sender = msg["Sender"]
        else:
            mail_sender = ""

        if msg["X-Sender"]:
            mail_xsender = msg["X-Sender"]
        else:
            mail_xsender = ""

        if msg["To"]:
            mail_to = re.findall("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", msg["To"], re.IGNORECASE)

            if mail_to:
                mail_to = dict(zip(range(len(mail_to)), mail_to))
            else:
                mail_to = ""
        else:
            mail_to = ""

        if msg["Bcc"]:
            mail_bcc = msg["Bcc"]
        else:
            mail_bcc = ""

        if msg["Cc"]:
            mail_cc = re.findall("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", msg["Cc"], re.IGNORECASE)

            if mail_cc:
                mail_cc = dict(zip(range(len(mail_cc)), mail_cc))
            else:
                mail_cc = ""
        else:
            mail_cc = ""

        if msg["Envelope-to"]:

            mail_envelopeto = re.findall("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", msg["Envelope-to"],
                                         re.IGNORECASE)

            if mail_envelopeto:
                mail_envelopeto = dict(zip(range(len(mail_envelopeto)), mail_envelopeto))
            else:
                mail_envelopeto = ""
        else:
            mail_envelopeto = ""

        if msg["Delivered-To"]:
            mail_deliveredto = msg["Delivered-To"]
        else:
            mail_deliveredto = ""

        if msg["X-Originating-IP"]:
            # Usually the IP is in square brackets, I remove them if present.
            mail_xorigip = msg["X-Originating-IP"].replace("[", "").replace("]", "")
        else:
            mail_xorigip = ""

        if msg["Subject"]:
            mail_subject = msg["Subject"]
        else:
            mail_subject = ""

        resultmeioc = {
            "filename": os.path.basename(filename),
            "from": mail_from,
            "sender": mail_sender,
            "x-sender": mail_xsender,
            "to": mail_to,
            "cc": mail_cc,
            "bcc": mail_bcc,
            "envelope-to": mail_envelopeto,
            "delivered-to": mail_deliveredto,
            "subject": mail_subject,
            "x-originating-ip": mail_xorigip,
        }

        # Identify each url or attachment reported in the eMail body
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                # https://gist.github.com/dperini/729294
                urlList.extend(re.findall(
                    "(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+(?:[a-z\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?(?:[/?#]\S*)?",
                    part.get_content(), re.UNICODE | re.IGNORECASE | re.MULTILINE))

            if part.get_content_type() == "text/html":
                soup = BeautifulSoup(part.get_content(), "html.parser")
                tags = soup.find_all("a", href=True)
                for url in tags:
                    urlList.append(url.get("href"))

            if part.get_filename():
                if part.get_filename():
                    if part.get_payload(decode=True):
                        filename = part.get_filename()
                        filemd5 = hashlib.md5(part.get_payload(decode=True)).hexdigest()
                        filesha1 = hashlib.sha1(part.get_payload(decode=True)).hexdigest()
                        filesha256 = hashlib.sha256(part.get_payload(decode=True)).hexdigest()

                        resultmeioc.update(
                            {"attachments": {"filename": filename, "MD5": filemd5, "SHA1": filesha1,
                                             "SHA256": filesha256}})

        # Identify each domain reported in the eMail body
        for url in urlList:
            analyzeddomain = tldcache(url).registered_domain
            if analyzeddomain:
                domainList.append(analyzeddomain)

        # Remove Duplicate
        urlList = list(set(urlList))
        domainList = list(set(domainList))

        # Identify each relay
        received = msg.get_all("Received")
        if received:
            received.reverse()
            for line in received:
                hops = re.findall("from\s+(.*?)\s+by(.*?)(?:(?:with|via)(.*?)(?:id|$)|id|$)", line,
                                  re.DOTALL | re.X)
                for hop in hops:

                    ipv4_address = re.findall(r"[0-9]+(?:\.[0-9]+){3}", hop[0], re.DOTALL | re.X)

                    # https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
                    ipv6_address = re.findall(
                        r"(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}:[^\s:](?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:::(?:ffff(?::0{1,4}){0,1}:){0,1}[^\s:](?:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))|(?:fe80:(?::(?:(?:[0-9a-fA-F]){1,4})){0,4}%[0-9a-zA-Z]{1,})|(?::(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,7}|:))|(?:(?:(?:[0-9a-fA-F]){1,4}):(?:(?::(?:(?:[0-9a-fA-F]){1,4})){1,6}))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,2}(?::(?:(?:[0-9a-fA-F]){1,4})){1,5})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,3}(?::(?:(?:[0-9a-fA-F]){1,4})){1,4})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,4}(?::(?:(?:[0-9a-fA-F]){1,4})){1,3})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,5}(?::(?:(?:[0-9a-fA-F]){1,4})){1,2})|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,6}:(?:(?:[0-9a-fA-F]){1,4}))|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){1,7}:)|(?:(?:(?:(?:[0-9a-fA-F]){1,4}):){7,7}(?:(?:[0-9a-fA-F]){1,4}))",
                        hop[0], re.DOTALL | re.X)

                    if ipv4_address:
                        for ipv4 in ipv4_address:
                            if ipaddress.ip_address(ipv4):
                                hopListIP.append(ipv4)
                                if not ipaddress.ip_address(ipv4).is_private:
                                    hopListIPnoPrivate.append(ipv4)

                    if ipv6_address:
                        for ipv6 in ipv6_address:
                            if ipaddress.ip_address(ipv6):
                                hopListIP.append(ipv6)

                                if not ipaddress.ip_address(ipv6).is_private:
                                    hopListIPnoPrivate.append(ipv6)

                    if hop[0]:
                        hopList.append(hop[0])

        if hopList:
            resultmeioc.update({"relay_full": dict(zip(range(len(hopList)), hopList))})

        if hopListIP:
            if exclude_private_ip:
                resultmeioc.update({"relay_ip": dict(zip(range(len(hopListIPnoPrivate)), hopListIPnoPrivate))})
            else:
                resultmeioc.update({"relay_ip": dict(zip(range(len(hopListIP)), hopListIP))})

        if urlList:
            resultmeioc.update({"urls": dict(zip(range(len(urlList)), urlList))})
            resultmeioc.update({"domains": dict(zip(range(len(domainList)), domainList))})

        # Verify the SPF record if requested
        if check_spf:
            testspf = False
            for ip in hopListIPnoPrivate:
                if not testspf and mail_from:
                    resultspf = spf.check2(ip, mail_from, mail_from.split("@")[1])[0]

                    if resultspf == "pass":
                        testspf = True
                    else:
                        testspf = False

            resultmeioc.update({"spf": testspf})

        print(json.dumps(resultmeioc, indent=4))


def main():
    version = "1.1"
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Analyze an eMail (.eml format)")
    parser.add_argument("-x", "--exclude-private-ip", action="store_true", dest="excprip",
                        help="Exclude private IPs from the report")
    parser.add_argument("-s", "--spf", action="store_true", dest="spf",
                        help="Check SPF Records")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + version)

    arguments = parser.parse_args()

    if arguments.filename:
        email_analysis(arguments.filename, arguments.excprip, arguments.spf)


if __name__ == "__main__":
    main()
