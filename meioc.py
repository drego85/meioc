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
import email
import hashlib
import warnings
import argparse
import ipaddress
import encodings
import tldextract
from email import policy
from bs4 import BeautifulSoup

tld_cache = tldextract.TLDExtract()
encodings.aliases.aliases["cp_850"] = "cp850"
warnings.simplefilter(action="ignore", category=FutureWarning)

def real_email(string):
    # A sender obfuscation technique involves entering two e-mails. Only the last one is the real one. Example:
    #
    # Sender Name: Mario Rossi <rossi.mario@big-society.com>
    # Sender Mail: spoof@example.com

    try:
        mail = re.findall("[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", string,
                               re.IGNORECASE)
        mail = mail[-1]
        return mail
    except:
        return None

def email_analysis(run_as_module, filename, exclude_private_ip, check_spf, file_output):
    urlList = []
    hopList = []
    hopListIP = []
    domainList = []
    attachmentsList = []
    hopListIPnoPrivate = []

    resultmeioc = {
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
        "x-originating-ip": None,
        "relay_full": None,
        "relay_ip": None,
        "spf": None,
        "urls": None,
        "domains": None,
        "attachments": None
    }

    msg = email.message_from_file(open(filename, "r", errors="ignore"), policy=policy.default)

    if msg:

        #
        # Header analysis
        #

        if msg["Date"]:
            resultmeioc["date"] = msg["Date"]

        if msg["From"]:
            mail_from = real_email(msg["From"])

            if mail_from:
                resultmeioc["from"] = mail_from

        if msg["Sender"]:
            mail_sender = real_email(msg["Sender"])

            if mail_sender:
                resultmeioc["sender"] = mail_sender

        if msg["X-Sender"]:
            mail_xsender = real_email(msg["X-Sender"])

            if mail_xsender:
                resultmeioc["x-sender"] = mail_xsender

        if msg["To"]:
            mail_to = re.findall("[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}", msg["To"],
                                 re.IGNORECASE)

            if mail_to:
                # Remove possible duplicates and create a numbered dictionary
                mail_to = dict(zip(range(len(list(set(mail_to)))), list(set(mail_to))))
                resultmeioc["to"] = mail_to

        if msg["Bcc"]:
            resultmeioc["bcc"] = msg["Bcc"]

        if msg["Cc"]:
            mail_ccList = []
            for mail in msg["Cc"].split(","):
                mail_cc = real_email(mail)

                if mail_cc:
                    mail_ccList.append(mail_cc)

            if mail_ccList:
                # Remove possible duplicates and create a numbered dictionary
                mail_ccList = dict(zip(range(len(list(set(mail_ccList)))), list(set(mail_ccList))))
                resultmeioc["cc"] = mail_ccList

        if msg["Envelope-to"]:

            mail_envelopeto = re.findall("[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}",
                                         msg["Envelope-to"],
                                         re.IGNORECASE)

            if mail_envelopeto:
                # Remove possible duplicates and create a numbered dictionary
                mail_envelopeto = dict(zip(range(len(list(set(mail_envelopeto)))), list(set(mail_envelopeto))))
                resultmeioc["envelope-to"] = mail_envelopeto

        if msg["Delivered-To"]:
            resultmeioc["delivered-to"] = msg["Delivered-To"]

        if msg["Return-Path"]:
            mail_returnpath = real_email(msg["Return-Path"])

            if mail_returnpath:
                resultmeioc["return-path"] = mail_returnpath

        if msg["User-Agent"]:
            resultmeioc["user-agent"] = msg["User-Agent"]

        if msg["X-Originating-IP"]:
            # Usually the IP is in square brackets, I remove them if present.
            mail_xorigip = msg["X-Originating-IP"].replace("[", "").replace("]", "")
            resultmeioc["x-originating-ip"] = mail_xorigip

        if msg["Subject"]:
            resultmeioc["subject"] = msg["Subject"]
        #
        # Identify each relay
        #
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
                            if ipaddress.ip_address(ipv6) and not "6::":
                                hopListIP.append(ipv6)

                                if not ipaddress.ip_address(ipv6).is_private:
                                    hopListIPnoPrivate.append(ipv6)

                    if hop[0]:
                        hopList.append(hop[0])

        if hopList:
            resultmeioc["relay_full"] = dict(zip(range(len(hopList)), hopList))

        if hopListIP:
            if exclude_private_ip:
                resultmeioc["relay_ip"] = dict(zip(range(len(hopListIPnoPrivate)), hopListIPnoPrivate))
            else:
                resultmeioc["relay_ip"] = dict(zip(range(len(hopListIP)), hopListIP))

        #
        # Body analysis
        #
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                # https://gist.github.com/dperini/729294
                urlList.extend(re.findall(
                    "(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+(?:[a-z\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?(?:[/?#]\S*)?",
                    part.get_content(), re.UNICODE | re.IGNORECASE | re.MULTILINE))

            if part.get_content_type() == "text/html":
                # The try/except is necessary, if the body of the eMail contains an incorrect or unencoded HTML code the script freeezes.
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
                        urlList.append(base + url.get("href"))
                except:
                    pass

            if part.get_filename():
                if part.get_payload(decode=True):
                    filename = part.get_filename()
                    filemd5 = hashlib.md5(part.get_payload(decode=True)).hexdigest()
                    filesha1 = hashlib.sha1(part.get_payload(decode=True)).hexdigest()
                    filesha256 = hashlib.sha256(part.get_payload(decode=True)).hexdigest()

                    attachmentsList.append({"filename": filename, "MD5": filemd5, "SHA1": filesha1,
                                            "SHA256": filesha256})

        # Identify each domain reported in the eMail body
        for url in urlList:
            analyzeddomain = tld_cache(url).registered_domain
            if analyzeddomain:
                domainList.append(analyzeddomain)

        # Remove Duplicate
        urlList = list(set(urlList))
        domainList = list(set(domainList))

        if urlList:
            resultmeioc["urls"] = dict(zip(range(len(urlList)), urlList))
            resultmeioc["domains"] = dict(zip(range(len(domainList)), domainList))

        if attachmentsList:
            resultmeioc["attachments"] = attachmentsList

        #
        # Verify the SPF record if requested
        #
        if check_spf:
            testspf = False
            resultspf = ""
            for ip in hopListIPnoPrivate:
                if not testspf and "mail_from" in locals():
                    try:
                        resultspf = spf.check2(ip, mail_from, mail_from.split("@")[1])[0]
                    except:
                        pass

                    if resultspf == "pass":
                        testspf = True
                    else:
                        testspf = False

            resultmeioc["spf"] = testspf

        if file_output:
            with open(file_output, "w") as f:
                json.dump(resultmeioc, f, indent=4)
            print("[!] Output saved in: %s" % file_output)
        else:
            if run_as_module:
                return resultmeioc
            else:
                print(json.dumps(resultmeioc, indent=4))


# Function to be used as a wrapper of email_analysis if meioc is used as a module
def analyze(filename, exclude_private_ip=False, spf=False, file_output=None):
    return email_analysis(True, filename, exclude_private_ip, spf, file_output)


def main():
    version = "1.3"
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="Analyze an eMail (.eml format)")
    parser.add_argument("-x", "--exclude-private-ip", action="store_true", dest="excprip",
                        help="Exclude private IPs from the report")
    parser.add_argument("-s", "--spf", action="store_true", dest="spf",
                        help="Check SPF Records")
    parser.add_argument("-o", "--output", dest="file_output",
                        help="Write output to <file>")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s " + version)

    arguments = parser.parse_args()

    if arguments.filename:
        email_analysis(False, arguments.filename, arguments.excprip, arguments.spf, arguments.file_output)


if __name__ == "__main__":
    main()
