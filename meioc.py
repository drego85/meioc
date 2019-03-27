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
import sys
import json
import argparse
import ipaddress
import tldextract
from email import policy
from email.parser import BytesParser

tldcache = tldextract.TLDExtract(cache_file="./.tld_set")


def email_analysis(filename, exclude_private_ip):
    urlList = []
    domainList = []
    hopList = []
    hopListIP = []
    attachList = []
    data = {}
    data["data"] = []

    with open(filename, "rb") as fp:
        msg = BytesParser(policy=policy.default).parse(fp)

    if msg:
        # Identify each url or attachment reported in the eMail body
        for part in msg.walk():
            if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html":

                # https://gist.github.com/dperini/729294
                urlList.extend(re.findall(
                    "(?:(?:(?:https?|ftp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+(?:[a-z\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?(?:[/?#]\S*)?",
                    part.get_content(), re.UNICODE | re.IGNORECASE | re.MULTILINE))
            else:
                if part.get_filename():
                    attachList.append(part.get_filename())

        # Identify each domain reported in the eMail body
        for url in urlList:
            analyzeddomain = tldcache(url).registered_domain
            if analyzeddomain:
                domainList.append(analyzeddomain)

        # Remove Duplicate
        urlList = list(set(urlList))
        domainList = list(set(domainList))

        # A sender obfuscation technique involves entering two e-mails. Only the last one is the real one. Example:
        #
        # Sender Name: Mario Rossi <rossi.mario@example.com>
        # Sender Mail: spoof@example.com

        if msg["From"]:
            mail_from = re.findall("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", msg["From"])
            if mail_from:
                mail_from = mail_from[-1]
        else:
            mail_from = ""

        if msg["Sender"]:
            mail_sender = msg["Sender"]
        else:
            mail_sender = ""

        if msg["Subject"]:
            mail_subject = msg["Subject"]
        else:
            mail_subject = ""

        if msg["X-Originating-IP"]:
            mail_xorigip = msg["X-Originating-IP"]
        else:
            mail_xorigip = ""

        data["data"].append({
            "Filename": os.path.basename(filename),
            "From": mail_from,
            "Sender": mail_sender,
            "Subject": mail_subject,
            "X-Originating-IP": mail_xorigip,
            "attachments": [],
            "relay_full": [],
            "relay_ip": [],
            "urls": [],
            "domains": []
        })

        # Identify each relay
        received = msg.get_all("Received")
        if received:
            received.reverse()
            for line in received:
                hops = re.findall("from\s+(.*?)\s+by(.*?)(?:(?:with|via)(.*?)(?:id|$)|id|$)", line, re.DOTALL | re.X)
                for hop in hops:

                    ipv4_address = re.findall(r"(?:^|\b(?<!\.))(?:1?\d?\d|2[0-4]\d|25[0-5])(?:\.(?:1?\d?\d|2[0-4]\d|25[0-5])){3}(?=$|[^\w.])", hop[0], re.DOTALL | re.X)

                    # https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8
                    ipv6_address = re.findall(
                        r"\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*",
                        hop[0], re.DOTALL | re.X)

                    if ipv4_address:
                        if ipaddress.ip_address(ipv4_address[0]):
                            if ipaddress.ip_address(ipv4_address[0]).is_private:
                                if not exclude_private_ip:
                                    hopListIP.append(ipv4_address[0])
                            else:
                                hopListIP.append(ipv4_address[0])

                    if ipv6_address:
                        if ipaddress.ip_address(ipv6_address[0]):
                            if ipaddress.ip_address(ipv6_address[0]).is_private:
                                if not exclude_private_ip:
                                    hopListIP.append(ipv6_address[0])
                            else:
                                hopListIP.append(ipv6_address[0])

                    if hop[0]:
                        hopList.append(hop[0])

        if attachList:
            data["data"][0]["attachments"].append(dict(zip(range(len(attachList)), attachList)))

        if hopList:
            data["data"][0]["relay_full"].append(dict(zip(range(len(hopList)), hopList)))

        if hopListIP:
            data["data"][0]["relay_ip"].append(dict(zip(range(len(hopListIP)), hopListIP)))

        if urlList:
            data["data"][0]["urls"].append(dict(zip(range(len(urlList)), urlList)))
            data["data"][0]["domains"].append(dict(zip(range(len(domainList)), domainList)))

        print(json.dumps(data, indent=4))


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", action="store", dest="file", help="Analyze an eMail (.eml format)")
    # parser.add_argument("-d", "--directory", action="store", dest="directory",help="Analyze multiple eMails (.eml format) contained in a directory.")
    parser.add_argument("-x", "--exclude-private-ip", action="store_true", dest="excprip",
                        help="Exclude private IPs from the report")
    # parser.add_argument("-v", "--version", action="version", version="%(prog)s " + swversion)

    arguments = parser.parse_args()

    if arguments.file:
        email_analysis(arguments.file, arguments.excprip)


if __name__ == "__main__":
    main(sys.argv[1:])
