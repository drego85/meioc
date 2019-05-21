# Meioc

Meioc (Mail Extractor IoC) is a python3 script to extract indicators of compromised from eMail.

Meioc allows you to extract the following information from an e-mail, in JSON format:

* Header Field: From
* Header Field: Sender
* Header Field: X-Sender
* Header Field: Subject
* Header Field: X-Originating-IP
* Relay Full
* Relay IP (Only the IPs involved with the possibility of excluding private IPs)
* Urls
* Domains
* Attachments with hash
* Check SPF record


### To Do List

- [ ] Support .msg files

### Requirements
```
pip3 install -r requirementes.txt
```

### Example
```
$ python3 meioc.py --exclude-private-ip --spf email.eml 
```
output:
```json
{
    "filename": "malspam.eml",
    "from": "info@real-domain.com",
    "sender": "spoof@example.com",
    "x-sender": "spoof@example.com",
    "subject": "Malware Inside",
    "x-originating-ip": "",
    "spf": false,
    "attachments": {
        "filename": "malware.ace",
        "MD5": "7d5a710c7d65ae7f185097748a52cf4c",
        "SHA1": "608c493849a24ee415c6d17ba36169f52e04cf83",
        "SHA256": "d180e0ece6780268d8ffbb19a6ac153c09b7022bb2e79258d8e88676f850a7b6"
    },
    "relay_full": {
        "0": "[127.0.0.1] (port=47760 helo=server.example.net)",
        "1": "server.example.net (unknown [123.123.123.123])",
        "2": "emin10.example.it ([127.0.0.1])",
        "3": "localhost (localhost [127.0.0.1])",
        "4": "emin10.example.it (host.static.ip.example.it [254.254.0.0])",
        "5": "mta09.example.it ([127.0.0.1])",
        "6": "localhost (localhost [127.0.0.1])",
        "7": "mta09.example.it ([127.0.0.1])",
        "8": "localhost (localhost [127.0.0.1])",
        "9": "mta09.example.it (LHLO mta09.example.it) (111.222.111.000)"
    },
    "relay_ip": {
        "0": "123.123.123.123",
        "1": "254.254.0.0",
        "2": "111.222.111.000"
    },
    "urls": {
        "0": "http://phishingsite.example.net"
    },
    "domains": {
        "0": "example.net"
    }
}
```

### License

GNU General Public License v3.0
