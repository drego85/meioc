# Meioc

Meioc (Mail Extractor IoC) is a python3 script to extract indicators of compromised from eMail.

Meioc allows you to extract the following information from an e-mail, in JSON format:

* Header Field: From
* Header Field: Sender
* Header Field: Subject
* Header Field: X-Originating-IP
* Relay Full
* Relay IP (Only the IPs involved with the possibility of excluding private IPs)
* Urls
* Domains

The software is currently distributed in beta version, every collaboration is welcome.

### To Do List

- [ ] Scan multiple eMail (directory input)
- [ ] Whitelist

### Requirements
```
pip3 install -r requirementes.txt
```

### Example
```
$ python3 meioc.py --exclude-private-ip -f email.eml 
```
output:
```json
{
    "data": [
        {
            "Filename": "phishing1.eml",
            "From": "info@example.com",
            "Sender": "",
            "Subject": "Phishing Mail",
            "X-Originating-IP": "",
            "relay_full": [
                {
                    "0": "localhost.localdomain (unknown [AAA.BBB.CCC.DDD])",
                    "1": "v6791.vps.example.ru (unknown [127.0.0.1])",
                    "2": "v6791.vps.example.ru ([QQQ.WWW.EEE.RRR])",
                    "3": "mail.it ([10.103.10.23])",
                    "4": "dcp-11.mail.local ([10.103.10.23])",
                    "5": "dcd-16 ([10.103.10.23])"
                }
            ],
            "relay_ip": [
                {
                    "0": "AA.BBB.CCC.DDD",
                    "1": "QQQ.WWW.EEE.RRR"
                }
            ],
            "url": [
                {
                    "0": "https://www.example.com/en/private.html",
                    "1": "http://phishingsite.random.net"
                }
            ],
            "domain": [
                {
                    "0": "example.it",
                    "1": "random.net"
                }
            ]
        }
    ]
}
```

### License

GNU General Public License v3.0
