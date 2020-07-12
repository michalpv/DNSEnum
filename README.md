# DNSEnum
A Subdomain Enumeration Script Designed for Pentesting Reconnaissance

The purpose of this script is to be able to collect A, CNAME, NS, and MX records to perform host discovery on a domain.
This program will require a wordlist to test subdomains in a line-by-line format; for example:
```
www
mail
remote
blog
webmail
server
...
```
In order to function, the ```dnspython``` package must be installed.
```
pip install dnspython
```
Once this prerequisite is met, the script can be run from the command line accordingly:

# Usage
```
usage: DNSEnum.py domain [options]

positional arguments:
  domain                Hostname to run enumeration on

optional arguments:
  -h, --help            Display this helpful bit and exit
  -w WORDLIST, --wordlist WORDLIST
                        Specify wordlist file
  --records {NS,A,CNAME,MX} [{NS,A,CNAME,MX} ...]
                        Query for DNS records; Options are NS, A, CNAME, and MX
  -z, --zone-transfer   Attempt a zone transfer on domain (Note: this may be illegal depending on your area, make sure
                        you are authorized to perform a zone transfer on your target assets)
  -o OUTPUT, --output OUTPUT
                        Specify output file
  --json                Output results in JSON format
```
The only required arguments are ```domain```, ```--records```, and ```--wordlist```, though I have added logging features and zone transfer capability which may be useful depending on the target surface.
## End note
This current version was built in around two days by one person. Instead of using this program to conduct host discovery, I would recommend using a tool such as OWASP's Amass which has far more capability.
Learning about DNS through this project was helpful; here are some interesting articles and resources I found beneficial and fun to read:

As it relates to the programming:
* https://www.dnspython.org/examples.html
* https://www.dnspython.org/docs/1.15.0/dns.query-module.html

As it relates to DNS:
* https://digi.ninja/projects/zonetransferme.php
* https://0xpatrik.com/subdomain-takeover-ns/

Other cool stuff:
* https://crt.sh/
* https://dnsdumpster.com/
