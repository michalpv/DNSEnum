# Written by Michael Pavle
# DNSEnum - DNS enumeration tool designed for pentesting reconnaissance
import dns.resolver
import dns.query
import argparse
import re
import sys

# TODO:
# Subdomain enumeration
# Zone transfer checking
# Writing output to file

class SubEnum:
    def __init__(self):
        self.subdomains = []
        self.domain = args.domain
        self.wordlist = args.wordlist
        self.output = args.output
        self.records = args.records
        # True/False:
        self.zt = args.transfer
        self.json = args.json
        self.to = args.takeover
        #self.verify()
        
    def verify(self):
        # Check that domain is in correct format; otherwise, produce error:
        # Thank https://stackoverflow.com/questions/8467647/python-domain-name-check-using-regex
        if re.search("^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$", self.domain) == None:
            print("[-] Domain is not valid... quitting")
            sys.exit(1)
        else:
            print("[+] Domain is valid")
        # Attempt reading wordlist
        try:
            with open(self.wordlist, "r") as f:
                self.subdomains = f.read().split()
        except FileNotFoundError:
            print("[-] Wordlist not found... quitting")
            sys.exit(1)
        print("[+] Found wordlist")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS enumeration tool designed for pentesting reconnaissance",
        #usage="%(prog)s [options]",
        add_help=False)
    
    # Little control with argparse; optget may be better
    parser.add_argument("-h", "--help", action="help", help="Display this helpful bit and exit")
    
    parser.add_argument("-w", "--wordlist", required=True, dest="wordlist", help="Specify wordlist file")
    parser.add_argument("--records", dest="records", help="Query for records", choices=["ns", "a", "cname"], nargs="+")
    
    parser.add_argument("-z", "--zone-transfer", dest="transfer", action="store_true", help="Attempt a zone transfer on domain (Note: this may be illegal depending on your area, make sure you are authorized to perform a zone transfer on your target assets)")
    parser.add_argument("-o", "--output", dest="output", help="Specify output file")
    parser.add_argument("--json", dest="json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--takeover", dest="takeover", action="store_true", help="Check if subdomain takeover is possible on subdomains")
    parser.add_argument("domain", help="Hostname to run enumeration on")
    args = parser.parse_args()
    
# Create SubEnum object, grab subs and verify domain
e = SubEnum()
e.verify()