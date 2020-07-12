# Written by Michael Pavle
# DNSEnum - DNS enumeration tool designed for pentesting reconnaissance
import dns.resolver
import dns.query
import dns.zone
import argparse
import re
import sys

# TODO:
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
        #self.verify()
        
        self.scanned_subs = []
        
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
    
    def enum(self):
        # Remove duplicate items from records list
        self.records = list(dict.fromkeys(self.records))
        for sub in self.subdomains:
            results = {"Hostname": "{}.{}".format(sub, self.domain)} # Used to collect all records for subdomain
            for rcd in self.records:
                print("[*] Querying {}.{} for {} records".format(sub, self.domain, rcd))
                # Make the query and initialize the record list
                try:
                    answer = dns.resolver.query("{}.{}".format(sub, self.domain), rcd)
                except dns.resolver.NXDOMAIN:
                    print("\t[-] ERROR: Recieved NXDOMAIN")
                except dns.resolver.NoAnswer:
                    print("\t[-] ERROR: Recieved NoAnswer")
                except dns.resolver.Timeout:
                    print("\t[-] ERROR: Recieved Timeout")
                else:
                    record_list = []
                    # Take the answer from the query and add the addresses to the record list
                    # https://www.programcreek.com/python/example/97695/dns.resolver.NXDOMAIN - referenced for the next couple lines
                    for item in answer:
                        print("\t[+] Found {} record: {}".format(rcd, item.to_text()))
                        record_list.append(item.to_text())
                    # Add records to results list for subdomain
                    results[rcd] = record_list
            # Append all record query results to the scanned_subs list
            self.scanned_subs.append(results)
                
    def print_results(self):
        print("[+] Printing scanned subdomain results:")
        for res in self.scanned_subs:
            print(res)
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS enumeration tool designed for pentesting reconnaissance",
        #usage="%(prog)s [options] domain",
        add_help=False)
    
    # Little control with argparse; optget may be better
    parser.add_argument("-h", "--help", action="help", help="Display this helpful bit and exit")
    
    parser.add_argument("-w", "--wordlist", required=True, dest="wordlist", help="Specify wordlist file")
    parser.add_argument("--records", required=True, dest="records", help="Query for DNS records; Options are NS, A, and CNAME", choices=["NS", "A", "CNAME"], nargs="+")
    
    parser.add_argument("-z", "--zone-transfer", dest="transfer", action="store_true", help="Attempt a zone transfer on domain (Note: this may be illegal depending on your area, make sure you are authorized to perform a zone transfer on your target assets)")
    parser.add_argument("-o", "--output", dest="output", help="Specify output file")
    parser.add_argument("--json", dest="json", action="store_true", help="Output results in JSON format")
    parser.add_argument("domain", help="Hostname to run enumeration on")
    args = parser.parse_args()
    
# Create SubEnum object, grab subs and verify domain
e = SubEnum()
e.verify()
# Enumerate and print results
e.enum()
e.print_results()