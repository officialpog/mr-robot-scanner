import dns.resolver
import dns.exception

def run_dns_scan(domain: str):
    results = {
        "a": [],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "cname": [],
        "soa": [],
        "error": None
    }

    record_types = {
        "a": dns.rdatatype.A,
        "aaaa": dns.rdatatype.AAAA,
        "mx": dns.rdatatype.MX,
        "ns": dns.rdatatype.NS,
        "txt": dns.rdatatype.TXT,
        "cname": dns.rdatatype.CNAME,
        "soa": dns.rdatatype.SOA,
    }

    for key, rdtype in record_types.items():
        try:
            answers = dns.resolver.resolve(domain, rdtype, lifetime=5)
            for rdata in answers:
                if key == "mx":
                    results[key].append(f"{rdata.preference} {rdata.exchange}")
                elif key == "txt":
                    results[key].append(str(rdata).strip('"'))
                elif key == "soa":
                    results[key].append(f"{rdata.mname} {rdata.rname}")
                else:
                    results[key].append(str(rdata))
        except dns.resolver.NXDOMAIN:
            results["error"] = "Domain does not exist"
            break
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.DNSException as e:
            results["error"] = str(e)
        except Exception as e:
            results["error"] = str(e)

    return results
