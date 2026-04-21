import dns.query
import dns.message
import dns.resolver
import dns.name
import dns.flags
import dns.rdatatype
import dns.dnssec

from Q1 import validate_dnssec


# -----------------------------
# UDP → TCP fallback
# -----------------------------
def query(msg, ns):
    try:
        resp = dns.query.udp(msg, ns, timeout=5)
        if resp.flags & dns.flags.TC:
            raise Exception("Truncated")
        return resp
    except:
        return dns.query.tcp(msg, ns, timeout=5)


# -----------------------------
# Get base zone (simple)
# -----------------------------
def get_zone(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


# -----------------------------
# Get DNSKEY + RRSIG (correct way)
# -----------------------------
def get_dnskey(zone_name):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]

    # Enable DNSSEC (DO flag)
    resolver.use_edns(0, dns.flags.DO, 1232)

    try:
        answer = resolver.resolve(zone_name, "DNSKEY", raise_on_no_answer=False)

        keys = answer.rrset
        sigs = None

        # Extract RRSIG from response
        for rrset in answer.response.answer:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                sigs = rrset

        return keys, sigs

    except Exception:
        return None, None


# -----------------------------
# Check NSEC / NSEC3 proof
# -----------------------------
def check_nsec(response, zone, dnskey_rrset):
    for rrset in response.authority:

        if rrset.rdtype in [dns.rdatatype.NSEC, dns.rdatatype.NSEC3]:
            try:
                rrsig = response.find_rrset(
                    response.authority,
                    rrset.name,
                    dns.rdataclass.IN,
                    dns.rdatatype.RRSIG,
                    rrset.rdtype
                )

                dns.dnssec.validate(rrset, rrsig, {zone: dnskey_rrset})

                return True, dns.rdatatype.to_text(rrset.rdtype)

            except Exception:
                return False, None

    return False, None


# -----------------------------
# MAIN FUNCTION
# -----------------------------
def resolve_with_nsec(domain, rtype):
    print(f"Query: {domain} {rtype}")

    zone_name = get_zone(domain)
    zone = dns.name.from_text(zone_name)

    # -----------------------------
    # Get DNSKEY
    # -----------------------------
    keys, sigs = get_dnskey(zone_name)

    if not keys or not sigs:
        print("DNSSEC: INSECURE (No DNSKEY/RRSIG)")
        return

    # Validate DNSKEY using Q1
    ok, msg_status = validate_dnssec(
        zone,
        "DNSKEY",
        dnskey_rrset=keys,
        rrsig_rrset=sigs
    )

    if not ok:
        print(f"DNSSEC: INVALID ({msg_status})")
        return

    # -----------------------------
    # Query record
    # -----------------------------
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]
    resolver.use_edns(0, dns.flags.DO, 1232)

    try:
        answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)

        # Case: record exists
        if answer.rrset:
            print("Result: EXISTS")
            return

    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        print("Result: ERROR")
        return

    # -----------------------------
    # Get response for NSEC proof
    # -----------------------------
    msg = dns.message.make_query(
        domain,
        dns.rdatatype.from_text(rtype),
        want_dnssec=True
    )

    resp = query(msg, "8.8.8.8")

    valid, proof_type = check_nsec(resp, zone, keys)

    if valid:
        print("Result: DOES NOT EXIST")
        print(f"Proof: VALID ({proof_type})")
    else:
        print("Result: DOES NOT EXIST")
        print("Proof: NOT VERIFIED")


# -----------------------------
# RUN TESTS
# -----------------------------
if __name__ == "__main__":
    resolve_with_nsec("mail.example.com", "TXT")   # NXDOMAIN
    resolve_with_nsec("example.com", "TXT")        # NODATA
    resolve_with_nsec("example.com", "A")          # EXISTS
