import dns.resolver
import dns.dnssec
import dns.name


def analyze_dnssec(domain):
    print(f"Domain: {domain}")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]

    # Enable DNSSEC
    resolver.use_edns(0, dns.flags.DO, 1232)

    zone = dns.name.from_text(domain)

    try:
        # -------------------------
        # Get DNSKEY
        # -------------------------
        dnskey_ans = resolver.resolve(domain, "DNSKEY")
        dnskeys = dnskey_ans.rrset

        # -------------------------
        # Get RRSIG
        # -------------------------
        rrsigs = None
        for rr in dnskey_ans.response.answer:
            if rr.rdtype == dns.rdatatype.RRSIG:
                rrsigs = rr

        # -------------------------
        # Get DS from parent
        # -------------------------
        parent = ".".join(domain.split(".")[1:])  # e.g. com
        ds_ans = resolver.resolve(domain, "DS", raise_on_no_answer=False)
        ds_records = ds_ans.rrset

    except Exception as e:
        print("Error retrieving DNSSEC data:", e)
        return

    # -------------------------
    # Analyze Keys
    # -------------------------
    ksk = []
    zsk = []

    for key in dnskeys:
        if key.flags == 257:
            ksk.append(key)
        elif key.flags == 256:
            zsk.append(key)

    print("\nObservations:")

    print(f"- Total DNSKEYs: {len(dnskeys)}")
    print(f"- KSK count: {len(ksk)}")
    print(f"- ZSK count: {len(zsk)}")

    # -------------------------
    # Detect rollover
    # -------------------------
    if len(ksk) > 1:
        print("- Multiple KSK detected → Possible rollover")

    if len(zsk) > 1:
        print("- Multiple ZSK detected → Possible rollover")

    # -------------------------
    # DS Matching Check
    # -------------------------
    if ds_records:
        match_count = 0

        for ds in ds_records:
            for key in ksk:
                try:
                    generated_ds = dns.dnssec.make_ds(zone, key, ds.digest_type)
                    if generated_ds == ds:
                        match_count += 1
                except Exception:
                    continue

        if match_count == 0:
            print("- DS mismatch detected ❌")
        elif match_count < len(ksk):
            print("- DS matches only some KSK → Rollover in progress ⚠️")
        else:
            print("- DS matches all KSK → Stable state ")

    else:
        print("- No DS record found (Insecure delegation)")

    # -------------------------
    # Final Status
    # -------------------------
    print("\nStatus:")

    if len(ksk) > 1 and match_count < len(ksk):
        print("KSK Rollover in Progress")
    elif len(ksk) > 1:
        print("KSK Rollover (Completed or Safe State)")
    else:
        print("Normal Operation")


# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    analyze_dnssec("example.com")
    analyze_dnssec("cloudflare.com")
