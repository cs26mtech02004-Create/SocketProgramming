import dns.resolver
import dns.dnssec
import dns.query
import dns.message

def validate_dnssec(domain_name, record_type, dnskey_rrset=None, rrsig_rrset=None, parent_ds_rrset=None):
    """
    Q1: Flexible validation module.
    Can be called with just domain/type (for Q1) or with RRsets (for Q2).
    """
    domain = dns.name.from_text(domain_name) if isinstance(domain_name, str) else domain_name
    
    try:
        # Step 1: If RRsets aren't provided (Q1 mode), fetch them
        if dnskey_rrset is None or rrsig_rrset is None:
            request = dns.message.make_query(domain, record_type, want_dnssec=True)
            response = dns.query.udp(request, "10.9.0.65", timeout=10)
            
            # Find the Answer and RRSIG in the response
            dnskey_res = dns.resolver.resolve(domain, 'DNSKEY')
            dnskey_rrset = dnskey_res.rrset
            
            answer_rrset = response.find_rrset(response.answer, domain, dns.rdataclass.IN, dns.rdatatype.from_text(record_type))
            rrsig_rrset = response.find_rrset(response.answer, domain, dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.from_text(record_type))
            
            if parent_ds_rrset is None:
                parent_ds_rrset = dns.resolver.resolve(domain, 'DS').rrset

        # Step 2: Perform Cryptographic Validation (The core Q1 Task)
        # Verify RRSIG using DNSKEY
        dns.dnssec.validate(answer_rrset if 'answer_rrset' in locals() else dnskey_rrset, rrsig_rrset, {domain: dnskey_rrset})
        print(f"  [OK] RRSIG verified for {domain}")

        # Verify DNSKEY using DS (Chain Step)
        if parent_ds_rrset:
            match = any(dns.dnssec.make_ds(domain, key, ds.digest_type) == ds 
                        for ds in parent_ds_rrset for key in dnskey_rrset)
            if not match:
                return False, "DS Mismatch"
            print(f"  [OK] DS matched parent for {domain}")
        
        return True, "VALID"

    except Exception as e:
        return False, str(e)

# Independent testing for Q1
if __name__ == "__main__":
    status, msg = validate_dnssec("example.edu", "A")
    print(f"DNSSEC Validation: {msg}")