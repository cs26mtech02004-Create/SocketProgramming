import dns.query
import dns.message
import dns.resolver
import dns.name
import dns.flags
from Q1 import validate_dnssec

ROOT_NS = '198.41.0.4'  # a.root-servers.net


#  Helper: UDP → TCP fallback
def send_query(msg, ns):
    try:
        resp = dns.query.udp(msg, ns, timeout=5)

        # If truncated → switch to TCP
        if resp.flags & dns.flags.TC:
            raise Exception("Truncated")

        return resp

    except Exception:
        return dns.query.tcp(msg, ns, timeout=5)


#  Helper: Try all nameservers (failover)
def get_working_ns(ns_rrset, zone):
    for ns in ns_rrset:
        try:
            ns_target = ns.target
            ns_ip = dns.resolver.resolve(str(ns_target), 'A')[0].address

            # Test if NS responds
            test_msg = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
            send_query(test_msg, ns_ip)

            return ns_ip

        except Exception:
            continue

    return None


def recursive_resolver(target_domain):
    print(f"Query: \"{target_domain}\"")

    current_ns = ROOT_NS
    target_name = dns.name.from_text(target_domain)

    # Build path: . → com. → example.com.
    parts = target_domain.strip('.').split('.')
    zones = [dns.name.root] + [
        dns.name.from_text('.'.join(parts[i:]) + '.')
        for i in range(len(parts) - 1, -1, -1)
    ]

    parent_ds = None

    for i, zone in enumerate(zones):
        print(f"\nPath: {zone}")

        # =============================
        # 1. DNSKEY Query
        # =============================
        msg = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
        resp = send_query(msg, current_ns)

        keys = None
        sigs = None

        for section in [resp.answer, resp.authority]:
            try:
                keys = resp.find_rrset(section, zone,
                                       dns.rdataclass.IN, dns.rdatatype.DNSKEY)

                sigs = resp.find_rrset(section, zone,
                                       dns.rdataclass.IN,
                                       dns.rdatatype.RRSIG,
                                       dns.rdatatype.DNSKEY)

                if keys and sigs:
                    break

            except KeyError:
                continue

        if not keys or not sigs:
            print(f"DNSSEC: INSECURE (Missing DNSKEY at {zone})")
            return

        # =============================
        # 2. DNSSEC Validation
        # =============================
        is_valid, msg_status = validate_dnssec(
            zone,
            'DNSKEY',
            dnskey_rrset=keys,
            rrsig_rrset=sigs,
            parent_ds_rrset=parent_ds
        )

        if not is_valid:
            print(f"DNSSEC: INVALID ({msg_status})")
            return

        print("  DNSKEY retrieved")
        print("  RRSIG verified using ZSK/KSK")
        if parent_ds:
            print("  DS matched parent")

        # =============================
        # 3. Move to next zone
        # =============================
        if zone != target_name:
            next_zone = zones[i + 1]

            # ---- DS Query ----
            ds_msg = dns.message.make_query(next_zone, dns.rdatatype.DS, want_dnssec=True)
            ds_resp = send_query(ds_msg, current_ns)

            parent_ds = None
            for section in [ds_resp.answer, ds_resp.authority]:
                try:
                    parent_ds = ds_resp.find_rrset(section, next_zone,
                                                   dns.rdataclass.IN, dns.rdatatype.DS)
                    if parent_ds:
                        break
                except KeyError:
                    continue

            # ---- NS Query ----
            ns_msg = dns.message.make_query(next_zone, dns.rdatatype.NS)
            ns_resp = send_query(ns_msg, current_ns)

            ns_rrset = None
            for section in [ns_resp.answer, ns_resp.authority]:
                try:
                    ns_rrset = ns_resp.find_rrset(section, next_zone,
                                                 dns.rdataclass.IN, dns.rdatatype.NS)
                    if ns_rrset:
                        break
                except KeyError:
                    continue

            if not ns_rrset:
                print("Could not find next Nameserver.")
                return

            # ---- NS Failover ----
            next_ns = get_working_ns(ns_rrset, zone)

            if not next_ns:
                print("All nameservers failed (timeout).")
                return

            current_ns = next_ns

    # =============================
    # FINAL RESULT
    # =============================
    print("\nDNSSEC: VERIFIED")

    final_ip = dns.resolver.resolve(target_domain, 'A')[0].address
    print(f"IP: {final_ip}")


# =============================
# RUN
# =============================
if __name__ == "__main__":
    recursive_resolver("cloudflare.com")
