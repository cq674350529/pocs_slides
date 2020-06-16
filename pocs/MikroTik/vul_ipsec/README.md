### vul_ipsec

#### Description

The `ipsec` process suffers from an assertion failure vulnerability. There is a reachable assertion in the `ipsec` process. By sending a crafted packet, an authenticated remote user can crash the `ipsec` process due to assertion failure.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGABRT, Aborted.
=> 0x7748155b <raise+83>:       pop    ebx
   0x7748155c <raise+84>:       cmp    eax,0xfffff000
   0x77481561 <raise+89>:       jbe    0x77481571 <raise+105>
   0x77481563 <raise+91>:       mov    edx,DWORD PTR [ebx-0x34]
0x7748155b in raise () from target:/lib/libc.so.0
(gdb) i r
eax            0x0      0
ecx            0x291    657
edx            0x6      6
ebx            0x291    657
esp            0x7f8fa448       0x7f8fa448
ebp            0x7f8fa450       0x7f8fa450
esi            0x77489200       2001244672
edi            0x1      1
eip            0x7748155b       0x7748155b <raise+83>
eflags         0x246    [ PF ZF IF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 657       target:/ram/pckg/security/nova/bin/ipsec
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-18:25:16.04@0: 
2020.06.04-18:25:16.04@0: 
2020.06.04-18:25:16.04@0: /ram/pckg/security/nova/bin/ipsec
2020.06.04-18:25:16.04@0: --- signal=6 --------------------------------------------
2020.06.04-18:25:16.04@0: 
2020.06.04-18:25:16.04@0: eip=0x7748155b eflags=0x00000246
2020.06.04-18:25:16.04@0: edi=0x00000001 esi=0x77489200 ebp=0x7f8fa450 esp=0x7f8fa448
2020.06.04-18:25:16.04@0: eax=0x00000000 ebx=0x00000291 ecx=0x00000291 edx=0x00000006
2020.06.04-18:25:16.04@0: 
2020.06.04-18:25:16.04@0: maps:
2020.06.04-18:25:16.04@0: 08048000-080b5000 r-xp 00000000 00:11 42         /ram/pckg/security/nova/bin/ipsec
2020.06.04-18:25:16.04@0: 77453000-77488000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-18:25:16.04@0: 7748c000-774a6000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-18:25:16.04@0: 774a7000-774b6000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-18:25:16.04@0: 774b7000-774b9000 r-xp 00000000 00:0c 959        /lib/libdl-0.9.33.2.so
2020.06.04-18:25:16.04@0: 774bb000-774d0000 r-xp 00000000 00:1f 15         /ram/pckg/dhcp/lib/libudhcp.so
2020.06.04-18:25:16.04@0: 774d2000-774d8000 r-xp 00000000 00:0c 951        /lib/liburadius.so
2020.06.04-18:25:16.04@0: 774d9000-77524000 r-xp 00000000 00:0c 956        /lib/libssl.so.1.0.0
2020.06.04-18:25:16.04@0: 77528000-77530000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-18:25:16.04@0: 77531000-7757d000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-18:25:16.04@0: 77580000-7759d000 r-xp 00000000 00:0c 947        /lib/libucrypto.so
2020.06.04-18:25:16.04@0: 7759e000-776fb000 r-xp 00000000 00:0c 954        /lib/libcrypto.so.1.0.0
2020.06.04-18:25:16.04@0: 7770e000-77715000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-18:25:16.04@0: 
2020.06.04-18:25:16.04@0: stack: 0x7f8fb000 - 0x7f8fa448 
2020.06.04-18:25:16.04@0: 00 90 48 77 00 90 48 77 88 a4 8f 7f 77 d0 47 77 06 00 00 00 00 92 48 77 20 00 00 00 00 00 00 00 
2020.06.04-18:25:16.04@0: cc a4 8f 7f e8 a4 8f 7f 84 a4 8f 7f e4 da 57 77 01 00 00 00 e4 da 57 77 cc a4 8f 7f 01 00 00 00 
2020.06.04-18:25:16.04@0: 
2020.06.04-18:25:16.04@0: code: 0x7748155b
2020.06.04-18:25:16.04@0: 5b 3d 00 f0 ff ff 76 0e 8b 93 cc ff ff ff f7 d8
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `6.47`.

#### Timeline

+ 2020/01/06 - report the vulnerability to the vendor
+ 2020/06/02 - vendor fix it in stable `6.47`
