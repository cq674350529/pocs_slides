### vul_hotspot_2

#### Description

The `hotspot` process suffers from an assertion failure vulnerability. There is a reachable assertion in the `hotspot` process. By sending a crafted packet, an authenticated remote user can crash the `hotspot` process due to assertion failure.

> The authentication here means that the user should be authenticated to the device itself (e.g. web, winbox).

Against stable `6.46.5`, the poc resulted in the following crash dump.

```shell
---- current v6.46.5 Apr/07/2020 08:28:27 ----
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: /ram/pckg/hotspot/nova/bin/hotspot
2022.10.31-15:15:36.78@0: --- signal=6 --------------------------------------------
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: eip=0x7767e55b eflags=0x00000246
2022.10.31-15:15:36.78@0: edi=0x00000fe1 esi=0x77686200 ebp=0x7fdf7120 esp=0x7fdf7118
2022.10.31-15:15:36.78@0: eax=0x00000000 ebx=0x000000b8 ecx=0x000000b8 edx=0x00000006
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: maps:
2022.10.31-15:15:36.78@0: 08048000-08078000 r-xp 00000000 00:12 34         /ram/pckg/hotspot/nova/bin/hotspot
2022.10.31-15:15:36.78@0: 77650000-77685000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2022.10.31-15:15:36.78@0: 77689000-776a3000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2022.10.31-15:15:36.78@0: 776a4000-776b3000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2022.10.31-15:15:36.78@0: 776b4000-776d1000 r-xp 00000000 00:0c 947        /lib/libucrypto.so
2022.10.31-15:15:36.78@0: 776d2000-776d8000 r-xp 00000000 00:0c 951        /lib/liburadius.so
2022.10.31-15:15:36.78@0: 776d9000-77725000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2022.10.31-15:15:36.78@0: 77728000-77730000 r-xp 00000000 00:0c 950        /lib/libubox.so
2022.10.31-15:15:36.78@0: 77734000-7773b000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: stack: 0x7fdf8000 - 0x7fdf7118 
2022.10.31-15:15:36.78@0: 00 60 68 77 00 60 68 77 58 71 df 7f 77 a0 67 77 06 00 00 00 00 62 68 77 20 00 00 00 00 00 00 00 
2022.10.31-15:15:36.78@0: 15 00 00 00 b8 71 df 7f 54 71 df 7f e4 5a 72 77 01 00 00 00 e4 5a 72 77 15 00 00 00 e1 0f 00 00 
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: code: 0x7767e55b
2022.10.31-15:15:36.78@0: 5b 3d 00 f0 ff ff 76 0e 8b 93 cc ff ff ff f7 d8 
2022.10.31-15:15:36.78@0: 
2022.10.31-15:15:36.78@0: backtrace: 0x7767e55b 0x7767a077 0x77704ad3 0x7772c9a5 0x77700fb5 0x776fda8a 0x7770004e 0x776ffe82 0x776fb81b 0x776fb265 0x776fb37f 0x77701ffb 0x0804f7ed 0x7767efcb 0x08050b01
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `7.5`.

#### Timeline

+ 2022/07/29 - reported the vulnerability to the vendor
+ 2022/08/16 - vendor confirmed the vulnerability and would fix it in future releases
+ 2022/08/26 - vendor confirmed that the vulnerability was fixed
+ 2022/08/31 - stable 7.5 was released and this vulnerability was fixed
