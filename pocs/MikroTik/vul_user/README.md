### vul_user

#### Description

The `user` process suffers from an assertion failure vulnerability. There is a reachable assertion in the `user` process. By sending a crafted packet, an authenticated remote user can crash the `user` process due to assertion failure.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGABRT, Aborted.
=> 0x7765a55b <raise+83>:       pop    ebx
   0x7765a55c <raise+84>:       cmp    eax,0xfffff000
   0x7765a561 <raise+89>:       jbe    0x7765a571 <raise+105>
   0x7765a563 <raise+91>:       mov    edx,DWORD PTR [ebx-0x34]
0x7765a55b in raise () from target:/lib/libc.so.0
(gdb) i r
eax            0x0      0
ecx            0xb4     180
edx            0x6      6
ebx            0xb4     180
esp            0x7fee3788       0x7fee3788
ebp            0x7fee3790       0x7fee3790
esi            0x77662200       2003182080
edi            0xfe0001 16646145
eip            0x7765a55b       0x7765a55b <raise+83>
eflags         0x246    [ PF ZF IF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 180       target:/nova/bin/user
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-17:56:52.31@0: 
2020.06.04-17:56:52.31@0: 
2020.06.04-17:56:52.31@0: /nova/bin/user
2020.06.04-17:56:52.31@0: --- signal=6 --------------------------------------------
2020.06.04-17:56:52.31@0: 
2020.06.04-17:56:52.31@0: eip=0x7765a55b eflags=0x00000246
2020.06.04-17:56:52.31@0: edi=0x00fe0001 esi=0x77662200 ebp=0x7fee3790 esp=0x7fee3788
2020.06.04-17:56:52.31@0: eax=0x00000000 ebx=0x000000b4 ecx=0x000000b4 edx=0x00000006
2020.06.04-17:56:52.31@0: 
2020.06.04-17:56:52.31@0: maps:
2020.06.04-17:56:52.31@0: 08048000-08059000 r-xp 00000000 00:0c 1002       /nova/bin/user
2020.06.04-17:56:52.31@0: 7762c000-77661000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-17:56:52.31@0: 77665000-7767f000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-17:56:52.31@0: 77680000-7768f000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-17:56:52.31@0: 77690000-776ad000 r-xp 00000000 00:0c 947        /lib/libucrypto.so
2020.06.04-17:56:52.31@0: 776ae000-776b4000 r-xp 00000000 00:0c 951        /lib/liburadius.so
2020.06.04-17:56:52.31@0: 776b5000-776bd000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-17:56:52.31@0: 776be000-776c1000 r-xp 00000000 00:0c 948        /lib/libuxml++.so
2020.06.04-17:56:52.31@0: 776c2000-7770e000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-17:56:52.31@0: 77714000-7771b000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-17:56:52.31@0: 
2020.06.04-17:56:52.31@0: stack: 0x7fee4000 - 0x7fee3788 
2020.06.04-17:56:52.31@0: 00 20 66 77 00 20 66 77 c8 37 ee 7f 77 60 65 77 06 00 00 00 00 22 66 77 20 00 00 00 00 00 00 00 
2020.06.04-17:56:52.31@0: 15 00 00 00 28 38 ee 7f c4 37 ee 7f e4 ea 70 77 01 00 00 00 e4 ea 70 77 15 00 00 00 01 00 fe 00 
2020.06.04-17:56:52.31@0: 
2020.06.04-17:56:52.31@0: code: 0x7765a55b
2020.06.04-17:56:52.31@0: 5b 3d 00 f0 ff ff 76 0e 8b 93 cc ff ff ff f7 d8
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `6.47`.

#### Timeline

+ 2020/02/15 - report the vulnerability to the vendor
+ 2020/06/02 - vendor fix it in stable `6.47`