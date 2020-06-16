### vul_igmpproxy

#### Description

The `igmpproxy` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `igmpproxy` process due to invalid memory access.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x8050a8d:   mov    eax,DWORD PTR [ebx]
   0x8050a8f:   push   DWORD PTR [eax]
   0x8050a91:   push   0x1
   0x8050a93:   push   esi
0x08050a8d in ?? ()
(gdb) i r
eax            0x80581bc        134578620
ecx            0xb      11
edx            0x0      0
ebx            0x0      0
esp            0x7fa9326c       0x7fa9326c
ebp            0x7fa932a8       0x7fa932a8
esi            0x7fa932b8       2141795000
edi            0x7fa9331c       2141795100
eip            0x8050a8d        0x8050a8d
eflags         0x10206  [ PF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 237       target:/ram/pckg/multicast/nova/bin/igmpproxy
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-17:44:27.12@0: 
2020.06.04-17:44:27.12@0: 
2020.06.04-17:44:27.12@0: /ram/pckg/multicast/nova/bin/igmpproxy
2020.06.04-17:44:27.12@0: --- signal=11 --------------------------------------------
2020.06.04-17:44:27.12@0: 
2020.06.04-17:44:27.12@0: eip=0x08050a8d eflags=0x00010206
2020.06.04-17:44:27.12@0: edi=0x7fa9331c esi=0x7fa932b8 ebp=0x7fa932a8 esp=0x7fa9326c
2020.06.04-17:44:27.12@0: eax=0x080581bc ebx=0x00000000 ecx=0x0000000b edx=0x00000000
2020.06.04-17:44:27.12@0: 
2020.06.04-17:44:27.12@0: maps:
2020.06.04-17:44:27.12@0: 08048000-08053000 r-xp 00000000 00:13 16         /ram/pckg/multicast/nova/bin/igmpproxy
2020.06.04-17:44:27.12@0: 7770b000-77740000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-17:44:27.12@0: 77744000-7775e000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-17:44:27.12@0: 7775f000-7776e000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-17:44:27.12@0: 7776f000-77777000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-17:44:27.12@0: 77778000-777c4000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-17:44:27.12@0: 777ca000-777d1000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-17:44:27.12@0: 
2020.06.04-17:44:27.12@0: stack: 0x7fa94000 - 0x7fa9326c 
2020.06.04-17:44:27.12@0: 01 00 00 00 e8 7f 05 08 10 00 00 00 98 32 a9 7f 11 00 00 00 78 57 05 08 14 33 a9 7f a8 32 a9 7f 
2020.06.04-17:44:27.12@0: 67 29 79 77 04 5d 05 08 6c 25 79 77 d8 32 a9 7f e0 57 05 08 b8 32 a9 7f 1c 33 a9 7f d8 32 a9 7f 
2020.06.04-17:44:27.12@0: 
2020.06.04-17:44:27.12@0: code: 0x8050a8d
2020.06.04-17:44:27.12@0: 8b 03 ff 30 6a 01 56 e8 77 a8 ff ff 83 c4 0c 0f 
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `6.47`.

#### Timeline

+ 2020/01/06 - report the vulnerability to the vendor
+ 2020/06/02 - vendor fix it in stable `6.47`