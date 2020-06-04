### vul_console_1

#### Description

The `console` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `console` process due to NULL pointer reference.

Against stable `6.46.3`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x776d8cd9 <_ZN6stringC2ERKS_+21>:   mov    eax,DWORD PTR [eax]
   0x776d8cdb <_ZN6stringC2ERKS_+23>:   mov    edx,DWORD PTR [eax]
   0x776d8cdd <_ZN6stringC2ERKS_+25>:   add    edx,eax
   0x776d8cdf <_ZN6stringC2ERKS_+27>:   add    edx,0x4
0x776d8cd9 in string::string(string const&) () from target:/lib/libuc++.so
(gdb) i r
eax            0x0      0
ecx            0x0      0
edx            0x80c2ef0        135016176
ebx            0x776e14ec       2003703020
esp            0x7f8e59ec       0x7f8e59ec
ebp            0x7f8e59f8       0x7f8e59f8
esi            0x80d87a4        135104420
edi            0x7f8e5a58       2140035672
eip            0x776d8cd9       0x776d8cd9 <string::string(string const&)+21>
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 180       target:/nova/bin/console
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.05.16-20:52:17.11@0: 
2020.05.16-20:52:17.11@0: 
2020.05.16-20:52:17.11@0: /nova/bin/console
2020.05.16-20:52:17.11@0: --- signal=11 --------------------------------------------
2020.05.16-20:52:17.11@0: 
2020.05.16-20:52:17.11@0: eip=0x776d8cd9 eflags=0x00010202
2020.05.16-20:52:17.11@0: edi=0x7f8e5a58 esi=0x080d87a4 ebp=0x7f8e59f8 esp=0x7f8e59ec
2020.05.16-20:52:17.11@0: eax=0x00000000 ebx=0x776e14ec ecx=0x00000000 edx=0x080c2ef0
2020.05.16-20:52:17.11@0: 
2020.05.16-20:52:17.11@0: maps:
2020.05.16-20:52:17.11@0: 08048000-080bd000 r-xp 00000000 00:0c 1036       /nova/bin/console
2020.05.16-20:52:17.11@0: 7767e000-776b3000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.05.16-20:52:17.11@0: 776b7000-776d1000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.05.16-20:52:17.11@0: 776d2000-776e1000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.05.16-20:52:17.11@0: 776e2000-776e8000 r-xp 00000000 00:0c 949        /lib/libufiber.so
2020.05.16-20:52:17.11@0: 776e9000-77735000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.05.16-20:52:17.11@0: 7773b000-77742000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.05.16-20:52:17.11@0: 
2020.05.16-20:52:17.11@0: stack: 0x7f8e6000 - 0x7f8e59ec 
2020.05.16-20:52:17.11@0: c4 41 0c 08 01 00 00 00 c4 41 0c 08 28 5a 8e 7f f2 74 05 08 50 5a 8e 7f 00 00 00 00 01 00 00 00 
2020.05.16-20:52:17.11@0: 04 00 00 00 c4 41 0c 08 02 00 ff 88 58 5a 8e 7f 50 5a 8e 7f a4 87 0d 08 58 5a 8e 7f 78 5a 8e 7f 
2020.05.16-20:52:17.11@0: 
2020.05.16-20:52:17.11@0: code: 0x776d8cd9
2020.05.16-20:52:17.11@0: 8b 00 8b 10 01 c2 83 c2 04 52 83 c0 04 50 ff 75
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.5`. It seems that the latest stable version `6.46.5` still suffers from this vulnerability.

#### Timeline

+ 2019/08/26 - report the vulnerability to the vendor
+ 2020/04/14 - still no fix yet



