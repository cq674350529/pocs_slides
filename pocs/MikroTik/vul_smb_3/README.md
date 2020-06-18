### vul_smb_3

#### Description

The `smb` process suffers from a memory corruption vulnerability. By sending a crafted packet, an unauthenticated remote user can crash the `smb` process due to invalid memory access.

> In default, the `smb` service is disabled.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x806bffd:   mov    edx,DWORD PTR [eax]
   0x806bfff:   push   ebx
   0x806c000:   push   DWORD PTR [ebp-0x12c]
   0x806c006:   push   DWORD PTR [ebp-0x120]
0x0806bffd in ?? ()
(gdb) i r
eax            0x0      0
ecx            0x77727f00       2003992320
edx            0x1      1
ebx            0x7ffca9e0       2147264992
esp            0x7ffca960       0x7ffca960
ebp            0x7ffcaaa8       0x7ffcaaa8
esi            0x7ffca9f8       2147265016
edi            0x0      0
eip            0x806bffd        0x806bffd
eflags         0x10206  [ PF IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 181       target:/nova/bin/smb
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log
2020.06.18-19:33:09.94@0: 
2020.06.18-19:33:09.94@0: 
2020.06.18-19:33:09.94@0: /nova/bin/smb
2020.06.18-19:33:09.94@0: --- signal=11 --------------------------------------------
2020.06.18-19:33:09.94@0: 
2020.06.18-19:33:09.94@0: eip=0x0806bffd eflags=0x00010206
2020.06.18-19:33:09.94@0: edi=0x00000000 esi=0x7ffca9f8 ebp=0x7ffcaaa8 esp=0x7ffca960
2020.06.18-19:33:09.94@0: eax=0x00000000 ebx=0x7ffca9e0 ecx=0x77727f00 edx=0x00000001
2020.06.18-19:33:09.94@0: 
2020.06.18-19:33:09.94@0: maps:
2020.06.18-19:33:09.94@0: 08048000-08071000 r-xp 00000000 00:0c 1053       /nova/bin/smb
2020.06.18-19:33:09.94@0: 776f0000-77725000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.18-19:33:09.94@0: 77729000-77743000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.18-19:33:09.94@0: 77744000-77753000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.18-19:33:09.94@0: 77754000-77771000 r-xp 00000000 00:0c 947        /lib/libucrypto.so
2020.06.18-19:33:09.94@0: 77772000-777be000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.18-19:33:09.94@0: 777c1000-777c9000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.18-19:33:09.94@0: 777cd000-777d4000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.18-19:33:09.94@0: 
2020.06.18-19:33:09.94@0: stack: 0x7ffcb000 - 0x7ffca960 
2020.06.18-19:33:09.94@0: e0 a9 fc 7f 88 aa fc 7f 0e 73 07 08 a0 73 07 08 01 00 00 00 0e 73 07 08 91 00 00 00 00 00 00 00 
2020.06.18-19:33:09.94@0: 26 eb 71 77 00 60 72 77 00 00 00 00 21 ec 71 77 4e 54 4c 4d 53 53 50 00 d8 a9 fc 7f 4d 98 71 77 
2020.06.18-19:33:09.94@0: 
2020.06.18-19:33:09.94@0: code: 0x806bffd
2020.06.18-19:33:09.94@0: 8b 10 53 ff b5 d4 fe ff ff ff b5 e0 fe ff ff 50
```

#### Reproduce

```shell
$ python poc.py <ip> <port>
```
#### Affected Version

This vulnerability was initially found in stable `6.44.3`, and was fixed in stable `6.47`.

#### Timeline

+ 2020/05/12 - report the vulnerability to the vendor
+ 2020/05/13 - vendor confirms the vulnerability and says that it has been fixed in the latest beta (unreleased)
+ 2020/06/02 - vendor fix it in stable `6.47`