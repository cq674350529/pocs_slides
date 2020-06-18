### vul_dot1x

#### Description

The `dot1x` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `dot1x` process due to NULL pointer reference.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x776a51e5 <_ZN6string6assignERKS_+23>:      mov    edx,DWORD PTR [eax]
   0x776a51e7 <_ZN6string6assignERKS_+25>:      add    edx,eax
   0x776a51e9 <_ZN6string6assignERKS_+27>:      add    edx,0x4
   0x776a51ec <_ZN6string6assignERKS_+30>:      push   edx
0x776a51e5 in string::assign(string const&) () from target:/lib/libuc++.so
(gdb) i r
eax            0x0      0
ecx            0x0      0
edx            0x8062e28        134622760
ebx            0x776ad4ec       2003490028
esp            0x7fc50f6c       0x7fc50f6c
ebp            0x7fc50f78       0x7fc50f78
esi            0x8062ed0        134622928
edi            0x7fc51064       2143621220
eip            0x776a51e5       0x776a51e5 <string::assign(string const&)+23>
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 197       target:/nova/bin/dot1x
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-14:51:29.47@0: 
2020.06.04-14:51:29.47@0: 
2020.06.04-14:51:29.81@0: /nova/bin/dot1x
2020.06.04-14:51:29.81@0: --- signal=11 --------------------------------------------
2020.06.04-14:51:29.81@0: 
2020.06.04-14:51:29.81@0: eip=0x776a51e5 eflags=0x00010202
2020.06.04-14:51:29.81@0: edi=0x7fc51064 esi=0x08062ed0 ebp=0x7fc50f78 esp=0x7fc50f6c
2020.06.04-14:51:29.81@0: eax=0x00000000 ebx=0x776ad4ec ecx=0x00000000 edx=0x08062e28
2020.06.04-14:51:29.81@0: 
2020.06.04-14:51:29.81@0: maps:
2020.06.04-14:51:29.81@0: 08048000-0805f000 r-xp 00000000 00:0c 1064       /nova/bin/dot1x
2020.06.04-14:51:29.81@0: 7764a000-7767f000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-14:51:29.81@0: 77683000-7769d000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-14:51:29.81@0: 7769e000-776ad000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-14:51:29.81@0: 776ae000-776b4000 r-xp 00000000 00:0c 951        /lib/liburadius.so
2020.06.04-14:51:29.81@0: 776b5000-776bd000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-14:51:29.81@0: 776be000-776db000 r-xp 00000000 00:0c 947        /lib/libucrypto.so
2020.06.04-14:51:29.81@0: 776dc000-77728000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-14:51:29.81@0: 7772e000-77735000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-14:51:29.81@0: 
2020.06.04-14:51:29.81@0: stack: 0x7fc52000 - 0x7fc50f6c 
2020.06.04-14:51:29.81@0: 00 00 00 00 90 27 06 08 e4 8a 72 77 a8 0f c5 7f 2e be 6f 77 90 27 06 08 d0 2e 06 08 28 2e 06 08 
2020.06.04-14:51:29.81@0: 28 2e 06 08 a4 0f c5 7f f0 da 6b 77 05 00 00 00 f0 da 6b 77 e0 2d 06 08 64 10 c5 7f e8 0f c5 7f 
2020.06.04-14:51:29.81@0: 
2020.06.04-14:51:29.81@0: code: 0x776a51e5
2020.06.04-14:51:29.81@0: 8b 10 01 c2 83 c2 04 52 83 c0 04 50 ff 75 08 e8 
```

#### Affected Version

This vulnerability was initially found in stable  `6.46.3`, and was fixed in stable `6.47`.

#### Timeline

+ 2020/04/20 - report the vulnerability to the vendor
+ 2020/06/02 - vendor fix it in stable `6.47`

