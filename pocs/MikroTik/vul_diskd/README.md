### vul_diskd

#### Description

The `diskd` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `diskd` process due to invalid memory access.

Against stable `6.44.3`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x776cd1db <_ZN6string6assignERKS_+21>:      mov    eax,DWORD PTR [eax]
   0x776cd1dd <_ZN6string6assignERKS_+23>:      mov    edx,DWORD PTR [eax]
   0x776cd1df <_ZN6string6assignERKS_+25>:      add    edx,eax
   0x776cd1e1 <_ZN6string6assignERKS_+27>:      add    edx,0x4
0x776cd1db in string::assign(string const&) () from target:/lib/libuc++.so
(gdb) i r
eax            0x1b     27
ecx            0x776d54ec       2003653868
edx            0x20fe0010       553517072
ebx            0x776d54ec       2003653868
esp            0x7fd40b6c       0x7fd40b6c
ebp            0x7fd40b78       0x7fd40b78
esi            0x8056790        134571920
edi            0x8056760        134571872
eip            0x776cd1db       0x776cd1db <string::assign(string const&)+21>
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 264       target:/nova/bin/diskd
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-14:18:22.55@0: 
2020.06.04-14:18:22.55@0: 
2020.06.04-14:18:22.55@0: /nova/bin/diskd
2020.06.04-14:18:22.55@0: --- signal=11 --------------------------------------------
2020.06.04-14:18:22.55@0: 
2020.06.04-14:18:22.55@0: eip=0x776cd1db eflags=0x00010202
2020.06.04-14:18:22.55@0: edi=0x08056760 esi=0x08056790 ebp=0x7fd40b78 esp=0x7fd40b6c
2020.06.04-14:18:22.55@0: eax=0x0000001b ebx=0x776d54ec ecx=0x776d54ec edx=0x20fe0010
2020.06.04-14:18:22.55@0: 
2020.06.04-14:18:22.55@0: maps:
2020.06.04-14:18:22.55@0: 08048000-08052000 r-xp 00000000 00:0c 1131       /nova/bin/diskd
2020.06.04-14:18:22.55@0: 77672000-776a7000 r-xp 00000000 00:0c 996        /lib/libuClibc-0.9.33.2.so
2020.06.04-14:18:22.55@0: 776ab000-776c5000 r-xp 00000000 00:0c 992        /lib/libgcc_s.so.1
2020.06.04-14:18:22.55@0: 776c6000-776d5000 r-xp 00000000 00:0c 976        /lib/libuc++.so
2020.06.04-14:18:22.55@0: 776d6000-776de000 r-xp 00000000 00:0c 982        /lib/libubox.so
2020.06.04-14:18:22.55@0: 776df000-7772b000 r-xp 00000000 00:0c 978        /lib/libumsg.so
2020.06.04-14:18:22.55@0: 77731000-77738000 r-xp 00000000 00:0c 990        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-14:18:22.55@0: 
2020.06.04-14:18:22.55@0: stack: 0x7fd41000 - 0x7fd40b6c 
2020.06.04-14:18:22.55@0: ec 54 6d 77 1b 00 00 00 88 67 05 08 98 0b d4 7f c6 c6 04 08 88 67 05 08 1b 00 00 00 10 00 fe 20 
2020.06.04-14:18:22.55@0: 10 00 fe 20 ec 54 6d 77 f0 ea 6d 77 08 0c d4 7f 6d a9 6d 77 88 67 05 08 1b 00 00 00 05 00 00 00 
2020.06.04-14:18:22.55@0: 
2020.06.04-14:18:22.55@0: code: 0x776cd1db
2020.06.04-14:18:22.55@0: 8b 00 8b 10 01 c2 83 c2 04 52 83 c0 04 50 ff 75   
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.5`, and was fixed in stable `6.47`.

#### Timeline

+ 2019/10/21 - report the vulnerability to the vendor
+ 2019/10/21 - vendor confirms the vulnerability and will fix it as soon as possible
+ 2020/06/02 - vendor fix it in stable `6.47`




