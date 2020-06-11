### vul_graphing

#### Description

The `graphing` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `graphing` process due to invalid memory access.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
=> 0x80521e2:   call   DWORD PTR [ecx+0x4]
   0x80521e5:   add    esp,0x18
   0x80521e8:   push   0x5c
   0x80521ea:   push   ebx
0x080521e2 in ?? ()
(gdb) i r
eax            0x8061db8        134618552
ecx            0x0      0
edx            0x8061ce8        134618344
ebx            0x7fa8ad0c       2141760780
esp            0x7fa8acb0       0x7fa8acb0
ebp            0x7fa8acd8       0x7fa8acd8
esi            0x8061cb8        134618296
edi            0x80610a0        134615200
eip            0x80521e2        0x80521e2
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
* 1    process 196       target:/nova/bin/graphing
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-15:12:41.47@0: 
2020.06.04-15:12:41.47@0: 
2020.06.04-15:12:41.47@0: /nova/bin/graphing
2020.06.04-15:12:41.47@0: --- signal=11 --------------------------------------------
2020.06.04-15:12:41.47@0: 
2020.06.04-15:12:41.47@0: eip=0x080521e2 eflags=0x00010202
2020.06.04-15:12:41.47@0: edi=0x080610a0 esi=0x08061cb8 ebp=0x7fa8acd8 esp=0x7fa8acb0
2020.06.04-15:12:41.47@0: eax=0x08061db8 ebx=0x7fa8ad0c ecx=0x00000000 edx=0x08061ce8
2020.06.04-15:12:41.47@0: 
2020.06.04-15:12:41.47@0: maps:
2020.06.04-15:12:41.47@0: 08048000-0805c000 r-xp 00000000 00:0c 1038       /nova/bin/graphing
2020.06.04-15:12:41.47@0: 77651000-77686000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-15:12:41.47@0: 7768a000-776a4000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-15:12:41.47@0: 776a5000-776b4000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-15:12:41.47@0: 776b5000-776bd000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-15:12:41.47@0: 776be000-7770a000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-15:12:41.47@0: 7770d000-77717000 r-xp 00000000 00:0c 961        /lib/libm-0.9.33.2.so
2020.06.04-15:12:41.47@0: 7771c000-77723000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-15:12:41.47@0: 
2020.06.04-15:12:41.47@0: stack: 0x7fa8b000 - 0x7fa8acb0 
2020.06.04-15:12:41.47@0: e8 1c 06 08 b8 1d 06 08 00 00 00 00 01 00 00 00 0c ad a8 7f 5b 00 00 00 b8 98 05 08 b8 98 05 08 
2020.06.04-15:12:41.47@0: f0 da 6b 77 0c ad a8 7f 28 ad a8 7f 3a bc 6b 77 b8 1c 06 08 0c ad a8 7f 05 00 00 00 a0 10 06 08 
2020.06.04-15:12:41.47@0: 
2020.06.04-15:12:41.47@0: code: 0x80521e2
2020.06.04-15:12:41.47@0: ff 51 04 83 c4 18 6a 5c 53 e8 a0 9c ff ff 8b 56 
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `6.47`.

#### Timeline

+ 2019/12/02 - report the vulnerability to the vendor
+ 2020/06/02 - vendor fix it in stable `6.47`



