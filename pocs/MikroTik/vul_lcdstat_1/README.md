### vul_lcdstat_1

#### Description

The `lcdstat` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `lcdstat` process due to invalid memory access.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
Thread 2.1 "lcdstat" received signal SIGSEGV, Segmentation fault.
=> 0x805a26e:   mov    esi,DWORD PTR [eax-0x4]
   0x805a271:   push   DWORD PTR [ebx+0x78]
   0x805a274:   call   0x8056298
   0x805a279:   mov    eax,DWORD PTR [esi+0x10]
0x0805a26e in ?? ()
(gdb) i r
eax            0x0      0
ecx            0x807f14c        134738252
edx            0x1      1
ebx            0x7fbeb848       2143205448
esp            0x7fbeadf4       0x7fbeadf4
ebp            0x7fbeae18       0x7fbeae18
esi            0x7fbeaedc       2143203036
edi            0x0      0
eip            0x805a26e        0x805a26e
eflags         0x10202  [ IF RF ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) info inferiors
  Num  Description       Executable
  1    <null>            target:/nova/bin/lcdstat
* 2    process 465       target:/nova/bin/lcdstat
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-15:32:04.67@0: 
2020.06.04-15:32:04.67@0: 
2020.06.04-15:32:04.67@0: /nova/bin/lcdstat
2020.06.04-15:32:04.67@0: --- signal=11 --------------------------------------------
2020.06.04-15:32:04.67@0: 
2020.06.04-15:32:04.67@0: eip=0x0805a26e eflags=0x00010202
2020.06.04-15:32:04.67@0: edi=0x00000000 esi=0x7fbeaedc ebp=0x7fbeae18 esp=0x7fbeadf4
2020.06.04-15:32:04.67@0: eax=0x00000000 ebx=0x7fbeb848 ecx=0x0807f14c edx=0x00000001
2020.06.04-15:32:04.67@0: 
2020.06.04-15:32:04.67@0: maps:
2020.06.04-15:32:04.67@0: 08048000-0807e000 r-xp 00000000 00:0c 1054       /nova/bin/lcdstat
2020.06.04-15:32:04.67@0: 776fd000-77732000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-15:32:04.67@0: 77736000-77750000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-15:32:04.67@0: 77751000-77760000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-15:32:04.67@0: 77761000-77769000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-15:32:04.67@0: 7776a000-777b6000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-15:32:04.67@0: 777bc000-777c3000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-15:32:04.67@0: 
2020.06.04-15:32:04.67@0: stack: 0x7fbeb000 - 0x7fbeadf4 
2020.06.04-15:32:04.67@0: 48 b8 be 7f 18 ae be 7f 95 ab 05 08 a0 e5 07 08 00 00 00 00 4c f1 07 08 48 b8 be 7f dc ae be 7f 
2020.06.04-15:32:04.67@0: 00 00 00 00 58 ae be 7f 00 ad 05 08 48 b8 be 7f 00 00 00 00 00 00 00 00 ec 04 76 77 d8 af be 7f 
2020.06.04-15:32:04.67@0: 
2020.06.04-15:32:04.67@0: code: 0x805a26e
2020.06.04-15:32:04.67@0: 8b 70 fc ff 73 78 e8 1f c0 ff ff 8b 46 10 83 c4 
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `6.47`.

#### Timeline

+ 2020/03/11 - report the vulnerability to the vendor
+ 2020/06/02 - vendor fix it in stable `6.47`



