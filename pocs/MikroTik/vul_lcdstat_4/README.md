### vul_lcdstat_4

#### Description

The `lcdstat` process suffers from a division-by-zero vulnerability. By sending a crafted packet, an authenticated remote user can crash the `lcdstat` process due to arithmetic exception.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
Thread 2.1 "lcdstat" received signal SIGFPE, Arithmetic exception.      
=> 0x8058539:   idiv   ecx                                              
   0x805853b:   mov    DWORD PTR [ebp-0x20],eax                         
   0x805853e:   mov    eax,0x1                                          
   0x8058543:   shl    eax,cl                                           
0x08058539 in ?? ()                                                     
(gdb) i r                                                               
eax            0x8      8                                               
ecx            0x0      0                                               
edx            0x0      0                                               
ebx            0x7ffff030       2147479600                              
esp            0x7fffef50       0x7fffef50                              
ebp            0x7fffef88       0x7fffef88                              
esi            0x0      0                                               
edi            0x808b0c8        134787272                               
eip            0x8058539        0x8058539                               
eflags         0x10297  [ CF PF AF SF IF RF ]                           
cs             0x73     115                                             
ss             0x7b     123                                             
ds             0x7b     123                                             
es             0x7b     123                                             
fs             0x0      0                                               
gs             0x33     51                                              
(gdb) info inferiors                                                    
  Num  Description       Executable                                     
  1    <null>            target:/nova/bin/lcdstat                       
* 2    process 281       target:/nova/bin/lcdstat                       
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.04-16:17:48.62@0: 
2020.06.04-16:17:48.62@0: 
2020.06.04-16:17:48.62@0: /nova/bin/lcdstat
2020.06.04-16:17:48.62@0: --- signal=8 --------------------------------------------
2020.06.04-16:17:48.62@0: 
2020.06.04-16:17:48.62@0: eip=0x08058539 eflags=0x00010297
2020.06.04-16:17:48.62@0: edi=0x0808b0c8 esi=0x00000000 ebp=0x7fffef88 esp=0x7fffef50
2020.06.04-16:17:48.62@0: eax=0x00000008 ebx=0x7ffff030 ecx=0x00000000 edx=0x00000000
2020.06.04-16:17:48.62@0: 
2020.06.04-16:17:48.62@0: maps:
2020.06.04-16:17:48.62@0: 08048000-0807e000 r-xp 00000000 00:0c 1054       /nova/bin/lcdstat
2020.06.04-16:17:48.62@0: 77f38000-77f6d000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.04-16:17:48.62@0: 77f71000-77f8b000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.04-16:17:48.62@0: 77f8c000-77f9b000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.04-16:17:48.62@0: 77f9c000-77fa4000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.04-16:17:48.62@0: 77fa5000-77ff1000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.04-16:17:48.62@0: 77ff7000-77ffe000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.04-16:17:48.62@0: 
2020.06.04-16:17:48.62@0: stack: 0x80000000 - 0x7fffef50 
2020.06.04-16:17:48.62@0: 64 ef ff 7f ec b4 f9 77 84 b2 f9 77 ec b4 f9 77 a4 ef ff 7f 01 00 00 00 00 50 00 00 00 00 00 00 
2020.06.04-16:17:48.62@0: a4 ef ff 7f 74 5e 08 08 14 00 00 00 30 f0 ff 7f a4 ef ff 7f 28 f0 ff 7f e8 ef ff 7f cc 8e 05 08 
2020.06.04-16:17:48.62@0: 
2020.06.04-16:17:48.62@0: code: 0x8058539
2020.06.04-16:17:48.62@0: f7 f9 89 45 e0 b8 01 00 00 00 d3 e0 48 31 ff 8b 
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable `6.47.0`.



