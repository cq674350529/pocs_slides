### vul_traceroute

#### Description

The `traceroute` process suffers from a memory corruption vulnerability. By sending a crafted packet, an authenticated remote user can crash the `traceroute` process, for the count of loop operation is controllable.

Against stable `6.46.3`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c                                               
Continuing.                                           
                                                      
Program received signal SIGSEGV, Segmentation fault.  
=> 0x804da3e:   rep stos BYTE PTR es:[edi],al         
   0x804da40:   jne    0x804da81                      
   0x804da42:   mov    eax,DWORD PTR [ebx+0x50]       
   0x804da45:   mov    ecx,DWORD PTR [ebx+0x4]        
0x0804da3e in ?? ()                                   
(gdb) i r                                             
eax            0x0      0                             
ecx            0xfdffd1 16646097    <=== controllable                      
edx            0x7e9df530       2124281136            
ebx            0x8052848        134555720             
esp            0x7e9df530       0x7e9df530            
ebp            0x7f9bf5c8       0x7f9bf5c8            
esi            0x7e9df538       2124281144            
edi            0x7e9df538       2124281144            
eip            0x804da3e        0x804da3e             
eflags         0x10297  [ CF PF AF SF IF RF ]         
cs             0x73     115                           
ss             0x7b     123                           
ds             0x7b     123                           
es             0x7b     123                           
fs             0x0      0                             
gs             0x33     51                            
(gdb) info inferiors                                  
  Num  Description       Executable                   
* 1    process 455       target:/nova/bin/traceroute  
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log
2020.05.16-21:51:49.43@0: 
2020.05.16-21:51:49.43@0: 
2020.05.16-21:51:49.43@0: /nova/bin/traceroute
2020.05.16-21:51:49.43@0: --- signal=11 --------------------------------------------
2020.05.16-21:51:49.43@0: 
2020.05.16-21:51:49.43@0: eip=0x0804da3e eflags=0x00010297
2020.05.16-21:51:49.43@0: edi=0x7e9df538 esi=0x7e9df538 ebp=0x7f9bf5c8 esp=0x7e9df530
2020.05.16-21:51:49.43@0: eax=0x00000000 ebx=0x08052848 ecx=0x00fdffd1 edx=0x7e9df530
2020.05.16-21:51:49.43@0: 
2020.05.16-21:51:49.43@0: maps:
2020.05.16-21:51:49.43@0: 08048000-0804f000 r-xp 00000000 00:0c 1007       /nova/bin/traceroute
2020.05.16-21:51:49.43@0: 77705000-7773a000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.05.16-21:51:49.43@0: 7773e000-77758000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.05.16-21:51:49.43@0: 77759000-77768000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.05.16-21:51:49.43@0: 77769000-77773000 r-xp 00000000 00:0c 961        /lib/libm-0.9.33.2.so
2020.05.16-21:51:49.43@0: 77775000-777c1000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.05.16-21:51:49.43@0: 777c7000-777ce000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.05.16-21:51:49.43@0: 
2020.05.16-21:51:49.43@0: stack: 0x7f9c0000 - 0x7e9df530
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed in stable  `6.46.5` .

#### Timeline

+ 2020/01/06 - report the vulnerability to the vendor
+ 2020/01/08 - vendor confirms the vulnerability and fix it in Testing release tree
+ 2020/04/08 - vendor fix it in stable `6.46.5`