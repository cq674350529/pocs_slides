### vul_net

#### Description

The `net` process suffers from a stack exhaustion vulnerability. By sending a crafted packet to the `net` process, an authenticated remote user can trigger a stack exhaustion vulnerability via recursive function calls.

When testing the proof of concept on an x86 RouterOS VM, this vulnerability didn't just crash `net` process but caused the whole system to reboot.

Against stable `6.46.5`, the poc resulted in the following crash captured by `gdb`.

```shell
(gdb) c                                                                       
Continuing.                                                                   
                                                                              
Program received signal SIGSEGV, Segmentation fault.                          
=> 0x809ec65:   push   eax                                                    
   0x809ec66:   push   esi                                                    
   0x809ec67:   push   DWORD PTR [ebp+0xc]                                    
   0x809ec6a:   push   edi                                                    
0x0809ec65 in ?? ()                                                           
(gdb) i r                                                                     
eax            0xfe0008 16646152                                              
ecx            0x7772cae4       2004011748                                    
edx            0x8122630        135407152                                     
ebx            0x7772cae4       2004011748                                    
esp            0x7f310fe0       0x7f310fe0                                    
ebp            0x7f311018       0x7f311018                                    
esi            0x7fb0ff48       2142306120                                    
edi            0x7fb0fe4c       2142305868                                    
eip            0x809ec65        0x809ec65                                     
eflags         0x10206  [ PF IF RF ]                                          
cs             0x73     115                                                   
ss             0x7b     123                                                   
ds             0x7b     123                                                   
es             0x7b     123                                                   
fs             0x0      0                                                     
gs             0x33     51                                                    
(gdb) info inferiors                                                          
  Num  Description       Executable                                           
* 1    process 106       target:/nova/bin/net                                 
(gdb) info proc mappings                                                      
process 106                                                                   
Mapped address spaces:                                                        
                                                                              
        Start Addr   End Addr       Size     Offset objfile                   
         0x8048000  0x8121000    0xd9000        0x0 /nova/bin/net             
         0x8121000  0x8123000     0x2000    0xd8000 /nova/bin/net             
         0x8123000  0x8152000    0x2f000        0x0 [heap]                    
        0x77634000 0x77644000    0x10000        0x0 socket:[825]              
        0x77644000 0x77654000    0x10000        0x0 socket:[824]              
        0x77654000 0x77689000    0x35000        0x0 /lib/libuClibc-0.9.33.2.so
        0x77689000 0x7768a000     0x1000    0x35000 /lib/libuClibc-0.9.33.2.so
        0x7768a000 0x7768b000     0x1000    0x36000 /lib/libuClibc-0.9.33.2.so
        0x7768b000 0x7768d000     0x2000        0x0                           
        0x7768d000 0x776a7000    0x1a000        0x0 /lib/libgcc_s.so.1        
        0x776a7000 0x776a8000     0x1000    0x19000 /lib/libgcc_s.so.1        
        0x776a8000 0x776b7000     0xf000        0x0 /lib/libuc++.so           
        0x776b7000 0x776b8000     0x1000     0xf000 /lib/libuc++.so           
        0x776b8000 0x776c6000     0xe000        0x0 /lib/libz.so              
        0x776c6000 0x776c7000     0x1000     0xe000 /lib/libz.so              
        0x776c7000 0x776d1000     0xa000        0x0 /lib/libm-0.9.33.2.so     
        0x776d1000 0x776d2000     0x1000     0xa000 /lib/libm-0.9.33.2.so     
        0x776d2000 0x776d3000     0x1000     0xb000 /lib/libm-0.9.33.2.so     
        0x776d3000 0x776db000     0x8000        0x0 /lib/libubox.so           
        0x776db000 0x776dc000     0x1000     0x7000 /lib/libubox.so           
        0x776dc000 0x776df000     0x3000        0x0 /lib/libuxml++.so         
        0x776df000 0x776e0000     0x1000     0x2000 /lib/libuxml++.so         
        0x776e0000 0x7772c000    0x4c000        0x0 /lib/libumsg.so           
        0x7772c000 0x7772e000     0x2000    0x4c000 /lib/libumsg.so           
        0x7772e000 0x7772f000     0x1000        0x0                           
        0x7772f000 0x7774c000    0x1d000        0x0 /lib/libucrypto.so        
        0x7774c000 0x7774d000     0x1000    0x1d000 /lib/libucrypto.so        
        0x7774e000 0x77750000     0x2000        0x0                           
        0x77750000 0x77757000     0x7000        0x0 /lib/ld-uClibc-0.9.33.2.so
        0x77757000 0x77758000     0x1000     0x6000 /lib/ld-uClibc-0.9.33.2.so
        0x77758000 0x77759000     0x1000     0x7000 /lib/ld-uClibc-0.9.33.2.so
        0x7f312000 0x7fb11000   0x7ff000        0x0 [stack]                   
        0xffffe000 0xfffff000     0x1000        0x0 [vdso]                    
(gdb) x/10wx $esp                                                             
0x7f310fe0:     Cannot access memory at address 0x7f310fe0                    
(gdb) bt                                                                      
#0  0x0809ec65 in ?? ()                                                       
#1  0x0809ec70 in ?? ()                                                       
#2  0x0809ec70 in ?? ()                                                       
#3  0x0809ec70 in ?? ()                                                       
#4  0x0809ec70 in ?? ()                                                       
#5  0x0809ec70 in ?? ()                                                       
#6  0x0809ec70 in ?? ()                                                       
#7  0x0809ec70 in ?? ()                                                       
#8  0x0809ec70 in ?? ()                                                       
#9  0x0809ec70 in ?? ()                                                       
#10 0x0809ec70 in ?? ()                                                       
#11 0x0809ec70 in ?? ()                                                       
#12 0x0809ec70 in ?? ()                                                       
#13 0x0809ec70 in ?? ()                                                       
#14 0x0809ec70 in ?? ()                                                       
#15 0x0809ec70 in ?? ()                                                       
#16 0x0809ec70 in ?? ()                                                       
#17 0x0809ec70 in ?? ()                                                       
#18 0x0809ec70 in ?? ()                                                       
#19 0x0809ec70 in ?? ()                                                       
#20 0x0809ec70 in ?? ()                                                       
#21 0x0809ec70 in ?? ()                                                       
#22 0x0809ec70 in ?? ()                                                       
#23 0x0809ec70 in ?? ()                                                       
# ...                                                 
```

And the crash dump in `/rw/logs/backtrace.log` was:

```shell
# cat /rw/logs/backtrace.log 
2020.06.08-11:19:45.40@0: 
2020.06.08-11:19:45.40@0: 
2020.06.08-11:19:45.40@0: /nova/bin/net
2020.06.08-11:19:45.40@0: --- signal=11 --------------------------------------------
2020.06.08-11:19:45.40@0: 
2020.06.08-11:19:45.40@0: eip=0x0809ec65 eflags=0x00010206
2020.06.08-11:19:45.40@0: edi=0x7fb0fe4c esi=0x7fb0ff48 ebp=0x7f311018 esp=0x7f310fe0
2020.06.08-11:19:45.40@0: eax=0x00fe0008 ebx=0x7772cae4 ecx=0x7772cae4 edx=0x08122630
2020.06.08-11:19:45.40@0: 
2020.06.08-11:19:45.40@0: maps:
2020.06.08-11:19:45.40@0: 08048000-08121000 r-xp 00000000 00:0c 1004       /nova/bin/net
2020.06.08-11:19:45.40@0: 77654000-77689000 r-xp 00000000 00:0c 964        /lib/libuClibc-0.9.33.2.so
2020.06.08-11:19:45.40@0: 7768d000-776a7000 r-xp 00000000 00:0c 960        /lib/libgcc_s.so.1
2020.06.08-11:19:45.40@0: 776a8000-776b7000 r-xp 00000000 00:0c 944        /lib/libuc++.so
2020.06.08-11:19:45.40@0: 776b8000-776c6000 r-xp 00000000 00:0c 945        /lib/libz.so
2020.06.08-11:19:45.40@0: 776c7000-776d1000 r-xp 00000000 00:0c 961        /lib/libm-0.9.33.2.so
2020.06.08-11:19:45.40@0: 776d3000-776db000 r-xp 00000000 00:0c 950        /lib/libubox.so
2020.06.08-11:19:45.40@0: 776dc000-776df000 r-xp 00000000 00:0c 948        /lib/libuxml++.so
2020.06.08-11:19:45.40@0: 776e0000-7772c000 r-xp 00000000 00:0c 946        /lib/libumsg.so
2020.06.08-11:19:45.40@0: 7772f000-7774c000 r-xp 00000000 00:0c 947        /lib/libucrypto.so
2020.06.08-11:19:45.40@0: 77750000-77757000 r-xp 00000000 00:0c 958        /lib/ld-uClibc-0.9.33.2.so
2020.06.08-11:19:45.40@0: 
2020.06.08-11:19:45.40@0: stack: 0x7fb10000 - 0x7f310fe0
```

#### Affected Version

This vulnerability was initially found in long-term  `6.44.5`, and was fixed in stable `6.47`.

#### Timeline

+ 2019/09/16 - report the vulnerability to the vendor
+ 2019/09/17 - vendor confirms the vulnerability and will fix it as soon as possible
+ 2020/06/02 - vendor fix it in stable `6.47`