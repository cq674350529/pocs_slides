### vul_cerm

#### Description

The `cerm` process suffers from an uncontrolled resource consumption vulnerability. By sending a crafted packet, an authenticated remote user can cause a high cpu load, which may make the device respond slowly or unable to respond.

Against long-term `6.45.8`, the poc resulted in the high cpu load on the device.

![cerm_high_cpu_load](./images/cerm_high_cpu_load.png)

#### Affected Version

This vulnerability was initially found in long-term  `6.44.6`, and was fixed since stable `6.46` .

#### Timeline

+ 2020/01/06 - report the vulnerability to the vendor
+ 2020/01/08 - vendor confirms the vulnerability and fix it since stable `6.46`