### vul_smb_2

#### Description

The `smb` process suffers from a memory corruption vulnerability. By sending a crafted packet, an unauthenticated remote user can crash the `smb` process due to invalid memory access.

> In default, the `smb` service is disabled.

#### Reproduce

```shell
$ python poc.py <ip> <port>
```
#### Affected Version

This vulnerability was found in stable `6.44.2`, and was fixed since stable `6.44.3`.

