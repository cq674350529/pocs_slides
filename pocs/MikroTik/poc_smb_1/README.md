### poc_smb_1

#### Description

The smb process suffers from a memory corruption vulnerability. By sending a crafted packet, an unauthenticated remote user can crash the smb process due to invalid memory access.

In default, the smb service is disabled. This vulnerability was found in stable `6.44.2`, and was fixed in stable `6.44.3`.

#### Usage

```shell
$ python poc.py <ip> <port>
```