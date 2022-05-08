## Writeups : DevCTF

So, I'll be explaining the techniques used by me to solve various challenges in this interesting CTF.

Lemme start with my second favorite category: Rev (the first one is pwn, obviously:p).

<br><br>

## Reverse Engineering

## Challenge One : getargs
So, starting with the `file` command, I found out that the provided file is an ELF 64 bit shared object, so it can be easily decompiled using IDA Freeware. So, I loaded the file in IDA and used the decompiler to get a good idea about the pseudo code. The following image shows the pseudo code. 

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/getArgs_img1.png">

It is clear that we need to provide one command line argument which will go through some procedure. If everything goes well, `Yes, <argument> is correct!` will be printed otherwise `No, <argument> is not correct.` will be printed to stdout. There's a char array or a string named `aAji9vl0c4p` whose value is `AJi9VL0C4p`. Also, there's a function `QM9Nq()`.
The pseudo code for this function can be easily found using IDA

```
__int64 QM9Nq()
{
  __int64 result; // rax
  int i; // [rsp+0h] [rbp-14h]

  for ( i = 1; ; ++i )
  {
    result = (unsigned int)i;
    if ( i >= 11 )
      break;
    if ( 4 * (i % 11) % 11 == 1 )
      return (unsigned int)i;
  }
  return result;
}
```

On executing this function in some separate C file, we can easily find out that its return value is 3. 
Now, we know everything. In order to get the correct input, we just need to add `QM9Nq()`  or 3 to each member of the array `aAji9vl0c4p` (easy reversing).

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/getArgs_img2.png">

The final solution is:

```
#include<stdio.h>
#include<string.h>
int QM9Nq()
{
  int result; // rax
  int i; // [rsp+0h] [rbp-14h]

  for ( i = 1; ; ++i )
  {
    result = (unsigned int)i;
    if ( i >= 11 )
      break;
    if ( 4 * (i % 11) % 11 == 1 )
      return (unsigned int)i;
  }
  return result;
}
int main(){
    char str1[] = "AJi9VL0C4p";
    for(int i=0;i<strlen(str1);i++){
        putchar(str1[i]+QM9Nq());
    }
    return 0;
}
```
which gives the flag i.e `DMl<YO3F7s`

<br><br>


## Challenge Two : Excess Chars
Hmm, so here comes yet another interesting ELF reverse engineering challenge. In this case, it was a 32 bit binary, therefore I used IDA Pro to decompile it. 

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/excessChars_img1.png">


We can clearly see that there's not much stuff inside the main function. The `getInput` function is being called which just takes some user input and echoes it. 
```
int getInput()
{
  char v1[38]; // [esp+2h] [ebp-26h] BYREF

  puts("Enter:");
  __isoc99_scanf("%s", v1);
  return printf("Value entered: %s\n", v1);
}
```
Now, from the image above, we can see an interesting function named `printFlag`. On decompiling it, we get the following pseudo code:
```
int printFlag()
{
  if ( ptrace(PTRACE_TRACEME, 0, 1, 0) >= 0 )
    decryptAndPrint();
  return puts("Try triggering me without debugger\n");
}

So, this function contains some code which doesn't allow the user to use a debugger.
```
The decryptAndPrint() function contains the following stuff:
```
void __noreturn decryptAndPrint()
{
  unsigned __int8 v0; // [esp+6h] [ebp-22h] BYREF
  int v1[5]; // [esp+7h] [ebp-21h] BYREF
  char v2; // [esp+1Bh] [ebp-Dh]
  int i; // [esp+1Ch] [ebp-Ch]

  puts("Maybe you are in the right path ??");
  v1[0] = 1685383782;
  v1[1] = 1467003749;
  v1[2] = 997390087;
  v1[3] = 1713758503;
  v1[4] = 1329057042;
  v2 = 0;
  v0 = 38;
  for ( i = 0; i <= 19; ++i )
    *((_BYTE *)v1 + i) ^= *(&v0 + v0 + i % 4);
  printf("\nFlag you got is : %s", (const char *)v1);
  exit(0);
}
```
Our target is to either call the `printFlag` function or the `decryptAndPrint` function. Here, I'm not gonna mess up with the debugger. Instead, I'm gonna use my favorite tool radare2 to patch the binary.

```
r2 -w crackme2 -> Open the binary in writeable mode in radare2
aaa  -> Perform  auto analysis
s main  -> Seek to the address of the main function 

Now, press V to enter visual mode and then press p to see the instructions. Navigate to any address, let's say the address where getInput is called or call sym.getInpu

```
Now, find the address of `printFlag` which is 0x8049224. Modify a suitable instruction, let's say `call sym.imp.putchar` to `jmp 0x8049224`. Press Enter and save it, and then quit. Run the binary to get the flag!

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/excessChars_img2.png">

## Challenge3 :Ten Little Phrases
Similar to the previous challenge. Patch the binary using radare2, add a `jmp 0x80491a6` instruction where 0x80491a6 is the address of printFlag.
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/10lill_1.png">

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/10lill_2.png">


After dealing with all the three ELF reversing challenges, I decided to go with Winrev.
<br><br>

## Challenge4 : Payload
So, in this challenge we were dealing with some kind of payload. The question asks for the resource name where the payload is located. So, i thought that some Resource related API function might have a major role in it. I explored through the dll using IDA Pro and found an interesting snippet

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/payload.png">
```
hResInfo = FindResourceW(::hModule, (LPCWSTR)0x66, L"asdasdasdasdsad");
```
Thus, the flag is `asdasdasdasdsad`


## Challenge5: Mutex
We just need to find the name of the mutex used by the malware. On decompiling the function
`sub_10002300` we can find that
```
hObject = CreateMutexA(0, 0, "avcjkvcnmvcnmcvnmjdfkjfd");
```
which gives the mutex name as `avcjkvcnmvcnmcvnmjdfkjfd`


## Challenge6: WhichAddress
Here, we need to find which WINAPI function is send to CreateRemoteThreadAPI as a 4th parameter at location 0x10002174
Peeking at this particular location using IDA Pro, we find he following code
```
hHandle = CreateRemoteThread(hProcess, 0, 0, lpStartAddress, lpAddress, 0, ThreadId);
where,
lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");
```
So, `LoadLibraryA` is the required answer


## Challenge7: Privileged
Here, we have to find the token privileges gained by the malware. Again, we need to explore through the code using IDA Pro. I found a function `sub_100019a0` which contains
```
if ( OpenProcessToken(CurrentProcess, 0x28u, &TokenHandle) )
  {
    LookupPrivilegeValueA(0, "SeDebugPrivilege", &NewState.Privileges[0].Luid);
    NewState.PrivilegeCount = 1;
    NewState.Privileges[0].Attributes = 2;
    AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0, 0, 0);
  }
```
So, it is clear that the token privilege gained by the malware is `SeDebugPrivilege`

## Challenge8: DropThis
Now, we need to find the file name of the dropped payload. On decompiling the function
`sub_10002250`, we find that 
```
sub_10002B3B(a3, 260, "iexplore-1.dat"); 
```                                     
So, the filename is `iexplore-1.dat`


## Challenge9: LevelUp
Here, we need to find the process in which tries to inject the dropped payload. So, this is easy as well. Since the injected payload was iexplore-1.dat, I googled it to find the process name and luckily it came out to be `iexplore.exe` which is the flag.


## Challenge10: SHA1
I loaded the dll in the site https://manalyzer.org/ which gives various details including the SHA1 hash of dropped payload. Navigate to the resources section and get the hash

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/sha1.png">
