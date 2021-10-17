So, this was an interesting Reverse Engineering challenge. After downloading the [binary](https://github.com/0xSh4dy/CTF-Writeups/blob/master/deadfaceCTF/cerealKiller3/cerealKiller3), I used Ghidra to analyze it.
<br>


<img src="https://github.com/0xSh4dy/CTF-Writeups/blob/master/images/cerealKiller3.png" alt="Image not found">

So, we can see that the function FUN_000110e0("notflag{you-guessed-it-again--this-is-not-the-flag}") is called if the user input is wrong. Else, FUN_000110e0(local_268) is called which would give you some key or let's say a passcode.


After that, I checked if there is some binary mitigation or security mechanism.

```
checksec cerealKiller3

Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

So, it is clear that PIE is enabled. Again, I used Ghidra to calculate the base address of the PIE enabled binary.
<br><br>
<img src="https://github.com/0xSh4dy/CTF-Writeups/blob/master/images/cerealKiller.png" alt="Image not found">

It is clear that the base address in this case is 0x10000.

Then, I wrote down the address of the instructions where FUN_000110e0(local_268) and FUN_000110e0("notflag{you-guessed-it-again--this-is-not-the-flag}") are called.
This can be easily done using Ghidra.
<br><br>
      For FUN_000110e0(local_268):
 ```     
       000115b1 e8 2a fb        CALL       FUN_000110e0 
                 ff ff
       
 ``` 
 For FUN_000110e0("notflag{you-guessed-it-again--this-is-not-the-flag}"):
    
 ```
       000115c4 e8 17 fb        CALL       FUN_000110e0   
                 ff ff
```                            

Now, everything is easy if you use [Angr](https://github.com/angr/angr) , a powerful binary analysis framework. We just need to explore through the binary until we reach the address 0x000115b1 as the call instruction right here would only be called if the user provides correct input. Also, we need to avoid the address 0x000115c4 beacuse the instruction right here would be executed if the user input is wrong.

So, a simple Angr script can do the job of finding the correct input.

```
import angr
import logging
target = angr.Project('./cerealKiller3',main_opts={'base_addr':0x10000})
logging.getLogger('angr').setLevel(logging.CRITICAL) #To remove the unwanted logs on the terminal
entry_state = target.factory.entry_state()
simulation = target.factory.simulation_manager(entry_state)
simulation.explore(find=0x000115b1,avoid=0x000115c4)
solution = simulation.found[0].posix.dumps(0)
print(solution)
```

Running the above script,we get the output

```
b'B00-Boo-Boo-B33ry!\x00\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xdd\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9\xd9'
```
So, B00-Boo-Boo-B33ry! is the correct input.

<img src="https://github.com/0xSh4dy/CTF-Writeups/blob/master/images/cerealKiller3Output.png" alt="Image not found">
