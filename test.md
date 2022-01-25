# Static Analysis

## Finding vulnerabilities

1.The application is signed with v1 signature scheme, making it vulnerable to Janus vulnerability on Android 5.0-8.0, if signed only with v1 signature scheme. In case of Android 5.0-7.0, the application would still be vulnerable even if v2,v3 are used along with v1. The Janus vulnerability allows attackers to modify the code in applications without altering the signatures.

2. android:allowBackup flag is missing. By default it is set to true. It allows anyone to backup the application data via adb.

3. Remote WebView debugging is enabled: CWE-919 in 
```
com/huasheng/stock/jsbridge/BridgeWebView.java
com/pingan/core/happy/webview/BaseWebView.java
com/crh/lib/core/webview/JsWebView.java
```

4. Padding Oracle Attack : 	The App uses the encryption mode CBC with PKCS5/PKCS7 padding. This configuration is vulnerable to padding oracle attacks.

## Malware Analysis

### Analysis by VirusTotal ( https://www.virustotal.com/ )

I uploaded the SHA256 of the apk to VirusTotal and got the following results:
<img src='https://github.com/0xSh4dy/infosec_writeups/blob/images/ss1.png'/>
Thus, many popular and renowned companies like Microsoft, Avast, Tencent, Kaspersky, etc. found. I searched about some of those 
malwares.

```
Android:Evo-gen [Trj] : The virus is a trojan. It is a malware designed to provide unauthorized, remote access to a user's device. Then can lead to other malware being installed on a machine, various data being stolen, or other malicious activities.

Trojan-Dropper.AndroidOS.Agent.sl : It installs applications invisibly to the user. These applications are contained in the body of the Trojan and hidden on the system once installed. The applications use advertising as their main monetization method.

```

### Privacy Trackers
 This app has more than 5 privacy trackers. Trackers can track device or users and are privacy concerns for end users.

