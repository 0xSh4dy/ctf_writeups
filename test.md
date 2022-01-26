# Static Analysis

### App Name  -> FlashPlayer
### MD5:	42946e337db8ddbaa84772f7c0313098	 
### SHA1:	9f6c21f31da736addfb553283f01d3dead110024	 
### SHA256:	9f337117d6452c3e53a2bb5e72899ec10c46fde38883ad4dbef1ed13d85a74eb
### Version: 1.0
### SDK:	 19-24
## Package:
```
com.cxjhunlm.wvhnemc
```


I found the malicious package name multiple times in the Android Manifest file. Such activities have been obfuscated.<br>
I also found one such code snippet in the class snowcorp.vita.e
```
if (applicationInfo != null) {
            applicationInfo.className = "com.cxjhunlm.wvhnemc.App";
        }
```

The app is not debuggable.<br>

The app is not frosted which indicates that it may be a malware.

## Permissions requested by the app
```
android.permission.WRITE_EXTERNAL_STORAGE
android.permission.REQUEST_INSTALL_PACKAGES
android.permission.REORDER_TASKS
android.permission.READ_SMS
android.permission.REQUEST_DELETE_PACKAGES
android.permission.RECEIVE_BOOT_COMPLETED
android.permission.CALL_PHONE
android.permission.MODIFY_AUDIO_SETTINGS
android.permission.SEND_SMS
android.permission.CAPTURE_VIDEO_OUTPUT
android.permission.INTERNET
android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
android.permission.ACCESS_NETWORK_STATE
android.permission.WRITE_SMS
android.permission.ACCESS_NOTIFICATION_POLICY
android.permission.FOREGROUND_SERVICE
android.permission.DISABLE_KEYGUARD
android.permission.RECEIVE_SMS
android.permission.READ_CONTACTS
android.permission.SYSTEM_ALERT_WINDOW
android.permission.CHANGE_WIFI_STATE
android.permission.ACCESS_WIFI_STATE
android.permission.WAKE_LOCK
android.permission.READ_EXTERNAL_STORAGE
```

### Activities
```
com.cxjhunlm.wvhnemc.bot.components.screencast.ScreencastStartActivity
com.cxjhunlm.wvhnemc.bot.PermissionsActivity
com.cxjhunlm.wvhnemc.bot.sms.ComposeSmsActivity
com.cxjhunlm.wvhnemc.bot.components.locker.LockerActivity
com.cxjhunlm.wvhnemc.bot.components.locker.LockerActivity$DummyActivity
com.cxjhunlm.wvhnemc.core.injects_core.Screen
com.cxjhunlm.wvhnemc.bot.components.screencast.UnlockActivity
com.cxjhunlm.wvhnemc.MainActivity

```
### Broadcast Receivers
```
com.cxjhunlm.wvhnemc.bot.sms.MmsReceiver
info.pluggabletransports.dispatch.service.DispatchReceiver
com.cxjhunlm.wvhnemc.bot.receivers.MainReceiver
com.cxjhunlm.wvhnemc.core.injects_core.CHandler
com.cxjhunlm.wvhnemc.bot.HelperAdmin$MyHomeReceiver
com.cxjhunlm.wvhnemc.bot.sms.SmsReceiver
com.cxjhunlm.wvhnemc.core.PeriodicJobReceiver
```

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

I uploaded the SHA256 of the apk to VirusTotal and got the following results: <br>
<img src='https://github.com/0xSh4dy/infosec_writeups/blob/images/ss1.png'/>
Thus, many popular and renowned companies like Microsoft, Avast, Tencent, Kaspersky, etc. found. I searched about some of those 
malwares.


```
Android:Evo-gen [Trj] : The virus is a trojan. It is a malware designed to provide unauthorized, remote access to a user's device. Then can lead to other malware being installed on a machine, various data being stolen, or other malicious activities.

Trojan-Dropper.AndroidOS.Agent.sl : It installs applications invisibly to the user. These applications are contained in the body of the Trojan and hidden on the system once installed. The applications use advertising as their main monetization method.

```

### Privacy Trackers
 This app has more than 5 privacy trackers. Trackers can track device or users and are privacy concerns for end users.



# Dynamic Analysis

I used the android emulator provided by Google with the Android SDK and adb to perform dynamic analysis.

<img src='https://github.com/0xSh4dy/infosec_writeups/blob/images/fullCtrl.png'/>

If the user agrees, the malware would take full control of the device. 
After sometime, the app also asks for the following permission automatically and accepts some permissions like battery monitoring, call logs, etc. on its own.
<img src='https://github.com/0xSh4dy/infosec_writeups/blob/images/ss6.png'/>
After that, if we try to uninstall the Flash Player application, we fail. Even adb shell failed to uninstall the malicious app. Also, we cannot open the main activity after that. Also, we cannot view the app info after that. <br><br>
<img src='https://github.com/0xSh4dy/infosec_writeups/blob/images/notUninstall.png'/>

In order to know more about network communications, I decided to perform some packet sniffing.

```
./emulator -tcpdump emulator.cap -avd Pixel_2_API_30
```

After capturing few packets, I opened the file in wireshark and found that the application was logging my locationl. It was also posting some weird base64 strings. I decoded them but found nothing.

1. The malware is able to track the user location.

<img src='https://github.com/0xSh4dy/infosec_writeups/blob/images/location.png'/> 

2. After getting the initial permissions, the malware automatically accepts the remaining permissions.
As seen from the logcat,
```
startActivity called from finishing ActivityRecord{c11ce88 u0 com.cxjhunlm.wvhnemc/.bot.PermissionsActivity t62 f}; forcing Intent.FLAG_ACTIVITY_NEW_TASK for: Intent { flg=0x800000 cmp=com.android.systemui/.media.MediaProjectionPermissionActivity }
```

```
01-25 20:39:03.241  1663  1684 I ActivityManager: Displayed com.android.settings/.fuelgauge.RequestIgnoreBatteryOptimizations: +266ms
```
### Shared Preferences after providing the initially requested permission
```
<map>
    <boolean name="is_app_icon_hide_" value="true" />
    <boolean name="instructions_skipped_" value="true" />
    <long name="time_of_first_run_" value="1643122829729" />
    <boolean name="is_first_run_" value="false" />
</map>

```


# Conclusion
There is no denying the fact that this app is malicious. A flash player requesting permissions like Sending SMS, accessing contacts suggests that something's fishy. Detailed analysis by Virus Total and Dynamic Analysis proves that the app is really malicious.
