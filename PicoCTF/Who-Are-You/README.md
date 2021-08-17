We visit the provided URL [http://mercury.picoctf.net:1270/]("http://mercury.picoctf.net:1270/") and find 







Hmm, only people who use the Official PicoBrowser are allowed. What does it mean? Maybe, it's about HTTP headers. So, there is a HTTP header called User-Agent which contains information about the user OS, browser, etc. So , we just need to set the User-Agent header as PicoBrowser.

After that it says that users from other sites cannot be trusted. So, set the Referer header to the url of the current challenge page.

After that it says that the site only worked in 2018. So, set the Date header toany date in 2018, let's say "Date":"Date: Tue, 15 Nov 2018 08:12:31 GMT".

After that it doesn't want that the users should be tracked. So, set the DNT header to 1.

After that, it wants only users that are from Sweden. So, I searched the range of IP addresses available for Sweden and selected one of them. IP addresses can be set using the X-Forwarded-For header. X-Forwarded-For:2.16.155.0. 

Finally, the language must be Swedish. So, set the Accept-Language header as
Accept-Language:sv



I would not like to manually do the above stuff, to add more fun, I created a Python script 

```
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

request = requests.session()
url = "http://mercury.picoctf.net:1270/"
headers = {"User-Agent":"PicoBrowser","Referer":"http://mercury.picoctf.net:1270/",
            "Date":"Date: Tue, 15 Nov 2018 08:12:31 GMT","DNT":"1",
            "X-Forwarded-For":"2.16.155.0","Accept-Language":"sv"}
getData = request.get(url=url,headers=headers).text
soup = BeautifulSoup(getData,"html.parser")
print(soup)

```
