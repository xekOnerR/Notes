## network configs

**(NAT模式)** 把虚拟机的网络配置设置成vnet0
先设置虚拟网络适配器的NAT模式 查看系统给你的ip和网关是多少 然后记住后再在物理机的网络设置中找到v..net0 然后修改ipv4的ip地址 然后都修改成和虚拟网络适配器一样的属性 然后再修改虚拟机中的ip配置文件.

kalilinux network configs :

sudo vim /etc/network/interface
指定 eth0的 static ip

### 静态 IP

```bash
auto eth0 
iface eth0 inet static 
address YOUR_STATIC_IP 
netmask YOUR_NETMASK 
gateway YOUR_GATEWAY
```

linux network conigs:

su -
vim /etc/sysconfig/network-scripts/ifcfg-eth0

------

### 对于一些网卡没有配置正确的靶机网卡

靶机开机后按住shift , 

![image-20231129133142353](network configs.assets/image-20231129133142353.png)

再按e进入安全模式：

![image-20231129133152155](network configs.assets/image-20231129133152155.png)

**找到ro，删除该行后边内容，并将ro 。。。修改为：** 

`rw signie init=/bin/bash`

然后按**ctrl + x** 进入bash

![image-20231129133531972](network configs.assets/image-20231129133531972.png)

![image-20231129133807186](network configs.assets/image-20231129133807186.png)

如果interfaces是这样子 那就进入

`/etc/netplan`

![image-20231129133846662](network configs.assets/image-20231129133846662.png)

![image-20231129133858685](network configs.assets/image-20231129133858685.png)

把ens33修改成这个：

重启即可
