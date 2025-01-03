UDP 500通常用户秘钥交换，建立 ipsec vpn

```bash
ike-scan -M 10.129.228.122
```
例:
```bash
└─$ ike-scan -M 10.129.228.122
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.228.122  Main Mode Handshake returned
        HDR=(CKY-R=5553b0192c81d6dc)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
        VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
        VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
        VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
        VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.095 seconds (10.57 hosts/sec).  1 returned handshake; 0 returned notify
```
获取以下信息：
Enc=3DES，Hash=SHA1 , Group=2:modp1024 （使用三重 DES ，SHA1 ，modp1024加密）
Auth=PSK (身份验证是预验证秘钥)
IKE CGA version 1 （IKE 版本为1）


### 连接到 IPSEC VPN

下载客户端
```bash
sudo apt install strongswan
```

构建配置文件
- /etc/ipsec.secrets
```bash
# This file holds shared secrets or RSA private keys for authentication. 
%any : PSK "PASSWORD"
```
- /etc/ipsec.conf
```bash
# ipsec.conf - strongSwan IPsec configuration file 
config setup 
	charondebug="all" 
	uniqueids=yes 
	strictcrlpolicy=no 
conn conceal 
	authby=secret 
	auto=add 
	ike=3des-sha1-modp1024! 
	esp=3des-sha1! 
	type=transport 
	keyexchange=ikev1 
	left=10.10.14.15 
	right=10.10.10.116 
	rightsubnet=10.10.10.116[tcp]
```
`charondebug="all"` - 更详细地帮助我排除连接故障。
`authby="secret"` - 使用 PSK 身份验证。
`ike` 、 `esp` 和 `keyexchange` 是根据中的信息 `ike-scan` 设置的。
`left` 并 `right` 代表我的计算机和目标计算机。
`type=transport` - 使用 IPsec 传输模式连接主机到主机。

链接
```bash
ipsec restart
ipsec up conceal
```

提示 `connection 'conceal' established successfully` 就代表已经链接成功了 
