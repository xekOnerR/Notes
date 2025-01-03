通常用于 Finger 服务 , 一种网络协议，用于查询有关远程系统用户的信息，如用户名、登录时间等。

**finger-user-enum.pl**
https://github.com/pentestmonkey/finger-user-enum/blob/master/finger-user-enum.pl
```bash
./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <IP>
```
爆破出来带有 ip 的就是存在的 username


