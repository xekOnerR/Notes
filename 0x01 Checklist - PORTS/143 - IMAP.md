IMAP（Internet 邮件访问协议）邮件服务器使用此端口。另请参阅端口 993/tcp。

**如果拥有凭据信息，可以访问邮件**
```bash
nc <IP> 143
A1 login <Username> <Password>
A2 list "" "*"   (列出邮箱)
A3 SELECT "<NAME>"
A4 FETCH <message_id> BODY[]
```
