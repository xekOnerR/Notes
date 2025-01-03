## SSRF 	(Server-Side Request Forgery:服务器端请求伪造)

攻击者----->服务器---->目标地址 
就相当于服务器是一个跳板 用来访问内网或者其他站点

```php
//PHP中下面函数的使用不当会导致SSRF:
file_get_contents()
fsockopen()
curl_exec()     
```

![image-20231027112017599](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027112017599.png)

![image-20231027112111382](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027112111382.png)

php伪协议:

```php
file:/// 从文件系统中获取文件内容，如，file:///etc/passwd
dict:// 字典服务器协议，访问字典资源，如，dict:///ip:6739/info：
sftp:// SSH文件传输协议或安全文件传输协议
ldap:// 轻量级目录访问协议
tftp:// 简单文件传输协议
gopher:// 分布式文档传递服务，可使用gopherus生成payload
```

```php
file://
http://localhost/pikachu-master/vul/ssrf/ssrf_fgc.php?file=file://C:\Windows\win.ini
```

