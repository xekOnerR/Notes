=====================================================================================
### Linux 

##### 21 - FTP
- Anonymous Login Allowed
- Version Exploits


##### 22 - SSH
- Weak Password 
- **Password Crash**
- Password Crack / Enumeration


##### 25 - SMTP
- VRFY Allowed


##### 79 - Finger 
- Username Enumeration


##### 80 - HTTP
- HTTP Service Version CVE or Exploit
- CMS Verison Information Exploit
- CMS Plugin Exploit
- CMS Tools Scan/Crack
- Directory Enumeration **( BIG 字典 / rockyou.txt / 指定扩展名 )**
		(如果没有扫描结果，是不是 Cookie 不正确，调试后指定 Cookie 再次扫描尝试)
- **.git** Information Disclosure(Enumeration)  |  dumpall
- 目录拼接
- SQL Injection
- XXE
- Directory Traverse
- Remote File Inclusion / Local File Inclusion （php 伪协议绕过）
- Remote Command Execute
- FUZZ
- Upload Exploit / Bypass
- Login Page Crack / Weak Password / Password Crash 
- **dig**挖掘子域名 (Domain)
- SSTI Injection
- phpmyadmin 写入文件
- whatweb
- Network / Cookie / JSON / Method Allowed
- 前端源代码 注释，js 文件
- 前端图片隐写(**如果不同目录一样的图片也要下载下来，万一有信息就错过了**)
-  BP 抓包 : Cookie **UnSerialize exploit** 
- 是否存在域名解析（ssl-cert）


