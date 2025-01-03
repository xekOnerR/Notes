## 学生信息管理系统 2023/10/20

灵感来源于b站的差不多的一个视频 开始操作吧
先创建基本html骨架:

```html
<h2>学生信息管理系统</h2>
<form action="" method="post" name="index">  
    <p align="center"><input class="addbtn" type="button" value="新增" name="addbtn" onClick="location.herf='insert.php'"></p>
    <p align="center"><input type="text" name="searchtext">
        <input type="submit" value="搜索" name="searchsnb"></p>
    <table cellspacing="0px" border="1px" align="center" width="800px"> 
        <tr>
            <th>编号</th>
            <th>姓名</th>
            <th>性别</th>
            <th>年龄</th>
            <th>操作</th>
        </tr>
    </table>
</form>
```

![image-20231020173910579](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231020173910579.png)

链接数据库:

```php
$link = mysqli_connect('localhost','root','123456','std');
if (!$link){
    exit('链接失败！'); //如果链接失败那就退出并且返回 "链接失败！"
}
```

接下来获得用户输入的数据搜索的最基本的获取搜索集:

```php
if (empty($_POST["searchsusearchsnbb"])){
    $res = mysqli_query($link,"select * from stdinfo order by stdid"); 
}else{
    $search = $_POST["searchtext"];
    $res = mysqli_query($link,"select * from stdinfo where stdname like '%$search%' or stdsex like '%$search%' or stdid like '%$search%'");
}
```

然后就用while循环把搜索到的全部赋值显示到前端:

```php
while ($row = mysqli_fetch_array($res)){
    echo '<tr>';
    echo "<td>$row[0]</td><td>$row[1]</td><td>$row[2]</td><td>$row[3]</td>
            <td>
            <input type='submit' name='upsub$row[0]' value='修改' />
            <input type='submit' name='delsub$row[0]' value='删除' />
            </td>";
    echo '<tr>';
}
```

刷新网页 此时的searchsnb为empty 所以返回全结果集:
![image-20231020180404129](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231020180404129.png)



做添加网站:
简单的一个骨架表单:

```html
<h1>学生信息添加</h1>
<form action="" method="post" >
    <p align="center">
        学生姓名: &nbsp;<input type="text" name="addstdname">
    </p>
    <p align="center">
        学生性别: &nbsp;<input type="text" name="addstdsex">
    </p>
    <p align="center">
        学生年龄: &nbsp;<input type="text" name="addstdage">
    </p>
    <p align="center">
        <input type="submit" name="addsub" value="提交">
    </p>
</form>
```

![image-20231020182853727](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231020182853727.png)

继续链接到数据库数据 

```php
$link = mysqli_connect('localhost','root','123456','std');
if (!$link){
    exit('链接失败！');
}
```

```php
if (!empty($_POST["addsub"])) {
    if (empty($_POST["addstdname"] && $_POST["addstdsex"] && $_POST["addstdage"])){//简单的判断是否三个都输入了内容 目前还没有做正则表达式 后期优化的时候会和css一起补上
        echo '<script>alert("您输入的信息有误,请重新输入！")</script>';
    }else{
        $addstdname = $_POST["addstdname"];
        $addstdsex = $_POST["addstdsex"];
        $addstdage = $_POST["addstdage"];
        mysqli_query($link,"insert stdinfo (stdname,stdsex,stdage) values ('$addstdname','$addstdsex','$addstdage')");
        $_SESSION['success'] = '添加成功!'; //用于后面的弹窗传输
        header('location:stdmain.php');
    }
}
```

做完的效果如下:

![image-20231020203955791](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231020203955791.png)

接下来做修改功能:

```php
打算在下面重新开一行表格修改 带有默认value值
    if (!empty($_POST["upsub$row[0]"])){
        echo '<tr align="center">';
        echo "<td>$row[0]</td>
                <td><input type='text' name='upstdname' value='$row[1]'></td>
                <td><input type='text' name='upstdsex' value='$row[2]'></td>
                <td><input type='text' name='upstdage' value='$row[3]'></td>
                <td><input type='submit' value='确认修改' name='upsubs$row[0]'></td>";
        echo '</tr>';
    }
```

![image-20231020204328515](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231020204328515.png)

然后做判断 是否点击确认修改 如果点击就执行update:

```php
if (!empty($_POST["upsubs$row[0]"])){
    $upstdname = $_POST["upstdname"];
    $upstdsex = $_POST["upstdsex"];
    $upstdage = $_POST["upstdage"];
    mysqli_query($link,"update stdinfo set stdname='$upstdname',stdsex='$upstdsex',stdage=$upstdage where stdid=$row[0]");
    header('location:'.$_SERVER["HTTP_REFERER"]); //此处使用到了referer头来做自刷新
} 
```

做完修改做删除功能:

```php
if (!empty($_POST["delsub$row[0]"])){
    $_SESSION['del'] = $row[0];
    echo '<script>
                 if (confirm("是否确认删除?") == true){
                    location.href="del.php"
                 }
                 </script>';
}
```

这里的 $_SESSION['del'] = $row[0]; 是为了确认弹窗的出现做的跨站点传参:

![image-20231020204538408](C:\Users\13461\AppData\Roaming\Typora\typora-user-images\image-20231020204538408.png)

由于在php中访问script的变量有点麻烦 所以用了session跨站点跳弹窗删数据:
新建del.php：

```php
<?php
    session_start();
    $link = mysqli_connect('localhost','root','123456','std');
    if (!$link){
        exit('链接失败！');
    }
    $del = $_SESSION['del']; 	//取得从stdmain传来的数据
    mysqli_query($link,"delete from stdinfo where stdid = $del");
    unset($_SESSION['del']);    //记得删session
    header('location:stdmain.php');		//跳转回stdmain.php
?>
```

到这里所有的增查改删都完成了 

**注意** 记得在用session传递缓存的时候别忘了 
session_start(); 和 unset($_SESSION[' xx ']);

```html
<!-- 完成于2023.10.20 20:48 目前csrf还没有学 先学php和mysql的增查改删~ -->
```

