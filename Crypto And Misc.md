

**rot-13**
`synt1{z00ap4xr}` > `flag1{m00nc4ke}`
[ROT13加密/解密 - ROT13编码/解码—LZL在线工具 (lzltool.cn)](https://lzltool.cn/Tools/Rot13)


**横线解密**
```
DESC = 'C4N YOU 1D3N71FY 7H3 FL46?'
str1 = 'FLAG4{'
str2 = '______'
str3 = '0'
str4 = '_____________________'
str5 = '__________________'
str6 = '____'
str7 = '1'
str8 = '_______'
str9 = '1'
str10 = '____________________'
str11 = '__________________________'
str12 = '}'
```

几个 _ 对应了字母表中的字母 ： `flag{f0urd1g1tz}` 


**gpg**

- 针对 .gpg 后缀的文件的解密，需要密码
```bash
gpg --batch --passphrase HARPOCRATES -d ./login.txt.gpg

--batch 非交互模式
--passphrase 秘钥
-d 解密
```


**Caesar**

![](photos/Pasted%20image%2020231228204027.png)
向前移动 1 位 :
```
Hello Andrew, Welcome aboard to python programming and to the world of computer science. When writing code for the computer, "The simplest solution is the best one for the computer's."
Like I said when writing, keep your focus, the next step will be testing the program. 
```


**Hex**

```
61:6c:65:72:74:28:27:6d:75:6c:64:65:72:2e:66:62:69:27:29:3b
```
[HEX转字符 十六进制转字符 hex gb2312 gbk utf8 汉字内码转换 - The X 在线工具 (the-x.cn)](https://the-x.cn/encodings/Hex.aspx)
![](photos/Pasted%20image%2020240108112552.png)

```bash
xxd -r -ps path1 > path2
-r 从十六进制转换为二进制 
-ps 如果十六进制是纯文本的形式那就要使用参数-p或者-ps
```
`echo -n "6d2424716c5f53405f504073735730726421" | xxd -ps -r` > `m$$ql_S@_P@ssW0rd!`

 **JS packed**

```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('7:0:1:2:8:6:3:5:4:0:a:1:2:d:c:b:f:3:9:e',16,16,'6c|65|72|27|75|6d|28|61|74|29|64|62|66|2e|3b|69'.split('|'),0,{}))
```
[Javascript在线解压缩 - 在线工具 (tool.lu)](https://tool.lu/js/)
![](photos/Pasted%20image%2020240108112700.png)


 **MP4文件隐藏文件**

> [0x10 SpyderSecChallenge Wp](../0X0A%20vulhub%20WP/第四组推荐靶机%20Linux/0x10%20SpyderSecChallenge%20Wp.md)

```
python2 ~/tool/tcsteg2.py FILE
```

提取文件使用 `TrueCrypt` , 可能需要密码，挂载完后记得结束挂载


**图片相关**

- 查看图片隐写
```
exiftool <path>
```

- 查看内嵌信息 + 爆破密码
```bash
stegcracker <PATH>
stegseek <PATH> <DIR>
```

- 查看内嵌信息
```bash
steghide <PATH>
可以查看有无内嵌信息
sudo steghide info <PATH>
sudo steghide extract -sf <PATH>
```


**brainfuck crack:**

```bash
beef  
```


**VNC Decrypt**
https://github.com/billchaison/VNCDecrypt
```bash
echo -n 'Hex String like 2a2a2a1a1a1a' | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d -provider legacy -provider default | hexdump -Cv
```

**ANSIBLE_VAULT** 解密
可以用 ansible2john 来制作 hash， john 破解 (注意 ansible2john 只接受一行 hash) 比如：
hash_raw:
```bash
$ANSIBLE_VAULT;1.1;AES256 326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
```
解密出秘钥

```bash
pipx install ansible-core
```

```bash
cat hash_raw | ansible-vault decrypt
Vault password:
Decryption successful
svc_pwm
```