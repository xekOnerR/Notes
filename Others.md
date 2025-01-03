tmux 修改历史记录行数 
```bash
tmux set-option history-limit 10000 
```

Linux `ss -ntplu` 查询占用的端口号并杀死
```bash
ss -ntplu
lsof -i :11601
kill process
```


### OpenSSL 相关

`$Rxxxx.pfx` 文件读取信息
```bash
openssl pkcs12 -info -in $Rxxxx.pfx -noout
-info 文件的详细信息
-noout 阻止显示其他输出
```

提取证书
```bash
openssl pkcs12 -in \$Rxxxx.pfx -out cert.pem -nokeys
-nokeys 不导出私钥
```

查看证书信息
```bash
openssl x509 -in cert.pem -noout -text

要关注的点:  X509v3 Extended Key Usage: / X509v3 Key Usage: critical 
```

签名文件
```powershell
$pass = ConvertTo-SecureString -String 'abceasyas123' -AsPlainText -Force  (pfx文件秘钥)
$cert = Import-PfxCertificate -FilePath 'C:\$Recycle.bin\S-1-5-21-3783586571-2109290616-3725730865-2663\$RLYS3KF.pfx' -Password $pass -CertStoreLocation Cert:\CurrentUser\My

$cert (验证)

Set-AuthenticodeSignature .\Get-bADpasswords.ps1 $cert  (签名文件)
```

#### Strings
strings -n 10 xxx    显示大于等于10字符的内容
strings -el xxx        exe 文件可以尝试这样

#### Unzip Files
```
gzip -dk [FILE]   (.gz)
tar -xvzf [FILE]  (.tar.gz)
tar -xf [FILE]    (.tar)
tar -zxvf [FILE]  (.tgz)
7z x backup.7z -o./  (.7z)
unzip [-l] <File> (.zip)
```


**十六进制转二进制**

```bash
xxd -r -ps path1 > path2
-r 从十六进制转换为二进制 
-ps 如果十六进制是纯文本的形式那就要使用参数-p或者-ps
```
`echo -n "6d2424716c5f53405f504073735730726421" | xxd -ps -r` > `m$$ql_S@_P@ssW0rd!`


**GREP**

-v 删除
-i 大小写忽略
-E 使用正则表达式

```bash
cat 1 | grep -v "^#"    开头为#的 删除
	  | grep -v "^$"    空行 删除

grep -IE Creator\|Author  

exiftool *.pdf | grep -IE Creator\|Author | awk -F: '{print $2}' | sed -e 's/ //g' | grep -vi microsoft | grep -vE '[0-9]' | tail -n 6 | uniq | sort | tee username
```

uniq 去重
sort 排序


**Add User**

```bash
sudo adduser vulnix
sudo usermod -u 2008 vulnix
```


**文件去重**

```bash
sort -u <FILE>
```


**MP4 隐写**

```
python2 ~/tool/tcsteg2.py ./mulder.fbi

<TrueCrypt Container> is a TrueCrypt hidden volume. The file will be
modified in-place so that it seems like a copy of the input file that can be
opened in an appropriate viewer/player. However, the hidden TrueCtype volume
will also be preserved and can be used.
```

如果有就使用 TrueCrypt 提取文件隐藏卷，**需要密码**
![](../0X0A%20vulhub%20WP/第四组推荐靶机%20Linux/photos/Pasted%20image%2020240108115910.png)
> **[0x10 SpyderSecChallenge Wp](../0X0A%20vulhub%20WP/第四组推荐靶机%20Linux/0x10%20SpyderSecChallenge%20Wp.md)**

挂载后记得结束挂载


**文本处理**

```
tee 
sed -s 's///g'
awk -F ' ' '{print $2":"$3}'
tr -n " \t"
paste -sd
grep 
cut -d: -f1,3
```

**rlwrap**

```
rlwrap -cAr nc -lvvp 2233
```

**kpcli**

```bash
kpcli --kdb credentials.kdbx

keepass2john
ls
show -f [FILE]
```

**Nmap** 

```bash
nmap -6
指定ipv6格式扫描
```

**Execl Remove Password**

![](photos/Pasted%20image%2020240221081633.png)

进入后再进入 xl 文件夹，在 worksheets 中的 xml 或者 workbook.xml 里找到类似于 hash 的，直接删除即可
![](photos/Pasted%20image%2020240221082207.png)
然后压缩成 zip 后修改后缀为 xlsx 

**sqlite3**

```
sqlite3 FILE

.tables
select * from TABLE;
```

用户名改格式：
https://github.com/urbanadventurer/username-anarchy.git
```bash
└─$ ruby username-anarchy -i test-names.txt -f first.last [...用法很多 甚至可以直接-f]
```


**tmux 多屏复制**
```bash
ctrl + [
ctrl + Space
alt + w (结束选择)
ctrl + ] 粘贴
```

靶机 pdf 文件不好传输，直接 base64编码后复制到 kali 中解码
```powershell
[convert]::ToBase64String((Get-Content -path "CVE-2023-28252_Summary.pdf" -Encoding byte))
将文件转换为base64后再到kali中转换回来
echo "xxxx" | base64 -d > CVE.pdf
```

**jar 文件分析**
```
sudo apt install jd-gui
```

**windows 搜索文本相关内容上下文**
比如说运行一个程序输出到1.txt ，搜索特定内容的上下文或者值：
```powershell
Select-String -Path "path\to\your\file.txt" -Pattern "this" -Context 2
```

**可能的用户名**
https://gist.github.com/superkojiman/11076951
```bash
~/namemash.py names.txt > possible.txt
```

**命令行添加 hosts 文件**
```bash
sudo sed -i '1i x.x.x.x xx.xx' /etc/hosts

1 line1  ,  i insert
```

**简化 ip 显示**
```
ip -br -4 a 

-br brief 简化显示
-4 只显示ipv4
```

**js 解混淆：**  (jsj 解逆向)
https://beautifier.io/
Detect packers and obfuscators? (unsafe),  
Unescape printable chars encoded as \xNN or \uNNNN?

**msg 文件转换可读**
```bash
msgconvert *.msg
xdg-open xxx.eml
```


**低权限用户绑定端口程序**
```
$ which authbind 
/usr/bin/authbind

authbind nc -lnvp 80 
Listening on [0.0.0.0] (family 0, port 80)
```