### Web
```
/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
```

### TOMCAT 
- password crack
```
Seclists\Passwords\Default-Credentials\tomcat-betterdefaultpasslist_base64encoded.txt
Seclists\Passwords\Default-Credentials\tomcat-betterdefaultpasslist.txt
```

### FUZZ
```
LFI-gracefulsecurity-linux.txt
Seclists/Discovery/Web-Content/common.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt    (?xxx=)
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt    (子域名爆破)
/usr/share/wordlists/seclists/Fuzzing/special-chars.txt  (特殊符号)
```

### POP3
```
/usr/share/wordlists/fasttrack.txt
```

### smtp - user - enum
```
/usr/share/metasploit-framework/data/wordlists/unix_users.txt
```


### Drupal
- Drupal 7.x Module Services - Remote Code Execution **[0x01 Bastard (Drupal EXP,内核提权 , UDF PE)](../0x0B%20HackTheBox%20WP/靶机推荐第五组%2081-120暨内⽹和域渗透学习路径/0x01%20Bastard%20(Drupal%20EXP,内核提权%20,%20UDF%20PE).md)**
	endpoint_path Directory Path : 
```
/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt
```

### usernmae
```
/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
```

### EXP 需要文件的时候:
```bash
/var/lib/inetsim/http/fakefiles

└─$ tree
.
├── favicon.ico
├── sample.bmp
├── sample.gif
├── sample_gui.exe
├── sample.html
├── sample.jpg
├── sample.png
└── sample.txt

cp /var/lib/inetsim/http/fakefiles/sample.jpg SecSignal.jpg
```