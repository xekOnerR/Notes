DNS（Domain Name System）服务的默认端口

**区域传输**
```bash
dig +noall +answer @10.10.11.181 axfr absolute.htb
dig <Domain>
dig axfr +all +answer cronos.htb @10.129.227.211 (只使用基本域)
```

**wfuzz 爆破子域名**
```
wfuzz -u [URL] -H "HOST: FUZZ.xxxxxxx" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw [xx]
```
例: `wfuzz -u https://streamio.htb -H "HOST: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --hw 24 `

**dnscan**
https://github.com/rbsec/dnscan
```bash
./dnscan.py -d cyberbotic.io -w subdomains-100.txt
```

**whois**

**nslookup**
```bash
{25-01-02 9:21}kali:~/CRTO-pr/Cronos xekoner% nslookup
> server 10.129.227.211
Default server: 10.129.227.211
Address: 10.129.227.211#53
> 10.129.227.211                                                                                       211.227.129.10.in-addr.arpa     name = ns1.cronos.htb.
```