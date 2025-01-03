枚举 MIB 树
```bash
snmpwalk -c public -v1 -t <IP>
snmpwalk -v1 -c public 192.168.218.30 . > snmpwalk-full
sudo snmpwalk -c public -v2c 192.168.152.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

```
1.3.6.1.2.1.25.1.6.0    System Processes
1.3.6.1.2.1.25.4.2.1.2  Running Programs
1.3.6.1.2.1.25.4.2.1.4  Processes Path
1.3.6.1.2.1.25.2.3.1.4  Storage Units
1.3.6.1.2.1.25.6.3.1.2  Software Name
1.3.6.1.4.1.77.1.2.25   User Accounts
1.3.6.1.2.1.6.13.1.3    TCP Local Ports
```

枚举计算机上用户 ; 枚举本地 TCP 端口，进程等同理
```bash
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25
```

