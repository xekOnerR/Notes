Microsoft Windows RPC ;  RPC (Remote Procedure Call) : Windows 操作系统中的远程过程调用。
允许远程计算机执行在另一个计算机上运行的程序


###### rpcclient  （默认 session 139 ， -p 指定 port）
```bash
rpcclient -U '' -N 10.129.228.115
rpcclient -U 'jari%Cos@Chung@!RPG' 10.129.228.115
rpcclient -U 'BIR-ADFS-GMSA$' search.htb --pw-nt-hash --password='e1e9fd9e46d0d747e1595167eedcec0f'  (hash登录)

-U ''  空username
-N 禁用密码
%分割密码
```

```
srvinfo
enumdomusers
querydominfo
setuserinfo2 USER 23(PASSWORD) NEWPASS
enumprinters (枚举打印机)
querydispinfo  !!!! (可能会有密码信息)
```
###### rpcdump.py
```bash
/usr/share/doc/python3-impacket/examples/rpcdump.py [IP]
```
###### rpcmap.py
```bash
/usr/share/doc/python3-impacket/examples/rpcmap.py ncacn_ip_tcp:10.129.96.60[135]
/usr/share/doc/python3-impacket/examples/rpcmap.py ncacn_ip_tcp:10.129.96.60[135] -brute-uuids -brute-opnums
```





- 12345778-1234-abcd-ef00-0123456789ac -- References: [samr](http://www.hsc.fr/ressources/articles/win_net_srv/well_known_named_pipes.html), [samr interface](http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_samr.html), [SAM access](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en)  
    12345778-1234-abcd-ef00-0123456789ac -- 参考资料：samr、samr 接口、SAM 访问
- 2f5f6521-cb55-1059-b446-00df0bce31db -- References: [Unimodem LRPC Endpoint](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en)  
    2f5f6521-cb55-1059-b446-00df0bce31db -- 参考：Unimodem LRPC 端点
- 906b0ce0-c70b-1067-b317-00dd010662da -- References: [MS-DTC](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en), [IXnRemote operations](http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_msmq.html), [Distributed Transaction Coordinator](http://www.hsc.fr/ressources/articles/srv_res_win/index.html.en) 
    906b0ce0-c70b-1067-b317-00dd010662da -- 参考：MS-DTC、IXnRemote 操作、分布式事务处理协调器
- 367abb81-9844-35f1-ad32-98f038001003 -- References: [SVCCTL RPC](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en), [Services Control Manager](http://www.hsc.fr/ressources/articles/win_net_srv/multiple_rpc_services_example.html)  
    367abb81-9844-35f1-ad32-98f038001003 -- 参考资料：SVCCTL RPC、服务控制管理器
- 12345678-1234-abcd-ef00-0123456789ab -- References: [winipsec and spoolss](http://www.hsc.fr/ressources/articles/win_net_srv/well_known_named_pipes.html), [IPSec services and Spooler service](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en), [winipsec operations](http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_winipsec.html), [winspool operations](http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_spoolss.html)  
    12345678-1234-abcd-ef00-0123456789ab -- 参考：winipsec 和 spoolss、IPSec 服务和 Spooler 服务、winipsec 操作、winspool 操作
- 50abc2a4-574d-40b3-9d66-ee4fd5fba076 -- References: [DnsServer](http://www.hsc.fr/ressources/articles/win_net_srv/well_known_named_pipes.html), [DnsServer operations](http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_dns.html)  
    50abc2a4-574d-40b3-9d66-ee4fd5fba076 -- 参考：DnsServer、DnsServer 操作
- e1af8308-5d1f-11c9-91a4-08002b14a0fa -- References: [epmp](http://www.hsc.fr/ressources/articles/win_net_srv/well_known_named_pipes.html), [RPC endpoint mapper](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en), [Portmapper](http://www.hsc.fr/ressources/articles/srv_res_win/index.html.en), [Portmapper RPC service](http://www.hsc.fr/ressources/articles/win_net_srv/msrpc_portmapper.html), [epmp operations](http://www.hsc.fr/ressources/articles/win_net_srv/rpcss_msrpc_interfaces.html)  
    e1af8308-5d1f-11c9-91a4-08002b14a0fa -- 参考：epmp、RPC 端点映射器、端口映射器、端口映射器 RPC 服务、epmp 操作
- 0b0a6584-9e0f-11cf-a3cf-00805f68cb1b -- References: [localepmp](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en), [localepmp operations](http://www.hsc.fr/ressources/articles/win_net_srv/rpcss_msrpc_interfaces.html)  
    0b0a6584-9e0f-11cf-a3cf-00805f68cb1b -- 参考：localepmp、localepmp 操作
- 99fcfec4-5260-101b-bbcb-00aa0021347a -- References: [IObjectExporter](http://www.hsc.fr/ressources/breves/interfacesRPC.html.en), [IOXIDResolver](http://www.hsc.fr/ressources/articles/srv_res_win/index.html.en), [IOIXResolver operations](http://www.hsc.fr/ressources/articles/win_net_srv/rpcss_dcom_interfaces.html)  
    99fcfec4-5260-101b-bbcb-00aa0021347a -- 参考：IObjectExporter、IOXIDResolver、IOIXResolver 操作
- afa8bd80-7d8a-11c9-bef4-08002b102989 -- This is the RMI, or remote management interface that allows all of this enumeration to occur without authentication. Generally fixed in XP SP2 but the machine you are targeting behaves more like Windows 2000 or Server 2003.  
    afa8bd80-7d8a-11c9-bef4-08002b102989 -- 这是 RMI 或远程管理接口，允许在不进行身份验证的情况下进行所有这些枚举。通常在 XP SP2 中修复，但目标计算机的行为更像 Windows 2000 或 Server 2003。