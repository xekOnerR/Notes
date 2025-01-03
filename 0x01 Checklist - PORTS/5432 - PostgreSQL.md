PostgreSQL 数据库服务的默认端口


**LOGIN**
```bash
psql -h localhost -p 5432 -U your_username [-d your_database]
```


查看数据库
```sql
\l
```

选择数据库
```sql
\c [database]
```

查看当前连接的数据库
```sql
\conninfo
```

查看表列表
```sql
\d
```

查看表结构
```sql
\d [TABLE]
```

执行 SQL 语句查询
```sql
SELECT * FROM [TABLE] ;
```

LOGOUT
```sql
\q
```


**命令执行**
https://medium.com/r3d-buck3t/command-execution-with-postgresql-copy-command-a79aef9c2767