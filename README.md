coconut - Distribute sequence generator
=================================
Copyright by calvin<br>
Email : calvinwilliams@163.com<br>

# COMPILE && INSTALL

```Bash
$ git clone http://git.oschina.net/calvinwilliams/coconut.git
Cloning into 'coconut'...
remote: Counting objects: 27, done.
remote: Compressing objects: 100% (24/24), done.
remote: Total 27 (delta 5), reused 0 (delta 0)
Unpacking objects: 100% (27/27), done.
Checking connectivity... done.
```

```Bash
$ cd coconut
$ cd src
$ make -f makefile.Linux install
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include  -c coconut.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include  -c fasterhttp.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include  -c LOGC.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -o coconut coconut.o fasterhttp.o LOGC.o -L. -L/home/calvin/lib -lcrypto -lssl -lz 
cp -rf coconut /home/calvin/bin/
$ ls -l ~/bin/coconut
-rwxrwxr-x 1 calvin calvin 138477 04-09 14:38 /home/calvin/bin/coconut
```

# QUICK START SERVICE

```Bash
$ coconut
coconut v0.0.1
Copyright by calvin 2017
USAGE : coconut -r (reserve) -s (server_no) -p (listen_port)
```

```Bash
$ coconut -r 1 -s 2 -p 8888
$ ps -ef | grep coconut | grep -v grep
calvin   27015     1  0 14:59 pts/2    00:00:00 coconut -r 1 -s 2 -p 8888
```

# TEST && PERFORMANCE

```Bash
$ curl http://127.0.0.1:8888/fetch
aR2011o_cWG00002
$ curl "http://127.0.0.1:8888/explain?sequence=aR2011o_cWG00002"
reserve: 2  server_no: 1  secondstamp: 1492962986(2017-04-23 23:56:26) serial_no: 2
```

```Bash
$ ab -c 100 -n 100000 http://127.0.0.1:8888/fetch_sequence
This is ApacheBench, Version 2.0.40-dev <$Revision: 1.146 $> apache-2.0
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Copyright 2006 The Apache Software Foundation, http://www.apache.org/

Benchmarking 127.0.0.1 (be patient)
Completed 10000 requests
Completed 20000 requests
Completed 30000 requests
Completed 40000 requests
Completed 50000 requests
Completed 60000 requests
Completed 70000 requests
Completed 80000 requests
Completed 90000 requests
Finished 100000 requests


Server Software:        
Server Hostname:        127.0.0.1
Server Port:            8888

Document Path:          /fetch_sequence
Document Length:        18 bytes

Concurrency Level:      100
Time taken for tests:   3.73261 seconds
Complete requests:      100000
Failed requests:        0
Write errors:           0
Total transferred:      5700798 bytes
HTML transferred:       1800252 bytes
Requests per second:    32538.73 [#/sec] (mean)
Time per request:       3.073 [ms] (mean)
Time per request:       0.031 [ms] (mean, across all concurrent requests)
Transfer rate:          1811.43 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.4      0       6
Processing:     0    2   0.7      2       6
Waiting:        0    0   0.8      1       3
Total:          0    2   0.9      3      11
WARNING: The median and mean for the waiting time are not within a normal deviation
        These results are probably not that reliable.
WARNING: The median and mean for the total time are not within a normal deviation
        These results are probably not that reliable.

Percentage of the requests served within a certain time (ms)
  50%      3
  66%      3
  75%      3
  80%      3
  90%      3
  95%      3
  98%      4
  99%      4
 100%     11 (longest request)
```

# STOP SERVICE

```Bash
$ ps -ef | grep coconut | grep -v grep
calvin   27015     1  0 14:59 pts/2    00:00:00 coconut -r 1 -s 2 -p 8888
$ kill 27015
```

