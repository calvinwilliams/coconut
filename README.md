coconut - 应用缓存服务器
======================
Copyright by calvinwilliams

# 1.概述 #

coconut是一款应用缓存服务器，主要用于场景化的缓存服务。

coconut目前提供了两种场景模式：全局序列号发生器、全局额度管理器，可成为分布式、集群化系统架构中高性能独立功能部件。

* 全局序列号发生器 为分布式、集群化系统提供有序增长、全局唯一、可反解的高性能序列号生成分发服务
* 全局额度管理器 为分布式、集群化系统提供对理财额度、库存数量等高频热点对象的高性能无锁接口服务

# 1.1.全局序列号发生器 #

# 1.1.1.序列号格式 #

coconut生成的序列号为16个64进制可见字符组成，具体格式如下：

| 区号 | 区名 | 说明 |
|:---:|:---:| --- |
| 第一区 | 分区目录 | 2个六十四进制字符 共12个二进制位<br>第一段3个二进制位表示保留区六十四进制字符个数<br>第二段3个二进制位表示服务器编号区六十四进制字符个数<br>第三段3个二进制位表示秒戳区六十四进制字符个数<br>第四段3个二进制位表示序号区六十四进制字符个数 |
| 第二区 | 保留区 | 1个六十四进制字符 有6个二进制位可用 |
| 第三区 | 服务器编号区 | 2个六十四进制字符 可表示4096台发起器服务器 |
| 第四区 | 秒戳区 | 6个六十四进制字符 可表示2179年的秒戳 |
| 第五区 | 序号区 | 5个六十四进制字符 序号区间[1,10亿] |
|  |  | 共16个六十四进制字符 |

（64进制字符集合：0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_）

如序列号：aR2011o_cWG00002

反解出来包含如下信息：reserve: 2  server_no: 1  secondstamp: 1492962986(2017-04-23 23:56:26) serial_no: 2

# 1.1.2.服务接口 #

coconut的全局序列号发生器提供了2个HTTP接口：

* 获取序列号<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/fetch<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送一个有序增长的全局唯一的序列号，如aR2011o_cWG00002；如果发生系统级错误，返回HTTP状态码非200<br>
备注 : 可利用备注区区分业务类型；可利用服务器编号部署序列号发生器集群

* 反解序列号<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/explain?sequence=(序列号)<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送反解文本；如果发生系统级错误，返回HTTP状态码非200<br>
备注 : 反解文本格式"reserve: (保留值)  server_no: (服务器编号)  secondstamp: (1970年至今秒戳)((人可阅读的日期时间格式)) serial_no: (序号)"

# 1.2.全局额度管理器 #

全局额度管理器提供高性能无锁接口对额度、库存等高频热点对象做查询额度、申请额度、撤销流水、补充额度、扣减额度、清空额度等处理。

# 1.2.1.使用过程 #

命令行指定额度、导出结果流水文件名启动coconut，coconut对外提供HTTP接口，客户端可长/短连接发送指令给coconut以操作额度。期间还可以补充、扣减甚至清空额度。当额度为0时自动导出结果流水文件，可能会重复导出覆盖导出文件。

导出结果流水文件格式为每行一条流水，白字符分割为两列：申请流水号、申请额度，如果某流水被撤销则再加一列：撤销流水号。

# 1.2.2.服务接口 #

coconut的全局额度管理器提供了6个HTTP接口：

* 查询额度<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/query<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送"(剩余额度值)"，如果发生参数错误则返回"-1"；如果发生系统级错误，返回HTTP状态码非200<br>

* 申请额度<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/apply?amt=(额度值)<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送"(申请流水号) (剩余额度值)"，如果额度已空或额度不够则返回"0"，如果发生参数错误则返回"-1"；如果发生系统级错误，返回HTTP状态码非200<br>

* 撤销流水<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/cancel?jnlsno=(申请流水号)<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送"(撤销流水号) (剩余额度值)"，如果找不到原申请流水或已被撤销则返回"0"，如果发生参数错误则返回"-1"；如果发生系统级错误，返回HTTP状态码非200<br>

* 补充额度<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/increase?amt=(额度值)<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送"(剩余额度值)"，如果发生参数错误则返回"-1"；如果发生系统级错误，返回HTTP状态码非200<br>

* 扣减额度<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/decrease?amt=(额度值)<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送"(剩余额度值)"，如果发生参数错误则返回"-1"；如果发生系统级错误，返回HTTP状态码非200<br>

* 清空额度<br>
方法 : GET<br>
URL : http://(domain|ip):[port]/empty<br>
返回值 : 如果调用成功，返回HTTP状态码200，HTTP体中回送"(剩余额度值)"，如果发生参数错误则返回"-1"；如果发生系统级错误，返回HTTP状态码非200<br>

# 2.编译安装 #

# 2.1.下载最新源码 #

    $ git clone http://git.oschina.net/calvinwilliams/coconut.git
    Cloning into 'coconut'...
    remote: Counting objects: 27, done.
    remote: Compressing objects: 100% (24/24), done.
    remote: Total 27 (delta 5), reused 0 (delta 0)
    Unpacking objects: 100% (27/27), done.
    Checking connectivity... done.
    
# 2.2.编译源码安装 #

    $ cd src
    $ make -f makefile.Linux install
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c list.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c LOGC.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c fasterhttp.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c tcpdaemon_lib.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c rbtree.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c rbtree_ins.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I. -I/home/calvin/include -std=gnu99  -c coconut.c
    gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -o coconut list.o LOGC.o fasterhttp.o tcpdaemon_lib.o rbtree.o rbtree_ins.o coconut.o -L. -L/home/calvin/lib -lcrypto -lssl -lz -ldl 
    cp -rf coconut /home/calvin/bin/
    $ ls -l ~/bin/coconut 
    -rwxrwxr-x 1 calvin calvin 348856 6月  11 19:21 /home/calvin/bin/coconut

如有需要，修改内核参数以提高通讯性能
    
    $ cd ..
    $ sudo cat sysctl.conf.add >>/etc/sysctl.conf
    $ sudo sysctl -p
    fs.file-max = 10485760
    net.ipv4.tcp_rmem = 1024
    net.ipv4.tcp_wmem = 1024
    net.ipv4.tcp_syncookies = 0
    net.ipv4.ip_local_port_range = 1024 65535
    net.ipv4.tcp_max_tw_buckets = 819200
    net.ipv4.tcp_timestamps = 1
    net.ipv4.tcp_tw_reuse = 1
    net.ipv4.tcp_tw_recycle = 1

# 3.使用说明 #

# 3.1.全局序列号发生器 #

启动服务

    $ coconut -M SEQUENCE -l 127.0.0.1 -p 9527 -c 1 --loglevel-warn --reserve 2 --server-no 1

获取序列号

    $ curl http://127.0.0.1:9527/fetch
    aR2011pfizz00001

反解序列号

    $ curl http://127.0.0.1:9527/explain?sequence=aR2011pfizz00001
    reserve: 2  server_no: 1  secondstamp: 1497180387 (2017-06-11 19:26:27)  serial_no: 1

压测 获取序列号（短连接）

    $ ab -c 100 -n 100000 http://127.0.0.1:9527/fetch
    This is ApacheBench, Version 2.3 <$Revision: 1430300 $>
    Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
    Licensed to The Apache Software Foundation, http://www.apache.org/
    
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
    Completed 100000 requests
    Finished 100000 requests
    
    
    Server Software:        
    Server Hostname:        127.0.0.1
    Server Port:            9527
    
    Document Path:          /fetch
    Document Length:        19 bytes
    
    Concurrency Level:      100
    Time taken for tests:   2.439 seconds
    Complete requests:      100000
    Failed requests:        0
    Write errors:           0
    Total transferred:      5800000 bytes
    HTML transferred:       1900000 bytes
    Requests per second:    41008.25 [#/sec] (mean)
    Time per request:       2.439 [ms] (mean)
    Time per request:       0.024 [ms] (mean, across all concurrent requests)
    Transfer rate:          2322.73 [Kbytes/sec] received
    
    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0    1  29.2      0    1003
    Processing:     0    0   3.6      0     401
    Waiting:        0    0   3.6      0     401
    Total:          0    1  30.2      0    1403
    
    Percentage of the requests served within a certain time (ms)
      50%      0
      66%      0
      75%      0
      80%      0
      90%      0
      95%      0
      98%      0
      99%      1
     100%   1403 (longest request)

停止服务

    $ ps -ef | grep -w coconut | awk '{if($3==1)print $2}' | xargs kill

# 3.2.全局额度管理器 #

启动服务

    $ coconut -M LIMITAMT -l 127.0.0.1 -p 9527 -c 1 --loglevel-warn --limit-amt 1000000 --export-jnls-amt-pathfilename $HOME/coconut_JNLSNO_AMT.txt

查询额度

    $ curl http://127.0.0.1:9527/query
    1000000

申请额度

    $ curl http://127.0.0.1:9527/apply?amt=1
    1 999999
    $ curl http://127.0.0.1:9527/apply?amt=2
    2 999997
    $ curl http://127.0.0.1:9527/apply?amt=3
    3 999994
    $ curl http://127.0.0.1:9527/apply?amt=4
    4 999990
    $ curl http://127.0.0.1:9527/apply?amt=5
    5 999985

撤销流水

    $ curl http://127.0.0.1:9527/cancel?jnlsno=4
    6 999989

补充额度

    $ curl http://127.0.0.1:9527/increase?amt=1000000
    1000000

扣减额度

    $ curl http://127.0.0.1:9527/decrease?amt=100000
    900000

清空额度

    $ curl http://127.0.0.1:9527/empty
    0

查看导出的申请流水文件

    $ ls -l $HOME/coconut_JNLSNO_AMT.txt
    -rw-rw-r--   1 calvin calvin        22 6月  11 19:47 coconut_JNLSNO_AMT.txt
    $ cat $HOME/coconut_JNLSNO_AMT.txt
    1 1
    2 2
    3 3
    4 4 6
    5 5

压测 申请额度（长连接）

    $ curl http://127.0.0.1:9527/increase?amt=1000000
    1000000
    $ ab -kc 100 -n 1000000 http://127.0.0.1:9527/apply?amt=1
    This is ApacheBench, Version 2.3 <$Revision: 1430300 $>
    Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
    Licensed to The Apache Software Foundation, http://www.apache.org/
    
    Benchmarking 127.0.0.1 (be patient)
    Completed 100000 requests
    Completed 200000 requests
    Completed 300000 requests
    Completed 400000 requests
    Completed 500000 requests
    Completed 600000 requests
    Completed 700000 requests
    Completed 800000 requests
    Completed 900000 requests
    Completed 1000000 requests
    Finished 1000000 requests
    
    
    Server Software:        
    Server Hostname:        127.0.0.1
    Server Port:            9527
    
    Document Path:          /apply?amt=1
    Document Length:        12 bytes
    
    Concurrency Level:      100
    Time taken for tests:   3.389 seconds
    Complete requests:      1000000
    Failed requests:        999982
       (Connect: 0, Receive: 0, Length: 999982, Exceptions: 0)
    Write errors:           0
    Keep-Alive requests:    1000000
    Total transferred:      79777768 bytes
    HTML transferred:       16777786 bytes
    Requests per second:    295029.46 [#/sec] (mean)
    Time per request:       0.339 [ms] (mean)
    Time per request:       0.003 [ms] (mean, across all concurrent requests)
    Transfer rate:          22985.15 [Kbytes/sec] received
    
    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0    0   0.1      0       8
    Processing:     0    0   0.1      0       8
    Waiting:        0    0   0.1      0       3
    Total:          0    0   0.1      0      10
    
    Percentage of the requests served within a certain time (ms)
      50%      0
      66%      0
      75%      0
      80%      0
      90%      0
      95%      0
      98%      1
      99%      1
     100%     10 (longest request)

停止服务

    $ ps -ef | grep -w coconut | awk '{if($3==1)print $2}' | xargs kill

# 附录A.启动命令行参数 #

不带参数的执行coconut会显示所有参数提示

    $ coconut
    coconut v0.0.7.0
    Copyright by calvin 2017
    USAGE : coconut -M ( SEQUENCE | LIMITAMT ) [ -l (listen_ip) ] -p (listen_port) [ -c (processor_count) ] [ --loglevel-(debug|info|warn|error|fatal) ] [ --cpu-affinity (begin_mask) ]
                    global serial service :
                        --reserve (reserve) --server-no (server_no)
                    global limit-amt service :
                        --limit-amt (amt) --export-jnls-amt-pathfilename (pathfilename)

-M ( SEQUENCE | LIMITAMT ) : 场景模式 *SEQUENCE全局序列号发生器；LIMITAMT 全局额度管理器*<br>
-p (listen_port) : 侦听端口<br>
-c (processor_count) : 并发进程数量。全局额度管理器模式目前只支持单并发<br>
--loglevel-(debug|info|warn|error|fatal) : 日志等级，默认warn等级。日志文件输出到$HOME/log/coconut.log<br>

全局序列号发生器 场景模式<br>
--reserve (reserve) ： 保留值，可用作业务类型<br>
--server-no (server_no) ： 服务器编号<br>

全局额度管理器 场景模式<br>
--limit-amt (amt) : 总额度<br>
--export-jnls-amt-pathfilename (pathfilename) : 申请结束后导出申请流水文件<br>

# 最后 #

coconut使用到了作者的其它开源项目iLOG3,fasterhttp,tcpdaemon。

coconut全套源码托管在 [开源中国码云](http://git.oschina.net/calvinwilliams/coconut) 和 [github](http://github.com/calvinwilliams/coconut)，如有疑问或建议可以通过 [网易邮箱](calvinwilliams@163.com) 和 [GMAIL邮箱](calvinwilliams.c@gmail.com) 联系到作者。

感谢使用 :)
