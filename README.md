coconut - Ӧ�û��������
======================
Copyright by calvinwilliams

<!-- TOC -->

- [1. ����](#1-����)
- [2. ���밲װ](#2-���밲װ)
        - [2.1. ��������Դ��](#21-��������Դ��)
        - [2.2. ����Դ�밲װ](#22-����Դ�밲װ)
- [3. ȫ�����кŷ�����](#3-ȫ�����кŷ�����)
        - [3.1. ���кŸ�ʽ](#31-���кŸ�ʽ)
        - [3.2. ����ӿ�](#32-����ӿ�)
                - [3.2.1. ��ȡ���к�](#321-��ȡ���к�)
                - [3.2.2. �������к�](#322-�������к�)
        - [3.3. ����ʾ��](#33-����ʾ��)
                - [3.3.1. ��������](#331-��������)
                - [3.3.2. ��ȡ���к�](#332-��ȡ���к�)
                - [3.3.3. �������к�](#333-�������к�)
                - [3.3.4. ֹͣ����](#334-ֹͣ����)
        - [3.4. ����ѹ��](#34-����ѹ��)
                - [3.4.1. ��ȡ���кţ������ӣ�](#341-��ȡ���кŶ�����)
- [4. ȫ�ֶ�ȹ�����](#4-ȫ�ֶ�ȹ�����)
        - [4.1. ʹ��˵��](#41-ʹ��˵��)
        - [4.2. ����ӿ�](#42-����ӿ�)
                - [4.2.1. ��ѯ���](#421-��ѯ���)
                - [4.2.2. ������](#422-������)
                - [4.2.3. ������ˮ](#423-������ˮ)
                - [4.2.4. ������](#424-������)
                - [4.2.5. �ۼ����](#425-�ۼ����)
                - [4.2.6. ��ն��](#426-��ն��)
        - [4.3. ����ʾ��](#43-����ʾ��)
                - [4.3.1. ��������](#431-��������)
                - [4.3.2. ��ѯ���](#432-��ѯ���)
                - [4.3.3. ������](#433-������)
                - [4.3.4. ������ˮ](#434-������ˮ)
                - [4.3.5. ������](#435-������)
                - [4.3.6. �ۼ����](#436-�ۼ����)
                - [4.3.7. ��ն��](#437-��ն��)
                - [4.3.8. �鿴������������ˮ�ļ�](#438-�鿴������������ˮ�ļ�)
        - [4.4. ����ѹ��](#44-����ѹ��)
                - [4.4.1. �����ȣ������ӣ�](#441-�����ȳ�����)
- [5. ��¼A.���������в���](#5-��¼a���������в���)
- [6. ���](#6-���)

<!-- /TOC -->

# 1. ����

coconut��һ��Ӧ�û������������Ҫ���ڳ������Ļ������

coconutĿǰ�ṩ�����ֳ���ģʽ��ȫ�����кŷ�������ȫ�ֶ�ȹ��������ɳ�Ϊ�ֲ�ʽ����Ⱥ��ϵͳ�ܹ��и����ܶ������ܲ�����

* ȫ�����кŷ����� Ϊ�ֲ�ʽ����Ⱥ��ϵͳ�ṩ����������ȫ��Ψһ���ɷ���ĸ��������к����ɷַ�����
* ȫ�ֶ�ȹ����� Ϊ�ֲ�ʽ����Ⱥ��ϵͳ�ṩ����ƶ�ȡ���������ȸ�Ƶ�ȵ����ĸ����������ӿڷ���

# 2. ���밲װ

## 2.1. ��������Դ��

    $ git clone http://git.oschina.net/calvinwilliams/coconut.git
    Cloning into 'coconut'...
    remote: Counting objects: 27, done.
    remote: Compressing objects: 100% (24/24), done.
    remote: Total 27 (delta 5), reused 0 (delta 0)
    Unpacking objects: 100% (27/27), done.
    Checking connectivity... done.
    
## 2.2. ����Դ�밲װ

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
    -rwxrwxr-x 1 calvin calvin 348856 6��  11 19:21 /home/calvin/bin/coconut

������Ҫ���޸��ں˲��������ͨѶ����
    
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
    net.ipv4.tcp_tw_recycle = 0

# 3. ȫ�����кŷ�����

## 3.1. ���кŸ�ʽ

coconut���ɵ����к�Ϊ16��64���ƿɼ��ַ���ɣ������ʽ���£�

| ���� | ���� | ˵�� |
|:---:|:---:| --- |
| ��һ�� | ����Ŀ¼(index) | 2����ʮ�Ľ����ַ� ��12��������λ<br>��һ��3��������λ��ʾ��������ʮ�Ľ����ַ�����<br>�ڶ���3��������λ��ʾ�������������ʮ�Ľ����ַ�����<br>������3��������λ��ʾ�������ʮ�Ľ����ַ�����<br>���Ķ�3��������λ��ʾ�������ʮ�Ľ����ַ����� |
| �ڶ��� | ������(reserve) | 1����ʮ�Ľ����ַ� ��6��������λ���� |
| ������ | �����������(server_no) | 2����ʮ�Ľ����ַ� �ɱ�ʾ4096̨������������ |
| ������ | �����(secondstamp) | 6����ʮ�Ľ����ַ� �ɱ�ʾ2179������ |
| ������ | �����(serial_no) | 5����ʮ�Ľ����ַ� �������[1,10��] |
|  |  | ��16����ʮ�Ľ����ַ� |

��64�����ַ����ϣ�0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_��

�����кţ�aR2011o_cWG00002

�����������������Ϣ<br>
reserve: 2<br>
server_no: 1<br>
secondstamp: 1492962986(2017-04-23 23:56:26)<br>
serial_no: 2<br>

## 3.2. ����ӿ�

coconut��ȫ�����кŷ������ṩ��2��HTTP�ӿڣ�

### 3.2.1. ��ȡ���к�

���� : GET<br>
URL : http://(domain|ip):[port]/fetch<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���һ������������ȫ��Ψһ�����кţ���aR2011o_cWG00002���������ϵͳ�����󣬷���HTTP״̬���200<br>
��ע : �����ñ�ע������ҵ�����ͣ������÷�������Ų������кŷ�������Ⱥ

### 3.2.2. �������к�

���� : GET<br>
URL : http://(domain|ip):[port]/explain?sequence=(���к�)<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л��ͷ����ı����������ϵͳ�����󣬷���HTTP״̬���200<br>
��ע : �����ı���ʽ"reserve: (����ֵ)  server_no: (���������)  secondstamp: (1970���������)((�˿��Ķ�������ʱ���ʽ)) serial_no: (���)"

## 3.3. ����ʾ��

### 3.3.1. ��������

    $ coconut -M SEQUENCE -l 127.0.0.1 -p 9527 -c 1 --loglevel-warn --reserve 2 --server-no 1

### 3.3.2. ��ȡ���к�

    $ curl http://127.0.0.1:9527/fetch
    aR2011pfizz00001

### 3.3.3. �������к�

    $ curl http://127.0.0.1:9527/explain?sequence=aR2011pfizz00001
    reserve: 2  server_no: 1  secondstamp: 1497180387 (2017-06-11 19:26:27)  serial_no: 1

### 3.3.4. ֹͣ����

    $ ps -ef | grep -w coconut | awk '{if($3==1)print $2}' | xargs kill

## 3.4. ����ѹ��

### 3.4.1. ��ȡ���кţ������ӣ�

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

# 4. ȫ�ֶ�ȹ�����

ȫ�ֶ�ȹ������ṩ�����������ӿڶԶ�ȡ����ȸ�Ƶ�ȵ��������ѯ��ȡ������ȡ�������ˮ�������ȡ��ۼ���ȡ���ն�ȵȴ���

## 4.1. ʹ��˵��

������ָ����ȡ����������ˮ�ļ�������coconut��coconut�����ṩHTTP�ӿڣ��ͻ��˿ɳ�/�����ӷ���ָ���coconut�Բ�����ȡ��ڼ仹���Բ��䡢�ۼ�������ն�ȡ������Ϊ0ʱ�Զ����������ˮ�ļ������ܻ��ظ��������ǵ����ļ���

���������ˮ�ļ���ʽΪÿ��һ����ˮ�����ַ��ָ�Ϊ���У�������ˮ�š������ȣ����ĳ��ˮ���������ټ�һ�У�������ˮ�š�

## 4.2. ����ӿ�

coconut��ȫ�ֶ�ȹ������ṩ��6��HTTP�ӿڣ�

### 4.2.1. ��ѯ���

���� : GET<br>
URL : http://(domain|ip):[port]/query<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���"(ʣ����ֵ)"������������������򷵻�"-1"���������ϵͳ�����󣬷���HTTP״̬���200<br>

### 4.2.2. ������

���� : GET<br>
URL : http://(domain|ip):[port]/apply?amt=(���ֵ)<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���"(������ˮ��) (ʣ����ֵ)"���������ѿջ��Ȳ����򷵻�"0"������������������򷵻�"-1"���������ϵͳ�����󣬷���HTTP״̬���200<br>

### 4.2.3. ������ˮ

���� : GET<br>
URL : http://(domain|ip):[port]/cancel?jnlsno=(������ˮ��)<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���"(������ˮ��) (ʣ����ֵ)"������Ҳ���ԭ������ˮ���ѱ������򷵻�"0"������������������򷵻�"-1"���������ϵͳ�����󣬷���HTTP״̬���200<br>

### 4.2.4. ������

���� : GET<br>
URL : http://(domain|ip):[port]/increase?amt=(���ֵ)<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���"(ʣ����ֵ)"������������������򷵻�"-1"���������ϵͳ�����󣬷���HTTP״̬���200<br>

### 4.2.5. �ۼ����

���� : GET<br>
URL : http://(domain|ip):[port]/decrease?amt=(���ֵ)<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���"(ʣ����ֵ)"������������������򷵻�"-1"���������ϵͳ�����󣬷���HTTP״̬���200<br>

### 4.2.6. ��ն��

���� : GET<br>
URL : http://(domain|ip):[port]/empty<br>
����ֵ : ������óɹ�������HTTP״̬��200��HTTP���л���"(ʣ����ֵ)"������������������򷵻�"-1"���������ϵͳ�����󣬷���HTTP״̬���200<br>

## 4.3. ����ʾ��

### 4.3.1. ��������

    $ coconut -M LIMITAMT -l 127.0.0.1 -p 9527 -c 1 --loglevel-warn --limit-amt 1000000 --export-jnls-amt-pathfilename $HOME/coconut_JNLSNO_AMT.txt

### 4.3.2. ��ѯ���

    $ curl http://127.0.0.1:9527/query
    1000000

### 4.3.3. ������

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

### 4.3.4. ������ˮ

    $ curl http://127.0.0.1:9527/cancel?jnlsno=4
    6 999989

### 4.3.5. ������

    $ curl http://127.0.0.1:9527/increase?amt=1000000
    1000000

### 4.3.6. �ۼ����

    $ curl http://127.0.0.1:9527/decrease?amt=100000
    900000

### 4.3.7. ��ն��

    $ curl http://127.0.0.1:9527/empty
    0

### 4.3.8. �鿴������������ˮ�ļ�

    $ ls -l $HOME/coconut_JNLSNO_AMT.txt
    -rw-rw-r--   1 calvin calvin        22 6��  11 19:47 coconut_JNLSNO_AMT.txt
    $ cat $HOME/coconut_JNLSNO_AMT.txt
    1 1
    2 2
    3 3
    4 4 6
    5 5

## 4.4. ����ѹ��

### 4.4.1. �����ȣ������ӣ�

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

ֹͣ����

    $ ps -ef | grep -w coconut | awk '{if($3==1)print $2}' | xargs kill

# 5. ��¼A.���������в���

����������ִ��coconut����ʾ���в�����ʾ

    $ coconut
    coconut v0.0.7.0
    Copyright by calvin 2017
    USAGE : coconut -M ( SEQUENCE | LIMITAMT ) [ -l (listen_ip) ] -p (listen_port) [ -c (processor_count) ] [ --loglevel-(debug|info|warn|error|fatal) ] [ --cpu-affinity (begin_mask) ]
                    global serial service :
                        --reserve (reserve) --server-no (server_no)
                    global limit-amt service :
                        --limit-amt (amt) --export-jnls-amt-pathfilename (pathfilename)

-M ( SEQUENCE | LIMITAMT ) : ����ģʽ *SEQUENCEȫ�����кŷ�������LIMITAMT ȫ�ֶ�ȹ�����*<br>
-p (listen_port) : �����˿�<br>
-c (processor_count) : ��������������ȫ�ֶ�ȹ�����ģʽĿǰֻ֧�ֵ�����<br>
--loglevel-(debug|info|warn|error|fatal) : ��־�ȼ���Ĭ��warn�ȼ�����־�ļ������$HOME/log/coconut.log<br>

ȫ�����кŷ����� ����ģʽ<br>
--reserve (reserve) �� ����ֵ��������ҵ������<br>
--server-no (server_no) �� ���������<br>

ȫ�ֶ�ȹ����� ����ģʽ<br>
--limit-amt (amt) : �ܶ��<br>
--export-jnls-amt-pathfilename (pathfilename) : ��������󵼳�������ˮ�ļ�<br>

# 6. ���

coconutʹ�õ������ߵ�������Դ��ĿiLOG3,fasterhttp,tcpdaemon��

coconutȫ��Դ���й��� [��Դ�й�����](http://git.oschina.net/calvinwilliams/coconut) �� [github](http://github.com/calvinwilliams/coconut)���������ʻ������ͨ�� [��������](calvinwilliams@163.com) �� [GMAIL����](calvinwilliams.c@gmail.com) ��ϵ�����ߡ�

��лʹ�� :)
