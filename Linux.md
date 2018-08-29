# Linux

		/*                     _ooOoo_
		 *                    o8888888o
		 *                    88" . "88
		 *                    (| -_- |)
		 *                    O\  =  /O
		 *                 ____/`---'\____
		 *               .'  \\|     |//  `.
		 *              /  \\|||  :  |||//  \
		 *             /  _||||| -:- |||||-  \
		 *             |   | \\\  -  /// |   |
		 *             | \_|  ''\---/''  |   |
		 *             \  .-\__  `-`  ___/-. /
		 *           ___`. .'  /--.--\  `. . __
		 *        ."" '<  `.___\_<|>_/___.'  >'"".
		 *       | | :  `- \`.;`\ _ /`;.`/ - ` : | |
		 *       \  \ `-.   \_ __\ /__ _/   .-` /  /
		 *  ======`-.____`-.___\_____/___.-`____.-'======
		 *                     `=---='
		 *  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
		 *              佛祖保佑       永无BUG
		 */

#### 连接局域网内 虚拟机下的 linux系统
> 1. 虚拟机的网络连接设置成桥接模式
> 2. cp /ect/sysconfig/network-scripts/ifcfg-ens33 ifcfg-eth0
> 3. vim ifcfg-eth0 加入IPADDR0=虚拟机所在主机的IP(要一致) 修改ONBOOT=yes(ifconfig就能看到IP)
> 4. service network restart (重启后 ifconfig 就会看到分配的IP 连接这个IP就能连接到虚拟机)

#### VMware 安装 linux 注意事项
> 1. 网络连接
> - 桥接:占用真实机的IP(可以和局域网内的主机通信，下面两个只能和本机进行通信)
> - NAT:使用 VMnet8 这个虚拟网卡 (能上网)
> - 仅主机模式:使用 VMnet1 这个虚拟网卡 (不能上网)
>
> 2. 快照(保存虚拟机的状态 用于恢复错误操作之前的状态)
> 3. f2 进入boot 修改cd-rom顺序为第一 (+ 号就会往上移动)

#### yum 安装各种软件、服务
> yum install iptables-services (安装防火墙)

#### 上传网站到服务器
> scp -r [local_dir] user@host:/remote

#### 安装 java、git、maven、tomcat、mysql
> yum install java
>
> yum install git (git version)
>- 初始化设置
> - 生成授权证书( ssh -keygen -t rsa -C "email 地址")
> 确认证书是否已经在系统中生成( cd ~/.ssh/ ls 如果有两个文件)
> - 公钥证书注册到 github
> - 验证 git 配置是否正确(ssh git@github.com)
>
> wget maven tar.gz 下载地址 tar -zxvf 解压
> - 在系统属性文件中添加 maven 参数设置
> 1. vim /etc/profile
> 2. export MAVEN_HOME=(maven 的安装的全路径)
> 3. export PATH=\$MAVEN_HOME/bin:$PATH (把 maven 的 bin 文件夹 加入系统 path)
> 4. . /etc/profile (加载更新后的系统配置)
> - mvn -version(验证)
>
> wget tomcat tar.gz 下载地址  tar -zxvf 解压
>- 给 tomcat 可执行文件赋予执行权限
> 进入 tomcat 安装路径 chmod a+x -R *(路径下所有文件赋予可执行权限)
>- 修改端口 vim conf/server.xml
>- 开启 tomcat bin/startup.sh

> wget mysql-5.7.22-linux-glibc2.12-x86_64.tar.gz
> - groupadd mysql 添加 mysql 组，useradd -r -g mysql mysql 添加 mysql 用户 (系统用户，不可用于登录)
> - tar zxvf 解压
> - chown -R mysql mysql/ 更改所属的用户、chgrp -R mysql mysql/ 更改所属的组
> - bin/mysqld --initialize --user=mysql --basedir=/usr/local/mysql/ --datadir=/usr/local/mysql/data 初始化数据库
> - cp support-files/mysql.server /etc/init.d/mysqld 安装服务到系统 (service mysqld start)
> - chown -R mysql:mysql /var/log/mariadb (赋予权限)
> - chown -R mysql:mysql /var/run/mariadb/
> - chown -R mysql:mysql /var/lib/mysql/
> - my.cnf 要配置 client 的 socket

#### 防火墙 (centos)
> - systemctl start firewalld
> - firewall-cmd --zone=public --add-port=xxx/tcp --permanent (开启某个端口，永久生效)
> - firewall-cmd --reload (重启)
> - firewall-cmd --zone=public --query-port=xxx/tcp(查看端口是否添加成功)

#### ssh
> - 修改端口就按照上面防火墙步骤，添加端口，重启防火墙 
> - systemctl restart sshd.service (重启)
> -  scp -r test/ root@host:/root (上传 test 文件夹到另一台主机的 /root 下)
> - scp -r root@host:/root/testLoad . (下载另一台主机的 /root/testLoad 文件夹到本地主机当前目录)

#### 修改 hostname
> hostnamectl --static set-hostname 新的主机名

#### 同步目录
> rsync -r dir1 root@anthorHost:


####  top 命令(查看系统进程状况)
> 查看系统状况(类似 windows 任务管理器的进程)
> buffer(缓冲) 加快数据写入速度
> cache(缓存、内存) 加快数据读取速度
> 硬盘速度低于内存，内存速度低于CPU

#### kill 命令(杀死进程)(能正常关闭就不用kill)
> kill -HUP(1) [进程ID]  (平滑重启，例：apache重启 不会把apache已经登录的用户终止掉)
> w (查看当前登录用户)
> killall [option][进程名] (杀死某个服务的所有进程)
> pkill -t 终端号  (踢出用户更加准确)  [option][进程名] (按照进程名终止进程)

#### 把进程放入后台
> 1. & 符号 (把命令放入后台，在后台执行)
> 2. ctrl + z 快捷键 (放在后台暂停)
> 3. jobs -l(显示 PID) (查看后台正在执行的工作)( + 号表示最新一个放入后台的，- 号表示最靠近最新放入后台的)
>**把后台暂停的工作恢复到前台：**
> fg %工作号
> **把后台暂停的工作恢复到后台执行：**
> bg %工作号
> **后台命令脱离终端**
> nohup [命令] &

#### 查找文件命令
> - find / -name w  -d (在根目录下查找文件夹名称叫 w的目录地址。)
> 1. -type 查找的内容类型：f 文件、d 目录。
> 2. -exec find后执行其他命令： ``` '{}' ``` 代表find返回文件名  ``` ';' ``` 结尾。
> 3. -n 显示 
> 4. -print 打印匹配项的文件名
> - locate (从系统 db 中查找，默认一天 updatedb 一次，需要查找新文件就 updatedb)

#### 分页查看文件内容
> - less
> - 常用：j 向上、k 向下、/(查找文本)、n 跳到文本下一处、g 文档顶部、G 文档尾部、q 退出

##### 文件描述符
> - 0 ( stdin ，标准输入文件，键盘输入保存到这个文件)
> - 1 ( stdout，标准输出文件；这个文件包括下面那个文件的内容直接输出到屏幕中，不会保存到硬盘)
> - 2 ( stderr ，标准错误输出文件)

#### 内容重定向
> ``` > ``` (输出重定向：前面的内容输出到后面的文件，替换内容)
> ``` >> ``` (追加内容)
> ``` < ``` (输入重定向：后面的内容取出到前面，可以是 grep less < foo.txt)
> ``` 2> ``` (标准错误输出重定向)

#### 权限
> - 文件默认权限
> 1. 文件默认没有执行权限，必须手工赋予，默认最大为666
> 2. 默认权限值为 666换算成字母 - umask的后3位的值转字母，算出644(实际上是逻辑与相减)
> - 目录默认权限
> 1. 最大为777，第2点与文件类似
> - r (reading premission) 4 (cat、more、head、tail、ls)
> - w (writing premission) 2 (vi vim echo、touch rm mv cp)
> - x (executing premission) 1 (cd)
	> - -(文件类型)rw-(拥有者权限)rw-(所属组权限)r--(world 权限) 1(硬链接的数量) root(拥有者) root(所属组) 0(文件大小) Aug...(最后修改时间)
> 1. 第1位代表文件类型 ( - 普通文件、l 符号链接(软链接)、d 目录)
> - chmod -R(递归) +-ugoa=(增加删除用户，组，其他人，全部的权限) ，修改文件权限(推荐使用数字组合)
> - chown (修改文件所有者)、chown root:root (同时修改拥有者和所属组)
> - chgrp (修改所属组)
> - umask (默认权限) 
> 1. root (0022，第一位0：文件特殊权限、022：文件默认权限)
> 2. 普通用户 (0002，)

#### 系统定时任务
> PS:服务名后面的d 是demon(守护进程 即安装成系统服务) 例：httpd
>1.at(一次性定时任务)
> - chkconfig --list | grep atd  (at服务是否安装)
> - service atd start (at服务启动)
> - at [选项] 时间 -c (查看具体工作内容) -m(发送email给执行at命令的用户)
> - atq(查看已存在定时任务)
>
>2.crontab(循环定时任务)
>- chkconfig --list | grep cron (服务是否安装)
>- 视频看到 2:53
>
>3.crontab 系统定时任务
>- 把脚本复制到 /etc/cron.{daily,weekly,monthly} 任意一个(**推荐**)
>- 修改 /etc/crontab

>4.anacron 检测周期(一年、七天、一个月)
>- /var/spool/anacron/cron.{daily,weekly,monthly} (用于记录上次执行 cron 时间的文件，和当前时间做比较，若差值超过了 anacron 的指定差值，证明 cron 任务需要执行了)
>

#### 网络
> OSI 7 层模型：
> 1. 物理层 (bit，设备之间比特流的传输、物理接口、电气特性等)
> 2. 数据链路层 (帧：mac 地址访问媒介，错误检测与修正)
> 3. 网络层 (报文：保存 ip 地址，提供逻辑地址、选路)
> 4. 传输层 (TPDU，可靠与不可靠的传输、传输前的错误检测、流控 )
> 5. 会话层 (SPDU，应用会话的管理、同步)
> 6. 表示层 (PPDU，数据形式，特定功能实现：加密、压缩等)
> 7. 应用层 (APDU，用户接口 )

> TCP (传输控制协议) /IP 4层模型：
> 1. 网络接口层 (7层模型：1、2，地址解析协议 ARP 工作在这里，即2层)
> 2. 网际互联层 (3)
> 3. 传输层 (4)
> 4. 应用层 (5、6、7)

> 交换机：一个局域网内交换数据的设备
> 路由器：不同网段之间进行通信


#### IP
> - ipv4 四个字节(4段,例如:127.0.0.1)代表一个ip，每个字节 8bit(8位2进制，2进制最大的十进制255)
> - 127.0.0.1 (127 代表网络号(ip)，0 0 1 代表主机号(ip))
> 1. A类网 (网络段占一个字节的(第一位相同代表一个网段)，1-126；私有IP范围：10.0.0.0 -- 10.255.255.255)
> 2. B类网 (网络段占两个字节(前两位相同代表一个网段)，128-191；私有IP范围：172.16.0.0 -- 172.31.255.255)
> 3. C类网 (网络段占三个字节(前三位相同代表一个网段)，192-223；私有IP范围：192.168.0.0 -- 192.168.255.255)
> - 子网掩码 (255.255.255.0 ：255 对应IP的位数来区分网段，0对应的IP位区分同一网段下的不同主机)
> - 不同网络之间通过路由器进行访问，同一个网络之间的通信使用交换机。
> - IP 地址和子网掩码相与得到的就是网络地址
> - 如果不使用标准的掩码，将掩码转为二进制，通过0的位数算出主机段
> - ``` =========================================== ```
> - 配置IP：
> 1. ifconfig 临时配置IP地址 
> ``` ifconfig eth0(网卡名) 192.168.3.154(ip addr) netmask 255.255.255.0 ```
> 2. setup 永久配置IP地址 (redhat 系列特有)
> 3. 修改网络配置文件 ：``` USERCTL=no ``` 不允许非 root 用户控制此网卡、

#### 端口
> - 常见端口号：
> 1. FTP (文件传输协议) 20(数据传递) 21(登录、传输命令)
> 2. SSH (安全 shell 协议) 22
> 3. telnet (远程登录协议、禁用，数据明文传输不安全) 23
> 4. DNS (域名解析系统，TCP/UDP) 53
> 5. http (超文本传输协议) 80
> 6. SMTP (简单邮件传输协议，发信) 25
> 7. POP3 (邮局协议3代，收信) 110
> - 查看本机启用端口 ``` netstat -an ```
> 1. -a 查看所有连接和监听端口、 -n 显示IP地址和端口号，而不显示域名和服务名 

#### 网关
> - 作用：
> 1. 网关在所有内网计算机访问不是本网段的数据报时使用
> 2. 网关负责把内网IP转公网、把公网IP转内网  
> - ``` route -n ``` 查看路由网关 ，等同于 ``` netstat -rn ``` 


####  网卡
> - lo (loopback：本地回环网卡)
> - ``` ifdown 网卡设备名``` 禁用网卡
> - ``` ifup 网卡设备名 ``` 开启网卡
> - netstat 查看网络状态
> 1. -t 列出 tcp 协议端口
> 2. -u 列出 UDP 协议端口
> 3. -n 不使用域名和服务名 ，使用 ip 和 端口
> 4. -l 仅列出在监听状态的网络服务
> 5. -a 列出所有的网络连接 

#### 路由追踪
> ``` traceroute 域名或 ip ```

### 抓包
> ``` tcpdump -i eth0 -nnX(x代表16进制拆分包) port 21 ``` 抓取 eth0 网卡上21端口的包


#### shell 编程
> - source 当前 terminal 中运行 shell












### docker
命令：
- docker pull 获取 image
- docker build 创建 image
- docker images 列出 image
- docker run 运行 container
- docker ps 列出 container

dockerfile：
- FROM alpine:latest (images库(基础镜像库)，非常小)
- MAINTAINER flash (告知他人这个镜像谁写的)
- CMD echo 'hi flash'

dockerfile 命令：
- FROM 基础镜像
- RUN 命令
- ADD 添加文件
- COPY 拷贝文件
- CMD 执行命令
- EXPOSE 暴露端口
- WORKDIR 指定路径
- MAINTAINER 维护者
- ENV 设定环境变量
- ENTRYPOINT 容器入口
- USER 指定用户
- VOLUME 容器挂载的卷 




#### 搭建 shadowsocks&shadowsocksr

- shadowsocks环境搭建
1. curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py  (下载这个 py脚本)
2. python get-pip.py (运行脚本)
3. pip install shadowsocks (安装服务端)
 4. vim /etc/shadowsocks.json
5. ssserver -c /etc/shadowsocks.json -d start (启动命令，-d 后台操作，-d 后面执行的操作)
6. vim  /etc/rc.d/rc.local  添加 /usr/bin/ssserver -c /etc/shadowsocks.json -d start(开机启动)
7. chmod +x /etc/rc.d/rc.local (赋予执行权限，centos7貌似要抛弃这个文件)
 8. shadowsocks.json 配置如下

	{
	"server":"ip",
	"port_password":{
		"port1":"password",
		"port2":"password",
		"port3":"password"
	},
	"local_port":1080,
	"timeout":60,
	"method":"aes-256-cfb",
	"workers":1,
	"fast_open":false
	}

- shadowsocksr环境搭建
1. yum -y install git
2. yum -y install python-pip
3. git clone https://github.com/aihoom/shadowsocksr.git 或 https://github.com/hao35954514/shadowsocksR-b.git
4. 项目根目录执行 bash initcfg.sh
5. sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" userapiconfig.py (替换API接口（原 sspanelv2 改为 mudbjson）)

	参数说明: 
	python mujson_mgr.py -a|-d|-e|-c|-l [选项( -u|-p|-k|-m|-O|-o|-G|-g|-t|-f|-i|-s|-S )]
	     
	操作:
	  -a ADD               添加 用户
	  -d DELETE            删除 用户
	  -e EDIT              编辑 用户
	  -c CLEAR             清零 上传/下载 已使用流量
	  -l LIST              显示用户信息 或 所有用户信息
	     
	选项:
	  -u USER              用户名
	  -p PORT              服务器 端口
	  -k PASSWORD          服务器 密码
	  -m METHOD            服务器 加密方式，默认: aes-128-ctr
	  -O PROTOCOL          服务器 协议插件，默认: auth_aes128_md5
	  -o OBFS              服务器 混淆插件，默认: tls1.2_ticket_auth_compatible
	  -G PROTOCOL_PARAM    服务器 协议插件参数，可用于限制设备连接数，-G 5 代表限制5个
	  -g OBFS_PARAM        服务器 混淆插件参数，可省略
	  -t TRANSFER          限制总使用流量，单位: GB，默认:838868GB(即 8PB/8192TB 可理解为无限)
	  -f FORBID            设置禁止访问使用的端口
	                       -- 例如：禁止25,465,233~266这些端口，那么这样写: -f "25,465,233-266"
	  -i MUID              设置子ID显示（仅适用与 -l 操作）
	  -s value             当前用户(端口)单线程限速，单位: KB/s(speed_limit_per_con)
	  -S value             当前用户(端口)端口总限速，单位: KB/s(speed_limit_per_user)
	     
	一般选项:
	  -h, --help           显示此帮助消息并退出

	# 添加命令  
	端口：3333
    密码：lighti.me
    加密方式：chacha20
    协议插件：auth_aes128_md5
    协议参数：5 （同一时间链接设备数）
    混淆插件：tls1.2_ticket_auth_compatible(兼容原版)
    单线程限速：500KB/s
    端口总限速：1000KB/s
    总流量：10GB
    禁止访问端口：25,465,233-266
    # 示例命令
	python mujson_mgr.py -a -u lightime -p 3333 -k lighti.me -m chacha20 -O auth_aes128_md5 -G 5 -o tls1.2_ticket_auth_compatible -s 500 -S 1000 -t 10 -f "25,465,233-266" 
	# ======== 监控命令
	// 显示当前链接服务器的用户的SS端口
	netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $4}' |sort -u
	# 显示当前链接服务器的用户的SS端口数量
	netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $4}' |sort -u |wc -l
	
	# 显示当前所有链接SS的用户IP
	netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u
	# 显示当前所有链接SS的用户IP数量
	netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |wc -l



>/ssr+tor 
>https://sunny856.xyz/1664