# httpfake

Httpfake is a program that demnostrate how to hijack http package and response a advertisement to browser.
httpfake 演示http数据协议过程，涉及到数据包采集，tcp协议包构造等技术点。

## Install
```shell
#安装依赖
yum -y install libpcap-dev 
    
#编译
wget https://github.com/spkettas/httpfake/archive/master.zip
unzip master.zip
cd master
make
``` 
    
## Usage(需要root权限启动）：
```shell
# 启动web服务
go run test/web_server.go

# 启动劫持服务
# ./httpfake 网卡名 采集类型
./httpfake eth0 1
```

## Example
* 劫持前：
![劫持前](https://github.com/spkettas/httpfake/blob/master/screenshot/hibefore.png "Before")

* 劫持后：
![劫持后](https://github.com/spkettas/httpfake/blob/master/screenshot/hiafter.png "After")

## At last
更高效的采集方式，可考虑PF_RING，DPDK等零拷贝库。

