# 安全通信样例代码

## 源文件结构

```
├── client_main.cpp
├── client_main_tcp.cpp
├── server_main.cpp
├── server_main_tcp.cpp
├── test_include 
│   ├── test_tcp_client.h 
│   ├── test_tcp_common.h 
│   └── test_tcp_server.h 
└── test_utils 
    ├── test_tcp_client.cpp 
    ├── test_tcp_common.cpp 
    └── test_tcp_server.cpp
```

## 文件说明

| 文件                                                    | 说明               |
|-------------------------------------------------------|------------------|
| [client_main.cpp](client_main.cpp)                    | 基于PSK的安全通信客户端主程序 |
| [client_main_tcp.cpp](client_main_tcp.cpp)            | tcp通信客户端主程序，参照组  |
| [CMakeLists.txt](CMakeLists.txt)                      | cmake编译配置        |
| [server_main.cpp](server_main.cpp)                    | 基于PSK的安全通信服务端主程序 |
| [server_main_tcp.cpp](server_main_tcp.cpp)            | tcp通信服务端主程序，参照组  |
| [test_tcp_client.h](test_include/test_tcp_client.h)   | 样例代码TCP客户端头文件    |
| [test_tcp_common.h](test_include/test_tcp_common.h)   | 样例代码TCP公共头文件     |
| [test_tcp_server.h](test_include/test_tcp_server.h)   | 样例代码TCP服务端头文件    |
| [test_tcp_client.cpp](test_utils/test_tcp_client.cpp) | 样例代码TCP客户端实现     |
| [test_tcp_common.cpp](test_utils/test_tcp_common.cpp) | 样例代码TCP公共实现      |
| [test_tcp_server.cpp](test_utils/test_tcp_server.cpp) | 样例代码TCP服务端实现     |

<code>client_main.cpp</code>是客户端的程序，<code>server_main.cpp</code>是服务端的程序，
里面依赖了test_include和test_utils的文件。<br/>
<code>client_main_tcp.cpp</code>是TCP客户端的程序，<code>server_main_tcp.cpp</code>是TCP服务端的程序，
里面依赖了test_include和test_utils的文件。<br/>
编译服务端和客户端，先启动服务端再启动客户端

> 注意
> > 样例代码中每次传输内容固定，重复传输1000次，用于对比参照使用TLS和不使用TLS

## 编译

### 随SCF编译

1.修改[CMakeLists.txt](../CMakeLists.txt)文件

```cmake
# 增加编译sample目录
add_subdirectory(sample)
```

2.编译
<br/>需要提前下载依赖，参考[README.md](../README.md))

```shell
sh build.sh cicd_default
```

3.运行

```shell
# 启动服务端
# 参数说明
# [tlsFlag] 初始化TLS，目前仅支持openssl
# [libPath] TLS动态库路径
# [serverIp] 服务端ip
# [port] 服务端监听端口
./build/sample/server_main openssl /opt/openssl3012/ 0.0.0.0 9445
# 启动客户端
# 参数说明
# [tlsFlag] 初始化TLS，目前仅支持openssl
# [libPath] TLS动态库路径
# [serverIp] 服务端ip
# [port] 服务端监听端口
./build/sample/client_main openssl /opt/openssl3012/ 0.0.0.0 9445
```

> 注意
> > 调用前需要确保<code>libscf.so</code>, <code>libboundscheck.so</code>可链接<br>
> > [方案1] 安装SCF模块和libboundscheck模块，参考[README.md](../README.md)<br/>
> > [方案2] 手动指定<code>LD_LIBRARY_PATH</code>eg:<code>export LD_LIBRARY_PATH=SCF_LIB_PATH:
> > LIB_BOUNDS_CHECK_LIB_PATH</code><br/>
> > <code>SCF_LIB_PATH</code>:SCF动态库地址，执行编译后在：<code>{projectRoot}/output/scf/lib64/libscf.so</code><br/>
> > <code>LIB_BOUNDS_CHECK_LIB_PATH</code>:libboundscheck动态库地址，执行编译后在：<code>
> > {projectRoot}/build/deps/lib64/libboundscheck.so</code>

### 单独编译样例代码

1.编译

> 注意
> > 需要安装SCF模块和libboundscheck，参考[README.md](../README.md)

```shell
g++ server_main.cpp test_utils/*.cpp -o server_main -I ./test_include/ -lscf -lboundscheck
g++ client_main.cpp test_utils/*.cpp -o client_main -I ./test_include/ -lscf -lboundscheck
g++ server_main_tcp.cpp test_utils/*.cpp -o server_main_tcp -I ./test_include/ -lboundscheck
g++ client_main_tcp.cpp test_utils/*.cpp -o client_main_tcp -I ./test_include/ -lboundscheck
```

2.运行

```shell
# 启动服务端
# 参数说明
# [tlsFlag] 初始化TLS，目前仅支持openssl
# [libPath] TLS动态库路径
# [serverIp] 服务端ip
# [port] 服务端监听端口
./server_main openssl /opt/openssl3012/ 0.0.0.0 9445
# 启动客户端
# 参数说明
# [tlsFlag] 初始化TLS，目前仅支持openssl
# [libPath] TLS动态库路径
# [serverIp] 服务端ip
# [port] 服务端监听端口
./client_main openssl /opt/openssl3012/ 0.0.0.0 9445
```