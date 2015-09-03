# ranger_proxy
[![Join the chat at https://gitter.im/ufownl/ranger_proxy](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/ufownl/ranger_proxy?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

**ranger_proxy**是一个SOCKS5代理服务器的实现。

## 使用
使用默认设置启动**ranger_proxy**：
```
ranger_proxy
```
查看帮助信息：
```
ranger_proxy --help
Allowed options:
  -H [--host] arg    : set host
  -p [--port] arg    : set port (default: 1080)
  --password arg     : set password (default: empty)
  -G [--gate]        : run in gate mode
  --remote_host arg  : set remote host (only used in gate mode)
  --remote_port arg  : set remote port (only used in gate mode)
  --config arg       : load a config file (it will disable all options above)
  -v [--verbose]     : enable verbose output (default: disable)
  -h [-?,--help]     : print this text
```

## 安装
在完成所有依赖项的安装后，执行以下命令即可完成安装：
```
mkdir build
cd build
cmake ..
make
make test
make install
```

## 依赖项
* 支持C++11标准的编译器
  * GCC >= 4.8
  * Clang >= 3.2
* [CMake](http://www.cmake.org)
* [C++ Actor Framework](https://github.com/actor-framework/actor-framework) (develop分支)
* [OpenSSL](http://www.openssl.org)

## SOCKS5特性支持
**ranger_proxy**目前只支持部分SOCKS5特性。

### 验证方法
- [x] NO AUTHENTICATION REQUIRED
- [ ] GSSAPI
- [ ] USERNAME/PASSWORD

### 请求类型
- [x] CONNECT
- [ ] BIND
- [ ] UDP ASSOCIATE

### 地址类型
- [x] IP V4 address
- [x] DOMAINNAME
- [ ] IP V6 address

