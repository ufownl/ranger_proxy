# ranger_proxy
**ranger_proxy**是一个SOCKS5代理服务器的实现。

## 安装
在完成所有依赖项的安装后，执行以下命令即可完成安装：
```
mkdir build
cd build
cmake ..
make
make install
```

## 依赖项
* 一个支持C++11标准的编译器
  * GCC >= 4.8
  * Clang >= 3.2
* [CMake](http://www.cmake.org)
* [C++ Actor Framework](https://github.com/actor-framework/actor-framework) (develop分支)

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

