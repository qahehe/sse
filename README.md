# SSE方案

这是我即将投稿的文章的代码，里面是对比方案和我的方案的C++实现

使用方法:

```
cd fast/sample
make 即可

编译完成后运行对应的搜索、更新就行，数据集自己处理，然后修改里面的地址就行！
./rpc_server ./sdb 4
./update ./test 4
./search ./test 4

前提条件：
1.grpc :直接下载最新版的grpc
2.rocksdb: 5.7.3版本
3.cryptopp 密码学库
4.boost c++库
5.cmake :3.17.5
```

