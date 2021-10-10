# The Journey to The Speed of Lite

## Background

在当下主流的代理工具中，trojan系协议在复杂度、速度、稳定性和隐蔽性方面脱颖而出，该协议的基本流程为

```
1. user向代理客户端client发送请求
[user] ---> [client]
        ^ 包含target address

2. client通过一个tls隧道向代理服务器发送password + target address
[user] **** [client] ---> [server]
                      ^ tls secured

3. 代理server认证client，然后建立与目标服务器的链接
[user] **** [client] **** [server] ---> [target]

4. 最终，user通过这条隧道与target交换数据
[user] <--> [client] <--> [server] <--> [target]
                      ^ tls secured
```

## Double encryption

仔细观察上述流程，client和server之间已经建立了一个tls隧道，而当下，user和target之间大部分的通讯也是基于tls加密的，这就使得在传输数据的时候，client和server之间的加密变得没有意义

对此，我们探索了Lite-Tls机制，其核心思路非常简单，当user和target使用tls通讯并开始传输数据的时候，client和server一同退出tls隧道 —— 反正在监听者看来，这都是tls传输，没有任何区别。

## The pain starts

### What can we transfer without encryption?

我们首先需要解决的问题是，哪些东西是可以直接被转发无需加密的？直觉告诉我们，tls握手阶段应该是不能直接转发的，那么具体该如何区分呢？

我们需要简单了解一下tls(1.2/1.3)的包定义:
```
+-------------+-------------+--------+----------+
| Record Type |   version   | Length | Payload  |
+-------------+------+------+-------------------+
|      1      | 0x03 | 0x03 |   2    | Variable |
+-------------+------+------+--------+----------+
```

根据标准，包头的Record Type有
* 0x14: Change Cipher Spec
* 0x16: Handshake
* 0x17: Application Data

其中，0x14和0x16会在握手过程中被使用，而0x17则是数据传输使用的类型，也就是可以被直接转发的包类型。

### A First Try

TLS标准规定，0x14 - Change Cipher Spec的含义是，该包之后的包全部使用协商好的加密方法进行加密，

* 终端定义
   * `user` - 用户
   * `client` - 代理客户端
   * `server` - 代理服务端
   * `target` - 目标网站
* `一手包`和`二手包`：从`user/target`那里直接获得的包是`一手包`，从`server/client`那里获得的包是`二手包`。例如，对于`client`而言，从`user`发来的包是`一手包`，从`server`发来的包是`二手包`。

```
  ---- 0x17 ---> [client]                 [server]

                 [client] ==== 0x17 ====> [server]
                                ^ the first 0x17 in this stream

                    <== ...some traffics... ==>

                 [client]                 [server] <-{..., 0x17}--
                                             ^ active side *1

                 [client] <={..., 0xff}== [server]{0x17} < cached *3
     passive side *2 ^              ^ a 0xff is appended

                 [client]{...}            [server]{0x17}
                           ^ cached *4

                 [client]{...} == 0xff => [server]{0x17}
                                    ^ a 0xff is returned *5

                 [client]{...}            [server]{0x17}
                    ^ quit tls               ^ quit tls *6

                 [client] <- Plain Tcp -> [server]
                 
                 [client]{...} <- 0x17 -- [server]

 <-{..., 0x17}-- [client]                 [server]
                              ......
```
注：
1. active side: 第二个收到`一手0x17`的endpoint进入active mode
2. passive side: 收到`0xff`的endpoint进入passive mode
3. active side会把收到的0x17先缓存起来，在0x17之前、往往有与尚未发送的0x16/0x14包，我们把`0xff`包附在这些pending包的尾部，将这些包一起发往passive side，表示之后随时可以退出tls隧道
4. passive side收到`3`发过来的包之后，会验证`0xff`（之后丢弃），并把它前面的包缓存起来，等0x17到达后，一同发给`user`，否则会导致`user`（浏览器）因为收到的包不完整而出现错误。
5. passive side验证完`0xff`后，会返回一个`0xff`，表示自己已经不会再通过tls隧道接收数据，之后便退出`tls`隧道
6. 当active side收到返回的`0xff`后，便也退出tls隧道
7. 之后active side和passive side之间便通过tcp直接通信，active side把之前缓存的`0x17`发给passive side，passive side收到`0x17`后，连同之前缓存的包一起一次性发给`user`。之后整个过程结束。