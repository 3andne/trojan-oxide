# The Speed Of Lite —— Lite-Tls Specification

## 术语定义

### TLS Packet Specification

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
* ...

其中，0x14和0x16会在握手过程中被使用，而0x17则是数据传输使用的类型，也就是可以被直接转发的包类型。

### 终端定义

* `user` - 用户
* `client` - 代理客户端
* `server` - 代理服务端
* `target` - 目标网站

### 其他术语

`一手包`和`二手包`：从`user/target`那里直接获得的包是`一手包`，从`server/client`那里获得的包是`二手包`。例如，对于`client`而言，从`user`发来的包是`一手包`，从`server`发来的包是`二手包`。

## 握手流程

```
  --->: tcp traffic
  ===>: tls over tcp traffic
  ####################################################################
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
### 注释：

1. active side: 第二个收到`一手0x17`的endpoint进入active mode
2. passive side: 收到`0xff`的endpoint进入passive mode
3. active side会把收到的0x17先缓存起来，在0x17之前、往往有与尚未发送的0x16/0x14包，我们把`0xff`包附在这些pending包的尾部，将这些包一起发往passive side，表示之后随时可以退出tls隧道
4. passive side收到`3`发过来的包之后，会验证`0xff`（之后丢弃），并把它前面的包缓存起来，等0x17到达后，一同发给`user`，否则会导致`user`（浏览器）因为收到的包不完整而出现错误。
5. passive side验证完`0xff`后，会返回一个`0xff`，表示自己已经不会再通过tls隧道接收数据，之后便退出`tls`隧道
6. 当active side收到返回的`0xff`后，便也退出tls隧道
7. 之后active side和passive side之间便通过tcp直接通信，active side把之前缓存的`0x17`发给passive side，passive side收到`0x17`后，连同之前缓存的包一起一次性发给`user`。之后整个过程结束。

