"""
PDFium PDF Library Knowledge Base

PDFium是Chrome的PDF渲染引擎，处理PDF文档的解析和显示。
"""

PDFIUM_OVERVIEW = """
# PDFium PDF Library Overview

PDFium是Google开源的PDF渲染库，用于Chrome的PDF查看功能。

## 核心功能
1. **PDF解析**: 文档结构、对象解析
2. **页面渲染**: 文本、图形、图像
3. **JavaScript**: PDF内嵌JS执行
4. **表单处理**: AcroForm、XFA表单
5. **注释**: 批注、标记

## 关键目录
- `third_party/pdfium/core/`: 核心PDF解析
- `third_party/pdfium/fpdfsdk/`: SDK接口
- `third_party/pdfium/fxjs/`: JavaScript引擎
- `third_party/pdfium/xfa/`: XFA表单支持

## PDF文档结构
```
PDF文件
├── Header (版本信息)
├── Body (对象)
│   ├── 页面对象
│   ├── 字体对象
│   ├── 图像对象
│   └── 流对象
├── Cross-Reference Table (对象索引)
└── Trailer (入口点)
```
"""

PDFIUM_PARSING = """
# PDFium 解析机制

## 对象类型
- **Boolean**: true/false
- **Integer**: 整数
- **Real**: 浮点数
- **String**: 字符串 (literal/hex)
- **Name**: 名称对象
- **Array**: 数组 [obj1 obj2 ...]
- **Dictionary**: 字典 << /Key value >>
- **Stream**: 流数据
- **Null**: 空对象
- **Indirect Reference**: 间接引用 (n 0 R)

## 关键解析类
- **CPDF_Parser**: PDF文件解析器
- **CPDF_Document**: 文档对象
- **CPDF_Page**: 页面对象
- **CPDF_Object**: 基础对象类

## 流处理
```
压缩流 → 过滤器链 → 解压数据
常见过滤器:
- FlateDecode (zlib)
- ASCIIHexDecode
- ASCII85Decode
- LZWDecode
- DCTDecode (JPEG)
- JPXDecode (JPEG2000)
- CCITTFaxDecode
```
"""

PDFIUM_VULNERABILITY_PATTERNS = """
# PDFium 常见漏洞模式

## 1. 对象解析漏洞

### 模式
- 畸形对象结构
- 循环引用导致栈溢出
- 对象类型混淆

### 触发示例
```
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R
   /Contents 4 0 R
   /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /Length 9999999999 >>  %% 畸形长度
stream
...恶意数据...
endstream
endobj
```

## 2. 图像处理漏洞

### 模式
- 嵌入图像解码错误
- JPEG/JPEG2000解析问题
- 颜色空间处理错误

### 触发示例
```javascript
// 通过embed标签加载PDF
let embed = document.createElement('embed');
embed.type = 'application/pdf';
embed.src = 'malicious.pdf';
document.body.appendChild(embed);
```

## 3. JavaScript引擎漏洞

### 模式
- PDF内嵌JS执行
- API滥用
- 对象生命周期问题

### PDF内JS触发
```
/OpenAction << /S /JavaScript /JS (
    app.alert("Hello");
    // 恶意JavaScript代码
) >>
```

## 4. 字体处理漏洞

### 模式
- 嵌入字体解析错误
- CFF/TrueType解析问题
- 字形渲染溢出

### 常见位置
- Type1字体解析
- CID字体处理
- OpenType特性

## 5. XFA表单漏洞

### 模式
- XFA XML解析错误
- 脚本执行问题
- 表单布局计算

### 结构示例
```xml
<xfa:datasets>
    <xfa:data>
        <!-- 恶意XFA数据 -->
    </xfa:data>
</xfa:datasets>
```

## 6. 注释处理漏洞

### 模式
- 注释对象解析
- 富文本处理
- 附件处理

### 触发位置
- /Annots 数组
- /AP (外观流)
- /RichMedia
"""

PDFIUM_DEBUGGING = """
# PDFium 调试技术

## 调试工具
```bash
# pdfium_test 独立测试工具
./pdfium_test malicious.pdf

# Chrome中测试
./chrome --no-sandbox file:///path/to/malicious.pdf
```

## 关键源文件
- `core/fpdfapi/parser/cpdf_parser.cpp`: 解析器
- `core/fpdfapi/page/cpdf_page.cpp`: 页面处理
- `core/fxcodec/`: 图像编解码
- `fxjs/cjs_*.cpp`: JavaScript绑定

## 构造测试PDF
```python
# 使用Python构造PDF
pdf = b'''%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer << /Size 4 /Root 1 0 R >>
startxref
196
%%EOF'''

with open('test.pdf', 'wb') as f:
    f.write(pdf)
```

## ASAN错误类型
- `heap-buffer-overflow`: 堆溢出
- `heap-use-after-free`: UAF
- `stack-buffer-overflow`: 栈溢出
- `SEGV on unknown address`: 空指针/野指针
"""

PDFIUM_EXPLOITATION = """
# PDFium 利用技术

## 通过JavaScript利用
```javascript
// PDF内嵌JavaScript
// 获取app对象
var doc = this;
var app = doc.app;

// 触发漏洞操作
doc.getField("fieldname");
doc.addAnnot({...});
```

## 堆喷射
```javascript
// 在PDF JS中喷射
var spray = [];
for (var i = 0; i < 10000; i++) {
    spray.push(new Array(0x1000).fill(0x41414141));
}
```

## 信息泄露
```javascript
// 通过对象属性泄露
var obj = doc.getAnnot(0, "name");
console.println(obj.toString());  // 可能泄露地址
```

## 触发方式
1. **直接打开PDF**: `file:///path/to/poc.pdf`
2. **embed/object标签**: `<embed src="poc.pdf" type="application/pdf">`
3. **iframe**: `<iframe src="poc.pdf"></iframe>`
4. **PDF.js回退**: 某些情况使用JS渲染

## 沙箱考虑
- PDFium运行在renderer进程
- 需要沙箱逃逸才能完全利用
- 或结合其他漏洞链
"""


def get_pdfium_knowledge() -> str:
    """获取完整的PDFium知识库"""
    return "\n\n".join([
        PDFIUM_OVERVIEW,
        PDFIUM_PARSING,
        PDFIUM_VULNERABILITY_PATTERNS,
        PDFIUM_DEBUGGING,
    ])


PDFIUM_KNOWLEDGE_SECTIONS = {
    "overview": PDFIUM_OVERVIEW,
    "parsing": PDFIUM_PARSING,
    "patterns": PDFIUM_VULNERABILITY_PATTERNS,
    "debugging": PDFIUM_DEBUGGING,
    "exploitation": PDFIUM_EXPLOITATION,
}
