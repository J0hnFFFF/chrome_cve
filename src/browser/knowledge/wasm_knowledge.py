"""
WebAssembly (Wasm) Knowledge Base

WebAssembly是一种低级字节码格式，提供接近原生的执行性能。
"""

WASM_OVERVIEW = """
# WebAssembly Overview

WebAssembly (Wasm) 是一种可移植的低级字节码格式，设计用于高性能Web应用。

## 核心特性
1. **二进制格式**: 紧凑、快速解析
2. **沙箱执行**: 内存隔离
3. **确定性执行**: 跨平台一致性
4. **与JS互操作**: 无缝集成

## V8中的Wasm实现
```
Wasm字节码
    ↓
 验证器 (Validator)
    ↓
 ├── Liftoff (基线编译器，快速)
 └── TurboFan (优化编译器，慢但优化)
    ↓
 机器码执行
```

## 关键目录
- `v8/src/wasm/`: Wasm核心实现
- `v8/src/wasm/baseline/`: Liftoff编译器
- `v8/src/wasm/compiler/`: TurboFan Wasm编译
- `v8/src/wasm/module-decoder.cc`: 模块解码

## Wasm提案状态
- **MVP**: 基础功能 (已稳定)
- **SIMD**: 向量指令
- **Threads**: 线程和原子操作
- **Exception Handling**: 异常处理
- **GC**: 垃圾回收集成
- **Tail Calls**: 尾调用优化
"""

WASM_BINARY_FORMAT = """
# Wasm 二进制格式

## 模块结构
```
Module ::= magic version section*

magic   = 0x00 0x61 0x73 0x6D  ("\\0asm")
version = 0x01 0x00 0x00 0x00  (版本1)
```

## Section类型
| ID | Section | 描述 |
|----|---------|------|
| 0  | Custom  | 自定义数据 |
| 1  | Type    | 函数类型签名 |
| 2  | Import  | 导入声明 |
| 3  | Function| 函数声明 |
| 4  | Table   | 表声明 |
| 5  | Memory  | 内存声明 |
| 6  | Global  | 全局变量 |
| 7  | Export  | 导出声明 |
| 8  | Start   | 启动函数 |
| 9  | Element | 表初始化 |
| 10 | Code    | 函数体 |
| 11 | Data    | 数据段 |

## 指令编码
```
指令 ::= opcode immediate*

操作码示例:
0x00 - unreachable
0x01 - nop
0x02 - block
0x03 - loop
0x04 - if
0x0B - end
0x10 - call
0x20 - local.get
0x28 - i32.load
0x36 - i32.store
0x41 - i32.const
0x6A - i32.add
```
"""

WASM_VULNERABILITY_PATTERNS = """
# Wasm 常见漏洞模式

## 1. 模块验证绕过

### 模式
- 畸形模块通过验证
- 类型检查绕过
- 边界检查绕过

### 触发示例
```javascript
// 构造畸形Wasm模块
let bytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6D,  // magic
    0x01, 0x00, 0x00, 0x00,  // version

    // Type section
    0x01, 0x07,  // section id=1, size=7
    0x01,        // 1 type
    0x60,        // func type
    0x02, 0x7F, 0x7F,  // 2 params: i32, i32
    0x01, 0x7F,  // 1 result: i32

    // Function section
    0x03, 0x02,  // section id=3, size=2
    0x01, 0x00,  // 1 function, type index 0

    // Code section with malformed body
    0x0A, 0xFF,  // 畸形大小
    // ... 恶意代码体
]);

try {
    let module = new WebAssembly.Module(bytes);
} catch(e) {
    console.log(e);
}
```

## 2. 编译器漏洞

### 模式
- Liftoff/TurboFan编译错误
- 寄存器分配错误
- 指令生成错误

### 触发示例
```javascript
// 复杂控制流触发编译器bug
let wat = `
(module
    (func (export "f") (param i32) (result i32)
        (local i32 i32 i32 i32)
        ;; 深层嵌套循环
        (block
            (loop
                (block
                    (loop
                        ;; 复杂操作
                        local.get 0
                        i32.const 1
                        i32.add
                        local.set 0
                        br 0
                    )
                )
                br 0
            )
        )
        local.get 0
    )
)`;
```

## 3. 内存访问漏洞

### 模式
- 边界检查消除错误
- 内存增长竞争
- 共享内存问题

### 触发示例
```javascript
let memory = new WebAssembly.Memory({ initial: 1, maximum: 10 });
let module = new WebAssembly.Module(wasmBytes);
let instance = new WebAssembly.Instance(module, { env: { memory } });

// 并发增长和访问
let grow = () => memory.grow(1);
let access = () => instance.exports.readMemory(0xFFFF);

// 竞争条件
Promise.all([grow(), access()]);
```

## 4. 表调用漏洞

### 模式
- call_indirect类型混淆
- 表越界访问
- 表元素类型错误

### 触发示例
```javascript
// WAT with table manipulation
let wat = `
(module
    (table 10 funcref)
    (type $t (func (param i32) (result i32)))

    (func $f1 (type $t) (param i32) (result i32)
        local.get 0
        i32.const 1
        i32.add
    )

    (elem (i32.const 0) $f1)

    (func (export "call") (param i32) (result i32)
        local.get 0
        i32.const 999  ;; 越界索引
        call_indirect (type $t)
    )
)`;
```

## 5. SIMD漏洞

### 模式
- SIMD指令处理错误
- 向量运算溢出
- 未对齐访问

### 触发示例
```javascript
// SIMD操作
let wat = `
(module
    (memory 1)
    (func (export "simd_test")
        i32.const 0
        v128.load          ;; 加载128位向量
        i32.const 16
        v128.load
        i8x16.add          ;; 向量加法
        i32.const 0
        v128.store
    )
)`;
```

## 6. 异常处理漏洞

### 模式
- try/catch块处理错误
- 异常传播问题
- 栈展开错误

### 触发示例
```javascript
let wat = `
(module
    (tag $e (param i32))

    (func (export "throw_catch")
        try
            i32.const 42
            throw $e
        catch $e
            drop
        end
    )
)`;
```

## 7. GC集成漏洞 (新提案)

### 模式
- WasmGC对象管理错误
- JS/Wasm对象交互问题
- 引用类型混淆
"""

WASM_DEBUGGING = """
# Wasm 调试技术

## Chrome调试标志
```bash
--js-flags="--trace-wasm"
--js-flags="--print-wasm-code"
--js-flags="--wasm-lazy-compilation"
--js-flags="--no-wasm-lazy-compilation"
--js-flags="--wasm-tier-up"
--js-flags="--liftoff"
--js-flags="--no-liftoff"
--enable-features=WebAssemblySimd
--enable-features=WebAssemblyThreads
```

## 关键源文件
- `v8/src/wasm/module-decoder.cc`: 模块解码
- `v8/src/wasm/wasm-validator.cc`: 验证器
- `v8/src/wasm/baseline/liftoff-compiler.cc`: Liftoff
- `v8/src/wasm/compiler/wasm-compiler.cc`: TurboFan

## 调试工具
```javascript
// 检查Wasm支持
console.log(WebAssembly.validate(bytes));

// 反汇编 (需要工具)
// wasm2wat module.wasm -o module.wat
// wasm-objdump -d module.wasm
```

## 构造测试模块
```javascript
// 使用wabt工具链
// wat2wasm test.wat -o test.wasm

// 或使用JavaScript构造
function createWasmModule(funcBody) {
    return new Uint8Array([
        0x00, 0x61, 0x73, 0x6D,  // magic
        0x01, 0x00, 0x00, 0x00,  // version
        // ... sections
        ...funcBody
    ]);
}
```

## Native调试
```bash
# GDB调试V8
gdb -ex 'r' --args ./d8 --allow-natives-syntax poc.js

# 设置断点
b v8::internal::wasm::ModuleDecoder::DecodeModule
b v8::internal::wasm::LiftoffCompiler::Compile
```
"""

WASM_EXPLOITATION = """
# Wasm 利用技术

## 与V8漏洞结合

Wasm漏洞通常与V8漏洞结合使用:

1. **Wasm触发内存损坏**
2. **通过JS构造exploit primitives**
3. **实现任意读写**
4. **代码执行**

## 内存布局利用
```javascript
// Wasm内存是ArrayBuffer
let memory = new WebAssembly.Memory({ initial: 1 });
let buffer = memory.buffer;
let view = new Uint8Array(buffer);

// Wasm内存可以直接被JS访问
// 如果Wasm有OOB，可以读写JS堆
```

## JIT代码利用
```javascript
// Wasm代码被编译到RWX内存（某些配置）
// 如果能覆盖Wasm代码，可以执行shellcode

let instance = new WebAssembly.Instance(module);
// instance.exports.f 指向编译后的代码
// 通过漏洞覆盖这段代码
```

## 构造addrof/fakeobj
```javascript
// 利用Wasm内存越界
// 读取相邻JS对象地址
// 或伪造JS对象

let wasm_memory = new WebAssembly.Memory({ initial: 1 });
// 如果能OOB访问，可以读写Wasm Memory对象之外的数据
```

## 绕过JIT喷射缓解
```javascript
// Wasm代码更可预测
// 可以构造特定的gadgets
// 用于ROP/JOP链

let wat = `
(module
    (func (export "gadget")
        ;; 构造有用的指令序列
        i32.const 0x41414141
        drop
        i32.const 0x42424242
        drop
    )
)`;
```

## 完整利用流程示例
```javascript
// 1. 触发Wasm漏洞获得OOB
let oob_module = new WebAssembly.Module(malicious_bytes);
let oob_instance = new WebAssembly.Instance(oob_module);

// 2. 利用OOB泄露对象地址
let obj = {a: 1.1};
let addr = oob_instance.exports.leak(obj);

// 3. 利用OOB伪造对象
oob_instance.exports.write(target_addr, fake_obj_data);

// 4. 获得任意读写
let arb_rw = oob_instance.exports.get_fake_obj();

// 5. 覆盖代码指针或JIT代码
// 6. 执行shellcode
```
"""


def get_wasm_knowledge() -> str:
    """获取完整的Wasm知识库"""
    return "\n\n".join([
        WASM_OVERVIEW,
        WASM_BINARY_FORMAT,
        WASM_VULNERABILITY_PATTERNS,
        WASM_DEBUGGING,
    ])


WASM_KNOWLEDGE_SECTIONS = {
    "overview": WASM_OVERVIEW,
    "binary_format": WASM_BINARY_FORMAT,
    "patterns": WASM_VULNERABILITY_PATTERNS,
    "debugging": WASM_DEBUGGING,
    "exploitation": WASM_EXPLOITATION,
}
