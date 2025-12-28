# Browser Component Knowledge Bases

from .v8_knowledge import (
    V8_OVERVIEW,
    V8_OBJECT_MODEL,
    V8_JIT_KNOWLEDGE,
    V8_GC_KNOWLEDGE,
    V8_VULNERABILITY_PATTERNS,
    V8_DEBUGGING,
    V8_EXPLOITATION_PRIMITIVES,
    V8_KNOWLEDGE_SECTIONS,
    get_v8_knowledge,
    get_v8_exploitation_knowledge,
)

from .blink_knowledge import (
    BLINK_OVERVIEW,
    BLINK_DOM_KNOWLEDGE,
    BLINK_LAYOUT_KNOWLEDGE,
    BLINK_BINDINGS_KNOWLEDGE,
    BLINK_SECURITY_FEATURES,
    BLINK_VULNERABILITY_PATTERNS,
    BLINK_DEBUGGING,
    BLINK_EXPLOITATION_PRIMITIVES,
    BLINK_KNOWLEDGE_SECTIONS,
    get_blink_knowledge,
    get_blink_security_knowledge,
    get_blink_exploitation_knowledge,
)

"""
Knowledge Module

Dynamic knowledge extraction and management (Phase 5.1).
"""

from .dynamic_builder import (
    DynamicKnowledgeBuilder,
    KnowledgeContext,
)

from .cve_similarity import (
    CVESimilarityFinder,
)

__all__ = [
    "DynamicKnowledgeBuilder",
    "KnowledgeContext",
    "CVESimilarityFinder",
]

from .skia_knowledge import (
    SKIA_OVERVIEW,
    SKIA_IMAGE_DECODING,
    SKIA_VULNERABILITY_PATTERNS,
    SKIA_DEBUGGING,
    SKIA_EXPLOITATION,
    SKIA_KNOWLEDGE_SECTIONS,
    get_skia_knowledge,
)

from .pdfium_knowledge import (
    PDFIUM_OVERVIEW,
    PDFIUM_PARSING,
    PDFIUM_VULNERABILITY_PATTERNS,
    PDFIUM_DEBUGGING,
    PDFIUM_EXPLOITATION,
    PDFIUM_KNOWLEDGE_SECTIONS,
    get_pdfium_knowledge,
)

from .webrtc_knowledge import (
    WEBRTC_OVERVIEW,
    WEBRTC_PROTOCOLS,
    WEBRTC_VULNERABILITY_PATTERNS,
    WEBRTC_DEBUGGING,
    WEBRTC_EXPLOITATION,
    WEBRTC_KNOWLEDGE_SECTIONS,
    get_webrtc_knowledge,
)

from .network_knowledge import (
    NETWORK_OVERVIEW,
    NETWORK_HTTP,
    NETWORK_VULNERABILITY_PATTERNS,
    NETWORK_DEBUGGING,
    NETWORK_EXPLOITATION,
    NETWORK_KNOWLEDGE_SECTIONS,
    get_network_knowledge,
)

from .webgl_knowledge import (
    WEBGL_OVERVIEW,
    WEBGL_ARCHITECTURE,
    WEBGL_VULNERABILITY_PATTERNS,
    WEBGL_DEBUGGING,
    WEBGL_EXPLOITATION,
    WEBGL_KNOWLEDGE_SECTIONS,
    get_webgl_knowledge,
)

from .wasm_knowledge import (
    WASM_OVERVIEW,
    WASM_BINARY_FORMAT,
    WASM_VULNERABILITY_PATTERNS,
    WASM_DEBUGGING,
    WASM_EXPLOITATION,
    WASM_KNOWLEDGE_SECTIONS,
    get_wasm_knowledge,
)


# 组件名称映射
COMPONENT_ALIASES = {
    # V8
    'v8': 'v8',
    'javascript': 'v8',
    'js': 'v8',
    'jit': 'v8',
    'turbofan': 'v8',
    'maglev': 'v8',
    'ignition': 'v8',

    # WebAssembly (独立知识库)
    'wasm': 'wasm',
    'webassembly': 'wasm',
    'liftoff': 'wasm',

    # Blink
    'blink': 'blink',
    'dom': 'blink',
    'layout': 'blink',
    'css': 'blink',
    'html': 'blink',
    'rendering': 'blink',
    'bindings': 'blink',
    'oilpan': 'blink',

    # Skia (2D图形)
    'skia': 'skia',
    'image': 'skia',
    'png': 'skia',
    'jpeg': 'skia',
    'webp': 'skia',
    'gif': 'skia',
    'canvas2d': 'skia',
    '2d_graphics': 'skia',

    # WebGL (3D图形/GPU)
    'webgl': 'webgl',
    'webgl2': 'webgl',
    'angle': 'webgl',
    'gpu': 'webgl',
    'opengl': 'webgl',
    'canvas3d': 'webgl',
    'shader': 'webgl',
    '3d': 'webgl',
    'vulkan': 'webgl',
    'directx': 'webgl',
    'd3d': 'webgl',

    # PDFium
    'pdfium': 'pdfium',
    'pdf': 'pdfium',

    # WebRTC
    'webrtc': 'webrtc',
    'rtc': 'webrtc',
    'peerconnection': 'webrtc',
    'media': 'webrtc',
    'audio': 'webrtc',
    'video': 'webrtc',
    'datachannel': 'webrtc',
    'srtp': 'webrtc',
    'dtls': 'webrtc',

    # Network
    'network': 'network',
    'net': 'network',
    'http': 'network',
    'http2': 'network',
    'http3': 'network',
    'quic': 'network',
    'spdy': 'network',
    'tls': 'network',
    'ssl': 'network',
    'dns': 'network',
    'cookie': 'network',
    'cache': 'network',
    'url': 'network',
}


# 知识库获取函数映射
KNOWLEDGE_GETTERS = {
    'v8': get_v8_knowledge,
    'blink': get_blink_knowledge,
    'skia': get_skia_knowledge,
    'pdfium': get_pdfium_knowledge,
    'webrtc': get_webrtc_knowledge,
    'network': get_network_knowledge,
    'webgl': get_webgl_knowledge,
    'wasm': get_wasm_knowledge,
}


# 漏洞模式映射
VULNERABILITY_PATTERNS = {
    'v8': V8_VULNERABILITY_PATTERNS,
    'blink': BLINK_VULNERABILITY_PATTERNS,
    'skia': SKIA_VULNERABILITY_PATTERNS,
    'pdfium': PDFIUM_VULNERABILITY_PATTERNS,
    'webrtc': WEBRTC_VULNERABILITY_PATTERNS,
    'network': NETWORK_VULNERABILITY_PATTERNS,
    'webgl': WEBGL_VULNERABILITY_PATTERNS,
    'wasm': WASM_VULNERABILITY_PATTERNS,
}


# 调试指南映射
DEBUGGING_GUIDES = {
    'v8': V8_DEBUGGING,
    'blink': BLINK_DEBUGGING,
    'skia': SKIA_DEBUGGING,
    'pdfium': PDFIUM_DEBUGGING,
    'webrtc': WEBRTC_DEBUGGING,
    'network': NETWORK_DEBUGGING,
    'webgl': WEBGL_DEBUGGING,
    'wasm': WASM_DEBUGGING,
}


def normalize_component(component: str) -> str:
    """
    将组件名称规范化为标准名称。

    Args:
        component: 原始组件名称

    Returns:
        规范化后的组件名称
    """
    if not component:
        return None

    component_lower = component.lower().strip()

    # 直接匹配
    if component_lower in COMPONENT_ALIASES:
        return COMPONENT_ALIASES[component_lower]

    # 部分匹配
    for alias, normalized in COMPONENT_ALIASES.items():
        if alias in component_lower or component_lower in alias:
            return normalized

    return None


def get_component_knowledge(component: str) -> str:
    """
    获取特定组件的完整知识库。

    Args:
        component: 组件名称 (v8, blink, skia, pdfium, webrtc, network)

    Returns:
        相关知识库文本
    """
    normalized = normalize_component(component)

    if normalized and normalized in KNOWLEDGE_GETTERS:
        return KNOWLEDGE_GETTERS[normalized]()

    # 未知组件返回通用信息
    return f"""
# 组件: {component}

该组件的专项知识库尚未添加。

请参考 Chromium 源代码和安全文档:
- Chromium Code Search: https://source.chromium.org/chromium
- Chromium Security: https://www.chromium.org/Home/chromium-security/
- Issue Tracker: https://bugs.chromium.org/p/chromium/issues/list

常见漏洞类型:
- Use-After-Free (UAF)
- Type Confusion
- Buffer Overflow
- Integer Overflow
- Race Condition
"""


def get_vulnerability_patterns(component: str) -> str:
    """
    获取特定组件的漏洞模式。

    Args:
        component: 组件名称

    Returns:
        漏洞模式文本
    """
    normalized = normalize_component(component)

    if normalized and normalized in VULNERABILITY_PATTERNS:
        return VULNERABILITY_PATTERNS[normalized]

    return ""


def get_debugging_guide(component: str) -> str:
    """
    获取特定组件的调试指南。

    Args:
        component: 组件名称

    Returns:
        调试指南文本
    """
    normalized = normalize_component(component)

    if normalized and normalized in DEBUGGING_GUIDES:
        return DEBUGGING_GUIDES[normalized]

    return ""


def get_all_component_names() -> list:
    """获取所有支持的组件名称列表"""
    return list(set(COMPONENT_ALIASES.values()))


def detect_component_from_path(file_path: str) -> str:
    """
    从文件路径推断组件类型。

    Args:
        file_path: 源文件路径

    Returns:
        推断的组件名称，未知返回None
    """
    path_lower = file_path.lower()

    # Wasm特定路径 (在V8之前检查，因为wasm在v8目录下)
    if '/wasm/' in path_lower or '\\wasm\\' in path_lower:
        return 'wasm'

    # V8路径
    if '/v8/' in path_lower or '\\v8\\' in path_lower:
        return 'v8'

    # WebGL/GPU路径
    if '/gpu/' in path_lower or '\\gpu\\' in path_lower:
        return 'webgl'
    if '/angle/' in path_lower or '\\angle\\' in path_lower:
        return 'webgl'
    if 'webgl' in path_lower:
        return 'webgl'

    # Blink路径
    if '/blink/' in path_lower or '\\blink\\' in path_lower:
        return 'blink'

    # Skia路径
    if '/skia/' in path_lower or '\\skia\\' in path_lower:
        return 'skia'

    # PDFium路径
    if '/pdfium/' in path_lower or '\\pdfium\\' in path_lower:
        return 'pdfium'

    # WebRTC路径
    if '/webrtc/' in path_lower or '\\webrtc\\' in path_lower:
        return 'webrtc'

    # Network路径
    if '/net/' in path_lower or '\\net\\' in path_lower:
        return 'network'
    if '/quic/' in path_lower or '\\quic\\' in path_lower:
        return 'network'

    return None


def get_knowledge_for_files(file_paths: list) -> dict:
    """
    根据文件路径列表获取相关知识库。

    Args:
        file_paths: 文件路径列表

    Returns:
        字典 {组件名: 知识库文本}
    """
    components = set()

    for path in file_paths:
        component = detect_component_from_path(path)
        if component:
            components.add(component)

    result = {}
    for component in components:
        result[component] = get_component_knowledge(component)

    return result
