"""
Memory System for Chrome CVE Reproducer

This module provides the memory architecture:
1. Episode Memory (案例库): Store and retrieve CVE cases
2. Semantic Memory (知识库): Component knowledge, vuln patterns, exploitation primitives
3. Re-learning: Extract lessons from success/failure cases

The memory system enables:
- Experience reuse across similar CVEs
- Continuous learning and knowledge accumulation
- Similar case matching via vector retrieval
"""

from .episode import EpisodeMemory, CVECase
from .semantic import SemanticMemory, ComponentKnowledge, VulnTypeKnowledge
from .learning import LearningEngine
from .knowledge_loader import KnowledgeLoader, initialize_knowledge

__all__ = [
    'EpisodeMemory',
    'CVECase',
    'SemanticMemory',
    'ComponentKnowledge',
    'VulnTypeKnowledge',
    'LearningEngine',
    'KnowledgeLoader',
    'initialize_knowledge',
]
