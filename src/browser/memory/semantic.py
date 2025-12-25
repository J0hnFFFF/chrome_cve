"""
Semantic Memory (知识库)

Stores structured knowledge:
- Component knowledge (V8, Blink, etc.)
- Vulnerability patterns
- Exploitation primitives
- Successful plugins
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from pathlib import Path
import json


@dataclass
class ComponentKnowledge:
    """Knowledge about a browser component."""
    name: str
    overview: str = ""
    architecture: str = ""
    vulnerability_patterns: str = ""
    debugging_guide: str = ""
    exploitation_primitives: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "overview": self.overview,
            "architecture": self.architecture,
            "vulnerability_patterns": self.vulnerability_patterns,
            "debugging_guide": self.debugging_guide,
            "exploitation_primitives": self.exploitation_primitives,
        }


@dataclass
class VulnTypeKnowledge:
    """Knowledge about a vulnerability type."""
    name: str
    description: str = ""
    trigger_patterns: List[str] = field(default_factory=list)
    poc_templates: List[str] = field(default_factory=list)
    exploitation_steps: List[str] = field(default_factory=list)


class SemanticMemory:
    """
    Manages structured knowledge storage and retrieval.

    Knowledge categories:
    - Component knowledge (from browser/knowledge/)
    - Vulnerability type patterns
    - Exploitation primitives
    - Successful plugin templates
    """

    def __init__(self, storage_path: str = "./volumes/memory/semantic"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self._component_knowledge: Dict[str, ComponentKnowledge] = {}
        self._vuln_knowledge: Dict[str, VulnTypeKnowledge] = {}
        self._plugins: Dict[str, str] = {}  # plugin_name -> code

        self._load_all()

    def _load_all(self) -> None:
        """Load all knowledge from storage."""
        # Load component knowledge
        comp_dir = self.storage_path / "components"
        if comp_dir.exists():
            for file in comp_dir.glob("*.json"):
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        ck = ComponentKnowledge(**data)
                        self._component_knowledge[ck.name] = ck
                except Exception as e:
                    print(f"Warning: Failed to load component knowledge from {file}: {e}")

        # Load vulnerability knowledge
        vuln_dir = self.storage_path / "vulnerabilities"
        if vuln_dir.exists():
            for file in vuln_dir.glob("*.json"):
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        vk = VulnTypeKnowledge(**data)
                        self._vuln_knowledge[vk.name] = vk
                except Exception as e:
                    print(f"Warning: Failed to load vuln knowledge from {file}: {e}")

        # Load plugins
        plugin_dir = self.storage_path / "plugins"
        if plugin_dir.exists():
            for file in plugin_dir.glob("*.py"):
                try:
                    self._plugins[file.stem] = file.read_text(encoding='utf-8')
                except Exception as e:
                    print(f"Warning: Failed to load plugin from {file}: {e}")

    def get_component_knowledge(self, component: str) -> Optional[ComponentKnowledge]:
        """Get knowledge for a component."""
        # Try exact match first
        if component in self._component_knowledge:
            return self._component_knowledge[component]

        # Try case-insensitive match
        for name, knowledge in self._component_knowledge.items():
            if name.lower() == component.lower():
                return knowledge

        return None

    def save_component_knowledge(self, knowledge: ComponentKnowledge) -> None:
        """Save component knowledge."""
        self._component_knowledge[knowledge.name] = knowledge

        comp_dir = self.storage_path / "components"
        comp_dir.mkdir(parents=True, exist_ok=True)

        file_path = comp_dir / f"{knowledge.name.lower()}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(knowledge.to_dict(), f, indent=2)

    def get_vuln_knowledge(self, vuln_type: str) -> Optional[VulnTypeKnowledge]:
        """Get knowledge for a vulnerability type."""
        return self._vuln_knowledge.get(vuln_type)

    def save_plugin(self, name: str, code: str) -> None:
        """Save a successful plugin for reuse."""
        self._plugins[name] = code

        plugin_dir = self.storage_path / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)

        file_path = plugin_dir / f"{name}.py"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code)

    def get_plugin(self, name: str) -> Optional[str]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def find_similar_plugins(
        self,
        component: str = None,
        vuln_type: str = None,
        limit: int = 3,
    ) -> List[str]:
        """Find similar plugins for reference."""
        # Simple matching based on name patterns
        matches = []
        for name, code in self._plugins.items():
            score = 0
            if component and component.lower() in name.lower():
                score += 1
            if vuln_type and vuln_type.lower() in name.lower():
                score += 1
            if score > 0:
                matches.append((score, name, code))

        matches.sort(key=lambda x: x[0], reverse=True)
        return [code for _, _, code in matches[:limit]]

    def get_knowledge_for_context(
        self,
        component: str = None,
        vuln_type: str = None,
    ) -> str:
        """Get combined knowledge for LLM context."""
        parts = []

        if component:
            ck = self.get_component_knowledge(component)
            if ck:
                parts.append(f"# {ck.name} Knowledge\n\n{ck.overview}\n\n{ck.vulnerability_patterns}")

        if vuln_type:
            vk = self.get_vuln_knowledge(vuln_type)
            if vk:
                parts.append(f"# {vk.name} Vulnerability Pattern\n\n{vk.description}")

        return "\n\n---\n\n".join(parts)
