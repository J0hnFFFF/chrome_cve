"""
Base classes for Multi-Agent System

Provides common functionality for all agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, TYPE_CHECKING
from enum import Enum
from datetime import datetime
from pathlib import Path
import uuid
import logging

if TYPE_CHECKING:
    from ...services.llm_service import LLMService, LLMSession, ToolDefinition

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Agent execution states."""
    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentMessage:
    """Message for inter-agent communication."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    sender: str = ""
    receiver: str = ""
    type: str = ""  # request, response, broadcast
    action: str = ""  # analyze, generate, verify, review
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    correlation_id: str = ""  # Links request/response

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "sender": self.sender,
            "receiver": self.receiver,
            "type": self.type,
            "action": self.action,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def create_request(
        cls,
        sender: str,
        receiver: str,
        action: str,
        payload: Dict[str, Any] = None,
    ) -> "AgentMessage":
        """Create a request message."""
        msg = cls(
            sender=sender,
            receiver=receiver,
            type="request",
            action=action,
            payload=payload or {},
        )
        msg.correlation_id = msg.id
        return msg

    def create_response(
        self,
        sender: str,
        payload: Dict[str, Any] = None,
        success: bool = True,
    ) -> "AgentMessage":
        """Create a response to this message."""
        return AgentMessage(
            sender=sender,
            receiver=self.sender,
            type="response",
            action=f"{self.action}_result",
            payload={
                "success": success,
                **(payload or {}),
            },
            correlation_id=self.correlation_id,
        )


class BaseReproAgent(ABC):
    """
    Base class for all reproduction agents.

    Provides:
    - Message handling
    - State management
    - LLM integration via LLMService
    - Common utilities
    """

    name: str = "base_agent"
    system_prompt_file: str = ""  # Override in subclasses

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.state = AgentState.IDLE
        self._inbox: List[AgentMessage] = []
        self._outbox: List[AgentMessage] = []
        self._message_handlers: Dict[str, callable] = {}
        self._register_handlers()

        # LLM integration
        self._llm_service: Optional["LLMService"] = None
        self._llm_session: Optional["LLMSession"] = None
        self._tools: List["ToolDefinition"] = []
        self._system_prompt: str = ""

    def set_llm_service(self, service: "LLMService") -> None:
        """Set the LLM service for this agent."""
        self._llm_service = service

    def set_tools(self, tools: List["ToolDefinition"]) -> None:
        """Set available tools for this agent."""
        self._tools = tools

    def _load_system_prompt(self) -> str:
        """Load system prompt from file."""
        if not self.system_prompt_file:
            return ""

        prompt_path = Path(__file__).parent.parent.parent / "prompts" / "multi" / self.system_prompt_file
        if prompt_path.exists():
            return prompt_path.read_text(encoding="utf-8")

        logger.warning(f"System prompt file not found: {prompt_path}")
        return ""

    def _create_session(self, additional_context: str = "") -> "LLMSession":
        """Create a new LLM session for this agent."""
        if not self._llm_service:
            raise RuntimeError(f"{self.name}: LLMService not set")

        # Load system prompt
        system_prompt = self._load_system_prompt()
        if additional_context:
            system_prompt = f"{system_prompt}\n\n{additional_context}"

        session = self._llm_service.create_session(
            session_id=f"{self.name}_{uuid.uuid4().hex[:8]}",
            system_prompt=system_prompt,
            tools=self._tools,
        )
        self._llm_session = session
        return session

    def _llm_chat(self, message: str, use_tools: bool = True) -> str:
        """Send message to LLM and get response."""
        if not self._llm_session:
            self._create_session()

        if use_tools and self._tools:
            return self._llm_session.chat_with_tools(message)
        else:
            return self._llm_session.chat(message)

    def _llm_digest_knowledge(self, knowledge_chunks: List[str]) -> str:
        """Digest knowledge through multi-turn dialogue."""
        if not self._llm_session:
            self._create_session()

        return self._llm_session.digest_knowledge(knowledge_chunks)

    def _register_handlers(self) -> None:
        """Register message handlers. Override in subclasses."""
        pass

    def receive(self, message: AgentMessage) -> None:
        """Receive a message into inbox."""
        self._inbox.append(message)

    def send(self, message: AgentMessage) -> None:
        """Send a message to outbox."""
        self._outbox.append(message)

    def get_outgoing_messages(self) -> List[AgentMessage]:
        """Get and clear outgoing messages."""
        messages = self._outbox.copy()
        self._outbox.clear()
        return messages

    def process_messages(self) -> List[AgentMessage]:
        """Process all inbox messages and return responses."""
        responses = []

        while self._inbox:
            message = self._inbox.pop(0)
            response = self._handle_message(message)
            if response:
                responses.append(response)

        return responses

    def _handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Handle a single message."""
        handler = self._message_handlers.get(message.action)
        if handler:
            try:
                return handler(message)
            except Exception as e:
                return message.create_response(
                    sender=self.name,
                    payload={"error": str(e)},
                    success=False,
                )
        return None

    @abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main execution method.

        Args:
            context: Execution context with task info

        Returns:
            Result dictionary
        """
        pass

    def get_state(self) -> AgentState:
        """Get current agent state."""
        return self.state

    def set_state(self, state: AgentState) -> None:
        """Set agent state."""
        self.state = state
