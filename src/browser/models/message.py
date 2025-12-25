"""
Inter-Agent Message Models

Data structures for agent-to-agent communication.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from enum import Enum
from datetime import datetime


class MessageType(Enum):
    """Types of inter-agent messages."""
    # Control messages
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    TASK_FAILED = "task_failed"

    # Data messages
    INTEL_RESULT = "intel_result"
    ANALYSIS_RESULT = "analysis_result"
    POC_RESULT = "poc_result"
    VERIFY_RESULT = "verify_result"

    # Feedback messages
    REVIEW_REQUEST = "review_request"
    REVIEW_RESPONSE = "review_response"
    RETRY_REQUEST = "retry_request"

    # Status messages
    STATUS_UPDATE = "status_update"
    ERROR = "error"


@dataclass
class Message:
    """Message for inter-agent communication."""
    type: MessageType
    sender: str  # Agent name
    receiver: str  # Agent name or "broadcast"
    payload: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    correlation_id: str = ""  # For tracking related messages
    reply_to: str = ""  # For response messages

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "sender": self.sender,
            "receiver": self.receiver,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "reply_to": self.reply_to,
        }

    @classmethod
    def create_task_complete(
        cls,
        sender: str,
        receiver: str,
        result: Any,
        correlation_id: str = ""
    ) -> "Message":
        """Create a task completion message."""
        return cls(
            type=MessageType.TASK_COMPLETE,
            sender=sender,
            receiver=receiver,
            payload={"result": result},
            correlation_id=correlation_id,
        )

    @classmethod
    def create_error(
        cls,
        sender: str,
        receiver: str,
        error: str,
        correlation_id: str = ""
    ) -> "Message":
        """Create an error message."""
        return cls(
            type=MessageType.ERROR,
            sender=sender,
            receiver=receiver,
            payload={"error": error},
            correlation_id=correlation_id,
        )
