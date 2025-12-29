"""
LLM Service

Provides unified LLM capabilities for the multi-agent system.
Supports:
- Chat completions with tool calling
- ReAct pattern (Thought → Action → Observation)
- Multi-turn dialogue for knowledge digestion
- Session management
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Union
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

class MessageRole(Enum):
    """Message roles in conversation."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """A message in a conversation."""
    role: MessageRole
    content: str
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Optional[List[Dict]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible format."""
        msg = {
            "role": self.role.value,
            "content": self.content,
        }
        if self.name:
            msg["name"] = self.name
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            # Convert to OpenAI tool_calls format with type field
            formatted_tool_calls = []
            for tc in self.tool_calls:
                formatted_tc = {
                    "id": tc.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": tc.get("name", ""),
                        "arguments": json.dumps(tc.get("arguments", {})) if isinstance(tc.get("arguments"), dict) else tc.get("arguments", "{}"),
                    }
                }
                formatted_tool_calls.append(formatted_tc)
            msg["tool_calls"] = formatted_tool_calls
        return msg


@dataclass
class ToolDefinition:
    """Definition of a tool for LLM."""
    name: str
    description: str
    parameters: Dict[str, Any]
    function: Callable

    def to_dict(self) -> Dict[str, Any]:
        """Convert to OpenAI tool format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        }


@dataclass
class ReActStep:
    """A step in ReAct reasoning."""
    thought: str = ""
    action: str = ""
    action_input: Dict[str, Any] = field(default_factory=dict)
    observation: str = ""


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    tool_calls: List[Dict] = field(default_factory=list)
    finish_reason: str = ""
    usage: Dict[str, int] = field(default_factory=dict)


# ============================================================================
# LLM Backends
# ============================================================================

class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @abstractmethod
    def chat(
        self,
        messages: List[Message],
        tools: List[ToolDefinition] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat completion request."""
        pass


class OpenAIBackend(LLMBackend):
    """OpenAI API backend."""

    def __init__(
        self,
        api_key: str = None,
        model: str = "gpt-4o",
        base_url: str = None,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        
        # Validate and fix base_url
        if base_url and base_url.strip():
            # Ensure it has a protocol
            if not base_url.startswith(('http://', 'https://')):
                logger.warning(f"base_url '{base_url}' missing protocol, setting to None")
                base_url = None
        else:
            base_url = None
        
        self.base_url = base_url

        # Import OpenAI client
        try:
            from openai import OpenAI
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        except ImportError:
            raise ImportError("openai package required: pip install openai")

    def chat(
        self,
        messages: List[Message],
        tools: List[ToolDefinition] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat completion request to OpenAI."""
        # Convert messages to dict format
        msg_dicts = [m.to_dict() for m in messages]

        # Build request
        kwargs = {
            "model": self.model,
            "messages": msg_dicts,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        # Add tools if provided
        if tools:
            kwargs["tools"] = [t.to_dict() for t in tools]
            kwargs["tool_choice"] = "auto"

        try:
            print(f"    [LLM] Calling OpenAI API ({self.model})...")
            response = self.client.chat.completions.create(**kwargs)
            choice = response.choices[0]
            print(f"    [LLM] Response received (tokens: {response.usage.total_tokens})")

            # Extract tool calls if present
            tool_calls = []
            if choice.message.tool_calls:
                for tc in choice.message.tool_calls:
                    tool_calls.append({
                        "id": tc.id,
                        "name": tc.function.name,
                        "arguments": json.loads(tc.function.arguments),
                    })

            return LLMResponse(
                content=choice.message.content or "",
                tool_calls=tool_calls,
                finish_reason=choice.finish_reason,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
            )
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise


class AnthropicBackend(LLMBackend):
    """Anthropic API backend."""

    def __init__(
        self,
        api_key: str = None,
        model: str = "claude-sonnet-4-20250514",
        base_url: str = None,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.base_url = base_url

        try:
            from anthropic import Anthropic
            client_kwargs = {"api_key": self.api_key}
            if self.base_url:
                client_kwargs["base_url"] = self.base_url
            self.client = Anthropic(**client_kwargs)
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

    def chat(
        self,
        messages: List[Message],
        tools: List[ToolDefinition] = None,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send chat completion request to Anthropic."""
        # Separate system message
        system_msg = ""
        chat_messages = []

        for msg in messages:
            if msg.role == MessageRole.SYSTEM:
                system_msg = msg.content
            else:
                chat_messages.append({
                    "role": msg.role.value,
                    "content": msg.content,
                })

        # Build request
        kwargs = {
            "model": self.model,
            "messages": chat_messages,
            "max_tokens": max_tokens,
        }

        if system_msg:
            kwargs["system"] = system_msg

        # Add tools if provided
        if tools:
            kwargs["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                }
                for t in tools
            ]

        try:
            print(f"    [LLM] Calling Anthropic API ({self.model})...")
            response = self.client.messages.create(**kwargs)
            print(f"    [LLM] Response received (tokens: {response.usage.input_tokens + response.usage.output_tokens})")

            # Extract content and tool use
            content = ""
            tool_calls = []

            for block in response.content:
                if block.type == "text":
                    content = block.text
                elif block.type == "tool_use":
                    tool_calls.append({
                        "id": block.id,
                        "name": block.name,
                        "arguments": block.input,
                    })

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                finish_reason=response.stop_reason,
                usage={
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
                },
            )
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise


# ============================================================================
# LLM Session
# ============================================================================

class LLMSession:
    """
    A conversation session with an LLM.

    Maintains message history and supports:
    - Multi-turn dialogue
    - Tool calling with ReAct pattern
    - Knowledge digestion
    """

    def __init__(
        self,
        backend: LLMBackend,
        system_prompt: str = "",
        tools: List[ToolDefinition] = None,
        max_history: int = 50,
    ):
        self.backend = backend
        self.system_prompt = system_prompt
        self.tools = tools or []
        self.max_history = max_history

        self.messages: List[Message] = []
        if system_prompt:
            self.messages.append(Message(
                role=MessageRole.SYSTEM,
                content=system_prompt,
            ))

        # Tool registry for execution
        self._tool_registry: Dict[str, ToolDefinition] = {
            t.name: t for t in self.tools
        }

    def add_tool(self, tool: ToolDefinition) -> None:
        """Add a tool to the session."""
        self.tools.append(tool)
        self._tool_registry[tool.name] = tool

    def chat(
        self,
        message: str,
        temperature: float = 0.0,
    ) -> str:
        """
        Send a message and get a response.

        Does not execute tools - returns raw response.
        """
        # Add user message
        self.messages.append(Message(
            role=MessageRole.USER,
            content=message,
        ))

        # Get response
        response = self.backend.chat(
            messages=self.messages,
            tools=self.tools if self.tools else None,
            temperature=temperature,
        )

        # Add assistant response
        self.messages.append(Message(
            role=MessageRole.ASSISTANT,
            content=response.content,
            tool_calls=response.tool_calls if response.tool_calls else None,
        ))

        # Trim history if needed
        self._trim_history()

        return response.content

    def chat_with_tools(
        self,
        message: str,
        max_iterations: int = 10,
        temperature: float = 0.0,
    ) -> str:
        """
        Send a message and execute tools in ReAct loop.

        Continues until LLM stops calling tools or max_iterations reached.
        """
        # Add user message
        self.messages.append(Message(
            role=MessageRole.USER,
            content=message,
        ))

        for iteration in range(max_iterations):
            # Get response
            response = self.backend.chat(
                messages=self.messages,
                tools=self.tools if self.tools else None,
                temperature=temperature,
            )

            # Add assistant response
            self.messages.append(Message(
                role=MessageRole.ASSISTANT,
                content=response.content,
                tool_calls=response.tool_calls if response.tool_calls else None,
            ))

            # If no tool calls, we're done
            if not response.tool_calls:
                break

            # Execute tools and add results
            for tool_call in response.tool_calls:
                tool_name = tool_call["name"]
                tool_args = tool_call["arguments"]
                tool_id = tool_call["id"]

                print(f"    [LLM] Executing tool: {tool_name}")
                logger.debug(f"Executing tool: {tool_name}({tool_args})")

                # Execute tool
                result = self._execute_tool(tool_name, tool_args)
                print(f"    [LLM] Tool result: {str(result)[:100]}...")

                # Add tool result
                self.messages.append(Message(
                    role=MessageRole.TOOL,
                    content=str(result),
                    name=tool_name,
                    tool_call_id=tool_id,
                ))

        # Trim history if needed
        self._trim_history()

        return response.content

    def react_loop(
        self,
        task: str,
        max_steps: int = 10,
        temperature: float = 0.0,
    ) -> List[ReActStep]:
        """
        Execute task using ReAct pattern.

        Returns list of (Thought, Action, Observation) steps.
        """
        react_prompt = f"""You are an AI assistant that solves tasks using the ReAct pattern.

For each step, you MUST output in this exact format:
Thought: <your reasoning about what to do next>
Action: <tool name to call, or "finish" if done>
Action Input: <JSON arguments for the tool>

Available tools: {[t.name for t in self.tools]}

Task: {task}

Begin!"""

        self.messages.append(Message(
            role=MessageRole.USER,
            content=react_prompt,
        ))

        steps = []

        for step_num in range(max_steps):
            # Get response
            response = self.backend.chat(
                messages=self.messages,
                temperature=temperature,
            )

            content = response.content

            # Parse ReAct format
            step = self._parse_react_step(content)
            steps.append(step)

            # Add to history
            self.messages.append(Message(
                role=MessageRole.ASSISTANT,
                content=content,
            ))

            # Check if finished
            if step.action.lower() == "finish":
                break

            # Execute action
            if step.action in self._tool_registry:
                observation = self._execute_tool(step.action, step.action_input)
            else:
                observation = f"Error: Unknown tool '{step.action}'"

            step.observation = str(observation)

            # Add observation
            self.messages.append(Message(
                role=MessageRole.USER,
                content=f"Observation: {observation}",
            ))

        return steps

    def digest_knowledge(
        self,
        knowledge_chunks: List[str],
        digest_prompt: str = None,
    ) -> str:
        """
        Digest knowledge through multi-turn dialogue.

        Feeds knowledge chunks one by one, allowing LLM to process
        and integrate information before receiving more.
        """
        if not digest_prompt:
            digest_prompt = """I will provide you with knowledge in chunks.
After reading each chunk, briefly summarize what you learned.
At the end, I will ask you to apply this knowledge."""

        # Initial prompt
        self.messages.append(Message(
            role=MessageRole.USER,
            content=digest_prompt,
        ))

        response = self.backend.chat(
            messages=self.messages,
            temperature=0.0,
        )
        self.messages.append(Message(
            role=MessageRole.ASSISTANT,
            content=response.content,
        ))

        # Feed knowledge chunks
        summaries = []
        for i, chunk in enumerate(knowledge_chunks, 1):
            chunk_msg = f"Knowledge chunk {i}/{len(knowledge_chunks)}:\n\n{chunk}\n\nBriefly summarize what you learned from this."

            self.messages.append(Message(
                role=MessageRole.USER,
                content=chunk_msg,
            ))

            response = self.backend.chat(
                messages=self.messages,
                temperature=0.0,
            )
            self.messages.append(Message(
                role=MessageRole.ASSISTANT,
                content=response.content,
            ))
            summaries.append(response.content)

        # Finalize
        self.messages.append(Message(
            role=MessageRole.USER,
            content="Good. You have now digested all the knowledge. Ready to apply it.",
        ))

        response = self.backend.chat(
            messages=self.messages,
            temperature=0.0,
        )
        self.messages.append(Message(
            role=MessageRole.ASSISTANT,
            content=response.content,
        ))

        return response.content

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """Execute a tool by name."""
        if name not in self._tool_registry:
            return f"Error: Tool '{name}' not found"

        tool = self._tool_registry[name]
        try:
            return tool.function(**args)
        except Exception as e:
            return f"Error executing {name}: {e}"

    def _parse_react_step(self, content: str) -> ReActStep:
        """Parse ReAct formatted response."""
        import re

        step = ReActStep()

        # Parse Thought
        thought_match = re.search(r"Thought:\s*(.+?)(?=Action:|$)", content, re.DOTALL)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        # Parse Action
        action_match = re.search(r"Action:\s*(\w+)", content)
        if action_match:
            step.action = action_match.group(1).strip()

        # Parse Action Input
        input_match = re.search(r"Action Input:\s*(\{.+?\})", content, re.DOTALL)
        if input_match:
            try:
                step.action_input = json.loads(input_match.group(1))
            except json.JSONDecodeError:
                step.action_input = {}

        return step

    def _trim_history(self) -> None:
        """Trim message history to max_history."""
        if len(self.messages) > self.max_history:
            # Keep system message and recent messages
            system_msgs = [m for m in self.messages if m.role == MessageRole.SYSTEM]
            other_msgs = [m for m in self.messages if m.role != MessageRole.SYSTEM]

            # Keep last N messages
            keep_count = self.max_history - len(system_msgs)
            self.messages = system_msgs + other_msgs[-keep_count:]

    def get_history(self) -> List[Dict]:
        """Get message history as list of dicts."""
        return [m.to_dict() for m in self.messages]

    def clear_history(self, keep_system: bool = True) -> None:
        """Clear message history."""
        if keep_system:
            self.messages = [m for m in self.messages if m.role == MessageRole.SYSTEM]
        else:
            self.messages = []


# ============================================================================
# LLM Service
# ============================================================================

class LLMService:
    """
    Shared LLM service for all agents.

    Provides:
    - Session management
    - Multiple backend support (OpenAI, Anthropic)
    - Configuration-driven setup
    """

    def __init__(
        self,
        config: Dict[str, Any] = None,
        backend_type: str = "openai",
    ):
        self.config = config or {}
        self.backend_type = backend_type
        self._backend: Optional[LLMBackend] = None
        self._sessions: Dict[str, LLMSession] = {}

    def _get_backend(self) -> LLMBackend:
        """Get or create the LLM backend."""
        if self._backend is None:
            if self.backend_type == "openai":
                self._backend = OpenAIBackend(
                    api_key=self.config.get("openai_api_key"),
                    model=self.config.get("default_model", "gpt-4o"),
                    base_url=self.config.get("openai_base_url"),
                )
            elif self.backend_type == "anthropic":
                self._backend = AnthropicBackend(
                    api_key=self.config.get("anthropic_api_key"),
                    model=self.config.get("default_model", "claude-sonnet-4-20250514"),
                    base_url=self.config.get("anthropic_base_url"),
                )
            else:
                raise ValueError(f"Unknown backend type: {self.backend_type}")

        return self._backend

    def create_session(
        self,
        session_id: str,
        system_prompt: str = "",
        tools: List[ToolDefinition] = None,
    ) -> LLMSession:
        """
        Create a new LLM session.

        Args:
            session_id: Unique identifier for the session
            system_prompt: System prompt for the session
            tools: Available tools for the session

        Returns:
            LLMSession instance
        """
        session = LLMSession(
            backend=self._get_backend(),
            system_prompt=system_prompt,
            tools=tools,
            max_history=self.config.get("max_history", 50),
        )
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[LLMSession]:
        """Get an existing session by ID."""
        return self._sessions.get(session_id)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def quick_chat(
        self,
        message: str,
        system_prompt: str = "",
        temperature: float = 0.0,
    ) -> str:
        """
        One-shot chat without session management.

        Good for simple queries that don't need history.
        """
        messages = []
        if system_prompt:
            messages.append(Message(role=MessageRole.SYSTEM, content=system_prompt))
        messages.append(Message(role=MessageRole.USER, content=message))

        response = self._get_backend().chat(
            messages=messages,
            temperature=temperature,
        )
        return response.content


# ============================================================================
# Tool Helpers
# ============================================================================

def create_tool_from_function(func: Callable) -> ToolDefinition:
    """
    Create a ToolDefinition from a function with docstring.

    The function should have type hints and a docstring describing it.
    """
    import inspect

    name = func.__name__
    doc = func.__doc__ or ""
    description = doc.split("\n")[0] if doc else name

    # Get parameter info from type hints
    sig = inspect.signature(func)
    hints = getattr(func, "__annotations__", {})

    properties = {}
    required = []

    for param_name, param in sig.parameters.items():
        if param_name == "self":
            continue

        param_type = hints.get(param_name, str)
        json_type = _python_type_to_json(param_type)

        properties[param_name] = {
            "type": json_type,
            "description": f"Parameter: {param_name}",
        }

        if param.default == inspect.Parameter.empty:
            required.append(param_name)

    parameters = {
        "type": "object",
        "properties": properties,
        "required": required,
    }

    return ToolDefinition(
        name=name,
        description=description,
        parameters=parameters,
        function=func,
    )


def _python_type_to_json(py_type) -> str:
    """Convert Python type to JSON schema type."""
    type_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }
    return type_map.get(py_type, "string")


# ============================================================================
# Factory Function
# ============================================================================

def create_llm_service(
    config: Dict[str, Any] = None,
    backend: str = None,
) -> LLMService:
    """
    Create an LLMService instance.

    Args:
        config: Configuration dict with API keys, model settings, etc.
        backend: Backend type ("openai" or "anthropic")

    Returns:
        Configured LLMService instance
    """
    if config is None:
        config = {}

    # Determine backend
    if backend is None:
        # Auto-detect based on available API keys
        if config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY"):
            backend = "anthropic"
        else:
            backend = "openai"

    return LLMService(config=config, backend_type=backend)
