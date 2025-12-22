"""
Base classes for Browser CVE agents.
"""

import re
from typing import Optional
from agentlib import Agent, AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser


class XMLOutputParser(BaseParser):
    """
    Parser for XML-tagged output format.

    Expected format:
    <tag1>content1</tag1>
    <tag2>content2</tag2>
    """

    MAX_FIX_FORMAT_TRIES = 3

    def __init__(self, tags: list[str], format_description: str = ""):
        self.tags = tags
        self.format_description = format_description

    def get_format_instructions(self) -> str:
        if self.format_description:
            return self.format_description

        tags_str = "\n".join(f"<{tag}>...</{tag}>" for tag in self.tags)
        return f"""
Output your response in the following XML format:

```
{tags_str}
```

Replace ... with the appropriate content for each tag.
"""

    def invoke(self, msg, *args, **kwargs) -> dict:
        response = msg.get('output', '')
        if isinstance(response, list):
            response = ' '.join(response)
        if response == 'Agent stopped due to max iterations.':
            return {"error": response}
        return self.parse(response)

    def fix_format(self, text: str) -> str:
        """Use LLM to fix malformed output."""
        fix_llm = LLMFunction.create(
            'Fix the format of the response according to the format instructions.\n\n'
            '# CURRENT RESPONSE\n{{ info.current }}\n\n'
            '# REQUIRED FORMAT\n{{ info.format }}',
            model='gpt-4o-mini',
            temperature=0.0
        )
        return fix_llm(info=dict(
            current=text,
            format=self.get_format_instructions()
        ))

    def parse(self, text: str) -> dict:
        """Parse XML tags from text."""
        attempt = 1
        while attempt <= self.MAX_FIX_FORMAT_TRIES:
            try:
                result = {}
                for tag in self.tags:
                    pattern = rf'<{tag}>(.*?)</{tag}>'
                    match = re.search(pattern, text, re.DOTALL)
                    if match:
                        content = match.group(1).strip()
                        # Remove code block markers if present
                        if content.startswith('```'):
                            lines = content.split('\n')
                            content = '\n'.join(lines[1:-1] if lines[-1] == '```' else lines[1:])
                        result[tag] = content
                    else:
                        raise ValueError(f"Missing required tag: <{tag}>")
                return result
            except ValueError as e:
                if attempt < self.MAX_FIX_FORMAT_TRIES:
                    print(f"Parse error: {e}, attempting to fix...")
                    text = self.fix_format(text)
                    attempt += 1
                else:
                    raise

        return {}


class BrowserCVEAgent(Agent):
    """Base class for simple (single-call) Browser CVE agents."""

    def get_cost(self) -> float:
        """Calculate total cost of LLM calls."""
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name).get('total_cost', 0)
        return total_cost


class BrowserCVEAgentWithTools(AgentWithHistory):
    """Base class for Browser CVE agents with tool calling capability."""

    __MAX_TOOL_ITERATIONS__ = 60

    def get_cost(self) -> float:
        """Calculate total cost of LLM calls."""
        total_cost = 0
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name).get('total_cost', 0)
        return total_cost
