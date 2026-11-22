"""The Verdifax MCP server, in Python, held to the tool contract in mcp-tools.json."""

from .contract import CONTRACT

__version__ = CONTRACT["server"]["version"]

__all__ = ["CONTRACT", "__version__"]
