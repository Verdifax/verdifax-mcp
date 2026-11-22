class ToolError(Exception):
    """A refusal or failure a tool reports to the assistant, in plain words."""


class StartupError(Exception):
    """A reason this server will not start."""
