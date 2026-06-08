"""certpatrol — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from certpatrol.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:
    from certpatrol.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "certpatrol"
    TOOL_VERSION = "0.1.0"
__version__ = TOOL_VERSION
