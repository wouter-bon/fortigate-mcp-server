"""Core functionality for FortiGate MCP."""

from .logging import setup_logging
from .fortigate import FortiGateManager
from .ssh_client import FortiGateSSHClient, FortiGateSSHError, PARAMIKO_AVAILABLE

__all__ = [
    "setup_logging",
    "FortiGateManager",
    "FortiGateSSHClient",
    "FortiGateSSHError",
    "PARAMIKO_AVAILABLE",
]
