"""
Packet capture tools for FortiGate MCP.

This module provides MCP tools for packet capture operations:
- Create/configure packet capture profiles with filters
- Start/stop packet captures
- Monitor capture status
- Download captured packets
- Clear capture data
"""
from typing import Dict, Any, List, Optional
from mcp.types import TextContent as Content
from .base import FortiGateTool
from ..core.fortigate import FortiGateAPIError


class PacketCaptureTools(FortiGateTool):
    """Tools for FortiGate packet capture operations.

    Provides packet capture (sniffer) functionality for network traffic
    analysis on FortiGate devices, including Security Fabric members.
    """

    def _build_filter_string(
        self,
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None
    ) -> str:
        """Build BPF-style filter string from individual filter parameters.

        Args:
            host: Host IP filter (matches src or dst)
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            protocol: Protocol filter (tcp, udp, icmp)
            port: Port number filter

        Returns:
            BPF-style filter string
        """
        filter_parts = []

        if host:
            filter_parts.append(f"host {host}")
        if src_ip:
            filter_parts.append(f"src host {src_ip}")
        if dst_ip:
            filter_parts.append(f"dst host {dst_ip}")
        if port:
            filter_parts.append(f"port {port}")
        if protocol and protocol.lower() not in ("none", "any", "all", ""):
            filter_parts.append(protocol.lower())

        return " and ".join(filter_parts) if filter_parts else ""

    def list_packet_captures(self, device_id: str, vdom: Optional[str] = None) -> List[Content]:
        """List all configured packet capture profiles.

        Args:
            device_id: Target device identifier
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with packet capture profiles
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            captures_data = api_client.get_packet_captures(vdom)
            return self._format_response(captures_data, "packet_captures")

        except Exception as e:
            return self._handle_error("list packet captures", device_id, e)

    def create_packet_capture(
        self,
        device_id: str,
        interface: str = "any",
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        max_packet_count: int = 10000,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Create a packet capture profile with optional filters.

        Args:
            device_id: Target device identifier
            interface: Interface to capture on (default: 'any')
            host: Host IP filter (matches src or dst)
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            protocol: Protocol filter (tcp, udp, icmp)
            port: Port number filter
            max_packet_count: Maximum packets to capture (default: 10000)
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with created capture profile info
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            # Build BPF-style filter
            filter_str = self._build_filter_string(host, src_ip, dst_ip, protocol, port)

            result = api_client.create_packet_capture(
                interface=interface,
                filter_str=filter_str if filter_str else None,
                max_packet_count=max_packet_count,
                vdom=vdom
            )

            # Extract capture ID from response
            capture_id = result.get("mkey", "unknown")

            details = f"Capture ID: {capture_id}, Interface: {interface}"
            if filter_str:
                details += f", Filter: '{filter_str}'"
            details += f", Max packets: {max_packet_count}"

            return self._format_operation_result(
                "create packet capture",
                device_id,
                True,
                details
            )

        except Exception as e:
            return self._handle_error("create packet capture", device_id, e)

    def get_packet_capture_status(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Get status of a packet capture.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with capture status
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            status_data = api_client.get_packet_capture_status(capture_id, vdom)
            return self._format_response(status_data, "packet_capture_status")

        except Exception as e:
            return self._handle_error("get packet capture status", device_id, e)

    def start_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Start a packet capture.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.start_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "start packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} started"
            )

        except Exception as e:
            return self._handle_error("start packet capture", device_id, e)

    def stop_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Stop a packet capture.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.stop_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "stop packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} stopped"
            )

        except Exception as e:
            return self._handle_error("stop packet capture", device_id, e)

    def download_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Download captured packets.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with capture data or download info
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            download_data = api_client.download_packet_capture(capture_id, vdom)
            return self._format_response(download_data, "packet_capture_download")

        except Exception as e:
            return self._handle_error("download packet capture", device_id, e)

    def delete_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Delete a packet capture profile.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.delete_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "delete packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} deleted"
            )

        except Exception as e:
            return self._handle_error("delete packet capture", device_id, e)

    def clear_packet_capture(
        self,
        device_id: str,
        capture_id: int,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Clear captured packets from a capture profile.

        Args:
            device_id: Target device identifier
            capture_id: Packet capture profile ID
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with operation result
        """
        try:
            self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            api_client.clear_packet_capture(capture_id, vdom)
            return self._format_operation_result(
                "clear packet capture",
                device_id,
                True,
                f"Packet capture {capture_id} cleared"
            )

        except Exception as e:
            return self._handle_error("clear packet capture", device_id, e)

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for packet capture tools."""
        return {
            "name": "packet_capture_tools",
            "description": "FortiGate packet capture and sniffer tools",
            "operations": [
                {
                    "name": "list_packet_captures",
                    "description": "List all packet capture profiles",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "create_packet_capture",
                    "description": "Create a packet capture profile with filters",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "interface", "type": "string", "required": False, "default": "any"},
                        {"name": "host", "type": "string", "required": False},
                        {"name": "src_ip", "type": "string", "required": False},
                        {"name": "dst_ip", "type": "string", "required": False},
                        {"name": "protocol", "type": "string", "required": False},
                        {"name": "port", "type": "integer", "required": False},
                        {"name": "max_packet_count", "type": "integer", "required": False, "default": 10000},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "get_packet_capture_status",
                    "description": "Get status of a packet capture",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "start_packet_capture",
                    "description": "Start a packet capture",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "stop_packet_capture",
                    "description": "Stop a packet capture",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "download_packet_capture",
                    "description": "Download captured packets",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "delete_packet_capture",
                    "description": "Delete a packet capture profile",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                },
                {
                    "name": "clear_packet_capture",
                    "description": "Clear captured packets",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "capture_id", "type": "integer", "required": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
