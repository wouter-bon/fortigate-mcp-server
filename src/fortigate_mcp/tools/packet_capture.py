"""
Packet capture tools for FortiGate MCP.

This module provides MCP tools for packet capture operations:
- Create/configure packet capture profiles with filters
- Start/stop packet captures
- Monitor capture status
- Download captured packets
- Clear capture data
- Timed capture with automatic analysis
"""
import base64
import os
import subprocess
import tempfile
import time
from datetime import datetime
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

    def _analyze_pcap_with_tshark(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze PCAP file using tshark if available.

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            Analysis results dictionary
        """
        analysis = {
            "tool": "tshark",
            "available": False,
            "summary": {},
            "conversations": [],
            "protocols": {},
            "errors": []
        }

        # Check if tshark is available
        try:
            result = subprocess.run(
                ["tshark", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return analysis
            analysis["available"] = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return analysis

        try:
            # Get packet count and basic stats
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "io,stat,0"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["io_stats"] = result.stdout

            # Get protocol hierarchy
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["protocol_hierarchy"] = result.stdout

            # Get conversations (top 20)
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["ip_conversations"] = result.stdout

            # Get TCP conversations
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["tcp_conversations"] = result.stdout

            # Get endpoints
            result = subprocess.run(
                ["tshark", "-r", pcap_path, "-q", "-z", "endpoints,ip"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                analysis["summary"]["ip_endpoints"] = result.stdout

        except subprocess.TimeoutExpired:
            analysis["errors"].append("tshark analysis timed out")
        except Exception as e:
            analysis["errors"].append(f"tshark analysis error: {str(e)}")

        return analysis

    def _analyze_pcap_basic(self, pcap_data: bytes) -> Dict[str, Any]:
        """Basic PCAP analysis without external tools.

        Args:
            pcap_data: Raw PCAP file data

        Returns:
            Basic analysis results
        """
        analysis = {
            "tool": "basic",
            "file_size_bytes": len(pcap_data),
            "packet_count": 0,
            "capture_info": {}
        }

        # Basic PCAP header parsing (first 24 bytes for global header)
        if len(pcap_data) >= 24:
            # Check magic number
            magic = pcap_data[:4]
            if magic == b'\xd4\xc3\xb2\xa1':  # Little-endian
                analysis["capture_info"]["format"] = "pcap (little-endian)"
                analysis["capture_info"]["byte_order"] = "little"
            elif magic == b'\xa1\xb2\xc3\xd4':  # Big-endian
                analysis["capture_info"]["format"] = "pcap (big-endian)"
                analysis["capture_info"]["byte_order"] = "big"
            elif magic == b'\x0a\x0d\x0d\x0a':  # pcapng
                analysis["capture_info"]["format"] = "pcapng"
            else:
                analysis["capture_info"]["format"] = "unknown"

            # Count packets (rough estimate based on packet headers)
            # Each packet has a 16-byte header in standard pcap
            offset = 24  # Skip global header
            packet_count = 0
            while offset < len(pcap_data) - 16:
                try:
                    # Read packet length from header (bytes 8-12, little-endian)
                    if analysis["capture_info"].get("byte_order") == "little":
                        incl_len = int.from_bytes(pcap_data[offset+8:offset+12], 'little')
                    else:
                        incl_len = int.from_bytes(pcap_data[offset+8:offset+12], 'big')

                    if incl_len <= 0 or incl_len > 65535:
                        break

                    offset += 16 + incl_len  # Header + packet data
                    packet_count += 1

                    if packet_count > 100000:  # Safety limit
                        break
                except Exception:
                    break

            analysis["packet_count"] = packet_count

        return analysis

    def capture_and_analyze(
        self,
        device_id: str,
        interface: str = "any",
        host: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        duration_seconds: int = 120,
        max_packet_count: int = 10000,
        cleanup: bool = True,
        vdom: Optional[str] = None
    ) -> List[Content]:
        """Capture traffic for a specified duration, then analyze the results.

        This is a convenience method that:
        1. Creates a packet capture profile with the specified filters
        2. Starts the capture
        3. Waits for the specified duration (default: 2 minutes)
        4. Stops the capture
        5. Downloads and saves the capture to a temporary file
        6. Analyzes the capture using tshark (if available) or basic analysis
        7. Optionally cleans up the capture profile

        Args:
            device_id: Target device identifier or name
            interface: Interface to capture on (default: 'any')
            host: Host IP filter (matches src or dst)
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            protocol: Protocol filter (tcp, udp, icmp)
            port: Port number filter
            duration_seconds: Capture duration in seconds (default: 120 = 2 minutes)
            max_packet_count: Maximum packets to capture (default: 10000)
            cleanup: Delete capture profile after analysis (default: True)
            vdom: Virtual Domain (optional)

        Returns:
            List of Content objects with capture analysis results
        """
        capture_id = None
        pcap_path = None

        try:
            resolved_device_id = self._validate_device_exists(device_id)
            api_client = self._get_device_api(device_id)

            # Build filter string
            filter_str = self._build_filter_string(host, src_ip, dst_ip, protocol, port)

            # Step 1: Create capture profile
            self.logger.info(f"Creating packet capture on {device_id}, interface={interface}, filter='{filter_str}'")
            create_result = api_client.create_packet_capture(
                interface=interface,
                filter_str=filter_str if filter_str else None,
                max_packet_count=max_packet_count,
                vdom=vdom
            )
            capture_id = create_result.get("mkey")
            if not capture_id:
                raise ValueError("Failed to create capture profile - no capture ID returned")

            self.logger.info(f"Created capture profile with ID: {capture_id}")

            # Step 2: Start capture
            self.logger.info(f"Starting packet capture {capture_id}")
            api_client.start_packet_capture(capture_id, vdom)

            # Step 3: Wait for specified duration
            self.logger.info(f"Capturing for {duration_seconds} seconds...")
            start_time = time.time()
            elapsed = 0

            while elapsed < duration_seconds:
                time.sleep(min(10, duration_seconds - elapsed))  # Check every 10 seconds
                elapsed = time.time() - start_time

                # Check status periodically
                try:
                    status = api_client.get_packet_capture_status(capture_id, vdom)
                    results = status.get("results", {})
                    if isinstance(results, list) and results:
                        results = results[0]
                    packet_count = results.get("packet-count", 0)
                    state = results.get("state", "unknown")
                    self.logger.info(f"Capture status: {state}, packets: {packet_count}, elapsed: {int(elapsed)}s")

                    # Stop early if max packets reached
                    if packet_count >= max_packet_count:
                        self.logger.info(f"Max packet count ({max_packet_count}) reached, stopping early")
                        break
                except Exception as e:
                    self.logger.warning(f"Could not get capture status: {e}")

            # Step 4: Stop capture
            self.logger.info(f"Stopping packet capture {capture_id}")
            api_client.stop_packet_capture(capture_id, vdom)

            # Give it a moment to finalize
            time.sleep(2)

            # Step 5: Get final status
            final_status = api_client.get_packet_capture_status(capture_id, vdom)
            status_results = final_status.get("results", {})
            if isinstance(status_results, list) and status_results:
                status_results = status_results[0]

            final_packet_count = status_results.get("packet-count", 0)
            final_byte_count = status_results.get("byte-count", 0)

            # Step 6: Download capture
            self.logger.info(f"Downloading capture data...")
            download_result = api_client.download_packet_capture(capture_id, vdom)

            # Extract PCAP data
            pcap_data = None
            download_results = download_result.get("results", {})
            if isinstance(download_results, list) and download_results:
                download_results = download_results[0]

            if download_results.get("data"):
                # Base64 encoded data
                try:
                    pcap_data = base64.b64decode(download_results["data"])
                except Exception as e:
                    self.logger.warning(f"Failed to decode base64 data: {e}")
            elif download_results.get("file"):
                # File content directly
                pcap_data = download_results["file"]
                if isinstance(pcap_data, str):
                    pcap_data = pcap_data.encode()

            # Step 7: Save to temp file and analyze
            analysis_results = {
                "capture_summary": {
                    "device_id": resolved_device_id,
                    "capture_id": capture_id,
                    "interface": interface,
                    "filter": filter_str or "none",
                    "duration_seconds": int(time.time() - start_time),
                    "packets_captured": final_packet_count,
                    "bytes_captured": final_byte_count,
                    "timestamp": datetime.now().isoformat()
                },
                "analysis": {},
                "pcap_file": None
            }

            if pcap_data and len(pcap_data) > 0:
                # Save to temp file
                with tempfile.NamedTemporaryFile(
                    mode='wb',
                    suffix='.pcap',
                    prefix=f'fortigate_capture_{capture_id}_',
                    delete=False
                ) as f:
                    f.write(pcap_data)
                    pcap_path = f.name

                analysis_results["pcap_file"] = pcap_path
                self.logger.info(f"Saved capture to: {pcap_path}")

                # Try tshark analysis first
                tshark_analysis = self._analyze_pcap_with_tshark(pcap_path)
                if tshark_analysis["available"]:
                    analysis_results["analysis"] = tshark_analysis
                else:
                    # Fall back to basic analysis
                    analysis_results["analysis"] = self._analyze_pcap_basic(pcap_data)
                    analysis_results["analysis"]["note"] = "tshark not available, using basic analysis"
            else:
                analysis_results["analysis"]["error"] = "No capture data available - capture may be empty"

            # Step 8: Cleanup if requested
            if cleanup and capture_id:
                try:
                    self.logger.info(f"Cleaning up capture profile {capture_id}")
                    api_client.delete_packet_capture(capture_id, vdom)
                    analysis_results["capture_summary"]["cleaned_up"] = True
                except Exception as e:
                    self.logger.warning(f"Failed to cleanup capture profile: {e}")
                    analysis_results["capture_summary"]["cleaned_up"] = False

            # Format output
            return self._format_capture_analysis(analysis_results)

        except Exception as e:
            # Attempt cleanup on error
            if capture_id and cleanup:
                try:
                    api_client = self._get_device_api(device_id)
                    api_client.stop_packet_capture(capture_id, vdom)
                    api_client.delete_packet_capture(capture_id, vdom)
                except Exception:
                    pass
            return self._handle_error("capture and analyze", device_id, e)

    def _format_capture_analysis(self, results: Dict[str, Any]) -> List[Content]:
        """Format capture analysis results for display.

        Args:
            results: Analysis results dictionary

        Returns:
            List of Content objects with formatted analysis
        """
        lines = ["Packet Capture Analysis", "=" * 50, ""]

        # Capture summary
        summary = results.get("capture_summary", {})
        lines.extend([
            "Capture Summary:",
            f"  Device: {summary.get('device_id', 'N/A')}",
            f"  Capture ID: {summary.get('capture_id', 'N/A')}",
            f"  Interface: {summary.get('interface', 'N/A')}",
            f"  Filter: {summary.get('filter', 'none')}",
            f"  Duration: {summary.get('duration_seconds', 0)} seconds",
            f"  Packets Captured: {summary.get('packets_captured', 0)}",
            f"  Bytes Captured: {summary.get('bytes_captured', 0)}",
            f"  Timestamp: {summary.get('timestamp', 'N/A')}",
            ""
        ])

        if results.get("pcap_file"):
            lines.extend([
                f"PCAP File: {results['pcap_file']}",
                ""
            ])

        # Analysis results
        analysis = results.get("analysis", {})
        if analysis.get("error"):
            lines.extend([
                "Analysis Error:",
                f"  {analysis['error']}",
                ""
            ])
        elif analysis.get("tool") == "tshark":
            lines.extend([
                "Analysis (tshark):",
                "-" * 40,
                ""
            ])

            if analysis.get("summary", {}).get("io_stats"):
                lines.extend([
                    "I/O Statistics:",
                    analysis["summary"]["io_stats"],
                    ""
                ])

            if analysis.get("summary", {}).get("protocol_hierarchy"):
                lines.extend([
                    "Protocol Hierarchy:",
                    analysis["summary"]["protocol_hierarchy"],
                    ""
                ])

            if analysis.get("summary", {}).get("ip_conversations"):
                lines.extend([
                    "IP Conversations:",
                    analysis["summary"]["ip_conversations"],
                    ""
                ])

            if analysis.get("summary", {}).get("tcp_conversations"):
                lines.extend([
                    "TCP Conversations:",
                    analysis["summary"]["tcp_conversations"],
                    ""
                ])

            if analysis.get("summary", {}).get("ip_endpoints"):
                lines.extend([
                    "IP Endpoints:",
                    analysis["summary"]["ip_endpoints"],
                    ""
                ])

            if analysis.get("errors"):
                lines.extend([
                    "Analysis Warnings:",
                    *[f"  - {err}" for err in analysis["errors"]],
                    ""
                ])

        elif analysis.get("tool") == "basic":
            lines.extend([
                "Analysis (basic):",
                "-" * 40,
                f"  File Size: {analysis.get('file_size_bytes', 0)} bytes",
                f"  Packet Count: {analysis.get('packet_count', 0)}",
                f"  Format: {analysis.get('capture_info', {}).get('format', 'unknown')}",
                ""
            ])
            if analysis.get("note"):
                lines.append(f"  Note: {analysis['note']}")
                lines.append("")

        if summary.get("cleaned_up"):
            lines.append("Capture profile has been cleaned up.")
        elif summary.get("cleaned_up") is False:
            lines.append("Warning: Failed to clean up capture profile.")

        return [Content(type="text", text="\n".join(lines))]

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
                },
                {
                    "name": "capture_and_analyze",
                    "description": "Capture traffic for a duration and analyze results",
                    "parameters": [
                        {"name": "device_id", "type": "string", "required": True},
                        {"name": "interface", "type": "string", "required": False, "default": "any"},
                        {"name": "host", "type": "string", "required": False},
                        {"name": "src_ip", "type": "string", "required": False},
                        {"name": "dst_ip", "type": "string", "required": False},
                        {"name": "protocol", "type": "string", "required": False},
                        {"name": "port", "type": "integer", "required": False},
                        {"name": "duration_seconds", "type": "integer", "required": False, "default": 120},
                        {"name": "max_packet_count", "type": "integer", "required": False, "default": 10000},
                        {"name": "cleanup", "type": "boolean", "required": False, "default": True},
                        {"name": "vdom", "type": "string", "required": False}
                    ]
                }
            ]
        }
