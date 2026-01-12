"""
FortiManager API management for the MCP server.

This module provides FortiManager JSON-RPC API integration:
- Session management with authentication
- Device management across the fabric
- Policy package management
- Centralized configuration retrieval
"""
import logging
import time
from typing import Dict, Any, Optional, List
import httpx
import json
from .logging import get_logger, log_api_call


class FortiManagerAPIError(Exception):
    """Custom exception for FortiManager API errors."""

    def __init__(self, message: str, error_code: Optional[int] = None):
        super().__init__(message)
        self.error_code = error_code


class FortiManagerAPI:
    """FortiManager JSON-RPC API client.

    Handles all communication with FortiManager:
    - Session-based authentication
    - JSON-RPC request/response processing
    - Device and policy management
    """

    def __init__(
        self,
        host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 30,
        adom: str = "root"
    ):
        """Initialize FortiManager API client.

        Args:
            host: FortiManager hostname or IP
            api_token: API token for authentication
            username: Username for session authentication
            password: Password for session authentication
            port: HTTPS port (default 443)
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            adom: Administrative Domain (default "root")
        """
        self.host = host
        self.port = port
        self.api_token = api_token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.adom = adom

        self.base_url = f"https://{host}:{port}/jsonrpc"
        self.session_id: Optional[str] = None
        self.request_id = 1
        self.logger = get_logger("fortimanager")

        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        self.logger.info(f"Initialized FortiManager API client for {host}")

    def _get_request_id(self) -> int:
        """Get next request ID for JSON-RPC."""
        req_id = self.request_id
        self.request_id += 1
        return req_id

    def _make_request(
        self,
        method: str,
        params: Optional[List[Dict]] = None,
        url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make JSON-RPC request to FortiManager.

        Args:
            method: JSON-RPC method name
            params: List of parameter dictionaries
            url: URL path within params (for API calls)

        Returns:
            API response data

        Raises:
            FortiManagerAPIError: If request fails
        """
        if params is None:
            params = [{}]

        # Add session ID if we have one (not needed for login)
        if self.session_id and method != "exec":
            for param in params:
                if "session" not in param:
                    param["session"] = self.session_id
        elif self.session_id:
            # For exec method, session goes in first param
            if params and "session" not in params[0]:
                params[0]["session"] = self.session_id

        payload = {
            "id": self._get_request_id(),
            "method": method,
            "params": params
        }

        # Add API token to headers if using token auth
        headers = self.headers.copy()
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"

        start_time = time.time()

        try:
            with httpx.Client(
                verify=self.verify_ssl,
                timeout=self.timeout
            ) as client:
                response = client.post(
                    self.base_url,
                    headers=headers,
                    json=payload
                )

                duration_ms = (time.time() - start_time) * 1000
                log_api_call(self.logger, "POST", method, response.status_code, duration_ms)

                if response.status_code != 200:
                    raise FortiManagerAPIError(
                        f"HTTP error: {response.status_code}",
                        error_code=response.status_code
                    )

                result = response.json()

                # Check for JSON-RPC error
                if "error" in result and result["error"]:
                    error = result["error"]
                    raise FortiManagerAPIError(
                        f"API error: {error.get('message', str(error))}",
                        error_code=error.get("code")
                    )

                # Check result status
                if "result" in result:
                    res_data = result["result"]
                    if isinstance(res_data, list) and len(res_data) > 0:
                        status = res_data[0].get("status", {})
                        if isinstance(status, dict) and status.get("code", 0) != 0:
                            raise FortiManagerAPIError(
                                f"API error: {status.get('message', 'Unknown error')}",
                                error_code=status.get("code")
                            )
                        return res_data[0]
                    return res_data

                return result

        except httpx.RequestError as e:
            duration_ms = (time.time() - start_time) * 1000
            log_api_call(self.logger, "POST", method, None, duration_ms)
            raise FortiManagerAPIError(f"Network error: {str(e)}")

    def login(self) -> bool:
        """Login to FortiManager and establish session.

        Returns:
            True if login successful

        Raises:
            FortiManagerAPIError: If login fails
        """
        if self.api_token:
            # Token auth doesn't need explicit login
            self.logger.info("Using API token authentication")
            return True

        if not self.username or not self.password:
            raise FortiManagerAPIError("Username and password required for session auth")

        params = [{
            "url": "/sys/login/user",
            "data": {
                "user": self.username,
                "passwd": self.password
            }
        }]

        result = self._make_request("exec", params)

        if "session" in result:
            self.session_id = result["session"]
            self.logger.info("Login successful")
            return True

        raise FortiManagerAPIError("Login failed: no session returned")

    def logout(self) -> bool:
        """Logout from FortiManager.

        Returns:
            True if logout successful
        """
        if not self.session_id:
            return True

        try:
            params = [{
                "url": "/sys/logout",
                "session": self.session_id
            }]
            self._make_request("exec", params)
            self.session_id = None
            self.logger.info("Logout successful")
            return True
        except Exception as e:
            self.logger.warning(f"Logout error: {e}")
            self.session_id = None
            return False

    def test_connection(self) -> bool:
        """Test connection to FortiManager.

        Returns:
            True if connection successful
        """
        try:
            self.get_system_status()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

    # System endpoints
    def get_system_status(self) -> Dict[str, Any]:
        """Get FortiManager system status."""
        params = [{
            "url": "/sys/status"
        }]
        return self._make_request("get", params)

    def get_adoms(self) -> Dict[str, Any]:
        """Get list of Administrative Domains."""
        params = [{
            "url": "/dvmdb/adom"
        }]
        return self._make_request("get", params)

    # Device management
    def get_devices(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get managed devices.

        Args:
            adom: Administrative Domain (uses default if not specified)
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device"
        }]
        return self._make_request("get", params)

    def get_device_detail(self, device_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get detailed device information.

        Args:
            device_name: Device name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device/{device_name}"
        }]
        return self._make_request("get", params)

    def get_device_status(self, device_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get device connection and sync status.

        Args:
            device_name: Device name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device/{device_name}",
            "fields": ["name", "hostname", "ip", "conn_status", "conf_status",
                      "db_status", "dev_status", "os_type", "os_ver", "platform_str",
                      "sn", "ha_mode", "ha_slave"]
        }]
        return self._make_request("get", params)

    def get_all_devices_status(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get status for all managed devices.

        Args:
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/dvmdb/adom/{adom}/device",
            "fields": ["name", "hostname", "ip", "conn_status", "conf_status",
                      "db_status", "dev_status", "os_type", "os_ver", "platform_str",
                      "sn", "ha_mode", "ha_slave", "mgmt_mode", "flags"]
        }]
        return self._make_request("get", params)

    # Policy package management
    def get_policy_packages(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get policy packages.

        Args:
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/pm/pkg/adom/{adom}"
        }]
        return self._make_request("get", params)

    def get_policy_package_detail(self, pkg_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get policy package details.

        Args:
            pkg_name: Policy package name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/pm/pkg/adom/{adom}/{pkg_name}"
        }]
        return self._make_request("get", params)

    def get_firewall_policies(self, pkg_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall policies from a policy package.

        Args:
            pkg_name: Policy package name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/pm/config/adom/{adom}/pkg/{pkg_name}/firewall/policy"
        }]
        return self._make_request("get", params)

    # Address objects
    def get_address_objects(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall address objects.

        Args:
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/pm/config/adom/{adom}/obj/firewall/address"
        }]
        return self._make_request("get", params)

    # Service objects
    def get_service_objects(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get firewall service objects.

        Args:
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/pm/config/adom/{adom}/obj/firewall/service/custom"
        }]
        return self._make_request("get", params)

    # Certificate management
    def get_certificates(self, device_name: str, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get certificates from a managed device.

        Args:
            device_name: Device name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": f"/pm/config/device/{device_name}/vdom/root/vpn/certificate/local"
        }]
        return self._make_request("get", params)

    # Task management
    def get_task_status(self, task_id: int) -> Dict[str, Any]:
        """Get status of an asynchronous task.

        Args:
            task_id: Task ID
        """
        params = [{
            "url": f"/task/task/{task_id}"
        }]
        return self._make_request("get", params)

    # Script execution
    def run_script(
        self,
        script_name: str,
        device_name: str,
        adom: Optional[str] = None
    ) -> Dict[str, Any]:
        """Run a script on a device.

        Args:
            script_name: Name of the script
            device_name: Target device name
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": "/dvmdb/adom/{adom}/script/execute",
            "data": {
                "adom": adom,
                "script": script_name,
                "scope": [{
                    "name": device_name,
                    "vdom": "root"
                }]
            }
        }]
        return self._make_request("exec", params)

    # Install/sync operations
    def install_policy(
        self,
        pkg_name: str,
        device_name: str,
        adom: Optional[str] = None,
        vdom: str = "root"
    ) -> Dict[str, Any]:
        """Install policy package to a device.

        Args:
            pkg_name: Policy package name
            device_name: Target device name
            adom: Administrative Domain
            vdom: Virtual Domain on target device
        """
        adom = adom or self.adom
        params = [{
            "url": "/securityconsole/install/package",
            "data": {
                "adom": adom,
                "pkg": pkg_name,
                "scope": [{
                    "name": device_name,
                    "vdom": vdom
                }]
            }
        }]
        return self._make_request("exec", params)

    def get_install_status(self, adom: Optional[str] = None) -> Dict[str, Any]:
        """Get installation status.

        Args:
            adom: Administrative Domain
        """
        adom = adom or self.adom
        params = [{
            "url": "/securityconsole/install/status",
            "data": {
                "adom": adom
            }
        }]
        return self._make_request("get", params)


class FortiManagerManager:
    """Manager for FortiManager instances.

    Handles FortiManager registration and provides unified access.
    """

    def __init__(self):
        """Initialize FortiManager manager."""
        self.managers: Dict[str, FortiManagerAPI] = {}
        self.logger = get_logger("fortimanager_manager")

    def add_manager(
        self,
        manager_id: str,
        host: str,
        api_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 30,
        adom: str = "root"
    ) -> FortiManagerAPI:
        """Add a FortiManager instance.

        Args:
            manager_id: Unique identifier for this FortiManager
            host: FortiManager hostname or IP
            api_token: API token for authentication
            username: Username for session authentication
            password: Password for session authentication
            port: HTTPS port
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            adom: Default Administrative Domain

        Returns:
            FortiManagerAPI instance
        """
        if manager_id in self.managers:
            raise ValueError(f"Manager '{manager_id}' already exists")

        fmg = FortiManagerAPI(
            host=host,
            api_token=api_token,
            username=username,
            password=password,
            port=port,
            verify_ssl=verify_ssl,
            timeout=timeout,
            adom=adom
        )

        self.managers[manager_id] = fmg
        self.logger.info(f"Added FortiManager: {manager_id}")
        return fmg

    def get_manager(self, manager_id: str) -> FortiManagerAPI:
        """Get FortiManager API client.

        Args:
            manager_id: Manager identifier

        Returns:
            FortiManagerAPI instance
        """
        if manager_id not in self.managers:
            raise ValueError(f"Manager '{manager_id}' not found")
        return self.managers[manager_id]

    def remove_manager(self, manager_id: str) -> None:
        """Remove a FortiManager instance.

        Args:
            manager_id: Manager identifier to remove
        """
        if manager_id not in self.managers:
            raise ValueError(f"Manager '{manager_id}' not found")

        # Try to logout cleanly
        try:
            self.managers[manager_id].logout()
        except:
            pass

        del self.managers[manager_id]
        self.logger.info(f"Removed FortiManager: {manager_id}")

    def list_managers(self) -> List[str]:
        """List all registered FortiManager IDs.

        Returns:
            List of manager identifiers
        """
        return list(self.managers.keys())
