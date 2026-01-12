# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FortiGate MCP Server is a Model Context Protocol (MCP) server for managing FortiGate firewall devices. It exposes FortiGate REST API operations as MCP tools for integration with AI assistants and automation systems like Cursor IDE.

## Common Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest                           # All tests with coverage
python -m pytest tests/test_tools.py       # Single test file
python -m pytest -k "test_list_devices"    # Single test by name
python -m pytest --no-cov                  # Skip coverage

# Linting
black src tests                            # Format code
isort src tests                            # Sort imports
flake8 src tests                           # Lint
mypy src                                   # Type check

# Start server
python -m src.fortigate_mcp.server_http --host 0.0.0.0 --port 8814 --config config/config.json

# Docker
docker-compose up -d
```

## Architecture

### Server Layer
Two server implementations share the same tool infrastructure:
- `server.py` - STDIO transport for CLI/pipe integration, uses `mcp.run_stdio_async()`
- `server_http.py` - HTTP transport for web integration, uses `mcp.run(transport="http")`

Both instantiate `FortiGateMCPServer`/`FortiGateMCPHTTPServer` which:
1. Loads config via `config/loader.py` → validates with Pydantic models in `config/models.py`
2. Creates `FortiGateManager` with configured devices
3. Instantiates tool classes (`DeviceTools`, `FirewallTools`, etc.)
4. Registers MCP tools via `@self.mcp.tool()` decorators

### Core Layer (`core/`)
- `FortiGateManager` - Multi-device manager, maintains dict of `FortiGateAPI` instances by device_id
- `FortiGateAPI` - Single device client, wraps all FortiGate REST API calls via `_make_request()`
- API base URL pattern: `https://{host}:{port}/api/v2/{endpoint}`
- Auth: Bearer token (`api_token`) or Basic auth (`username/password`)

### Tools Layer (`tools/`)
All tools inherit from `FortiGateTool` base class which provides:
- `_get_device_api(device_id)` - Get API client for device
- `_format_response(data, resource_type)` - Format API responses via `FortiGateFormatters`
- `_handle_error(operation, device_id, error)` - Standardized error handling with HTTP status code mapping
- `_execute_with_logging()` - Async execution wrapper with timing

Tool categories map to FortiGate API endpoints:
| Tool Class | API Endpoints |
|------------|---------------|
| `DeviceTools` | `monitor/system/status`, `cmdb/system/vdom` |
| `FirewallTools` | `cmdb/firewall/policy` |
| `NetworkTools` | `cmdb/firewall/address`, `cmdb/firewall.service/custom` |
| `RoutingTools` | `cmdb/router/static`, `monitor/router/ipv4` |
| `VirtualIPTools` | `cmdb/firewall/vip` |
| `CertificateTools` | `cmdb/certificate/local`, `cmdb/certificate/ca`, `cmdb/certificate/remote`, `cmdb/certificate/crl` |

### Configuration
Config is loaded from JSON file specified by `--config` flag or `FORTIGATE_MCP_CONFIG` env var.
Root model: `Config` in `config/models.py` containing:
- `server` - Host/port/name
- `fortigate.devices` - Dict of `FortiGateDeviceConfig` keyed by device_id
- `auth` - MCP server auth (not FortiGate auth)
- `logging` - Log level/format/file
- `rate_limiting` - Request throttling

### Response Formatting (`formatting/`)
`FortiGateFormatters` class provides specialized formatters for each resource type, converting API responses to human-readable MCP `TextContent` objects.

## Key Patterns

- All device operations require `device_id` parameter to select which FortiGate to target
- Optional `vdom` parameter on most operations (defaults to device's configured vdom)
- HTTP server tests device connections on startup via `_test_initial_connection()`
- Tool descriptions in `tools/definitions.py` are used for MCP tool registration

## FortiGate REST API Reference

The server wraps FortiGate's REST API v2. Key endpoint patterns:

| Type | URL Pattern | Purpose |
|------|-------------|---------|
| CMDB | `/api/v2/cmdb/{section}/{subsection}` | Configuration (CRUD operations) |
| Monitor | `/api/v2/monitor/{section}/{subsection}` | Runtime data and statistics |

Common CMDB paths used by this server:
- `firewall/policy` - Firewall rules
- `firewall/address` - Address objects
- `firewall.service/custom` - Service objects
- `router/static` - Static routes
- `firewall/vip` - Virtual IPs
- `system/interface` - Network interfaces
- `system/vdom` - Virtual domains
- `certificate/local` - Local/device certificates
- `certificate/ca` - CA certificates
- `certificate/remote` - Remote certificates
- `certificate/crl` - Certificate revocation lists

All requests include `?vdom={vdom}` query parameter.

## MCP Protocol Notes

This server implements the Model Context Protocol using FastMCP:
- Tools return `List[TextContent]` (via `mcp.types.TextContent`)
- JSON-RPC 2.0 message format over STDIO or HTTP transport
- Tool schemas auto-generated from Python type annotations and `Field()` descriptions
- Errors returned as `{"isError": true}` in tool results, not protocol-level errors
