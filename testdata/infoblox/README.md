# Infoblox Solver Configuration

This directory contains the configuration for the Infoblox DNS solver.

## Configuration

The `config.json` file should contain:

- `host`: The Infoblox WAPI host (e.g., ipam.illinois.edu or dev.ipam.illinois.edu)
- `version`: The WAPI version (default: v2.12)
- `view`: The DNS view (default: default)
- `usernameSecretRef`: Reference to the Kubernetes secret containing the username
- `passwordSecretRef`: Reference to the Kubernetes secret containing the password
- `skipTLSVerify`: (optional) Skip TLS certificate verification

## Example

```json
{
  "host": "ipam.illinois.edu",
  "version": "v2.12",
  "view": "default",
  "usernameSecretRef": {
    "name": "infoblox-credentials",
    "key": "username"
  },
  "passwordSecretRef": {
    "name": "infoblox-credentials",
    "key": "password"
  }
}
```
