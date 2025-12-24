# Infoblox Solver Configuration

This directory contains the configuration for the Infoblox DNS solver.

## Configuration

The `config.json` file should contain:

- `host`: The Infoblox WAPI host (e.g., ipam.illinois.edu or dev.ipam.illinois.edu)
- `version`: The WAPI version (default: v2.12)
- `view`: The DNS view (default: default)
- `usernameFile`: Path to the file containing the username (default: /etc/infoblox/username)
- `passwordFile`: Path to the file containing the password (default: /etc/infoblox/password)
- `skipTLSVerify`: (optional) Skip TLS certificate verification

## Example

```json
{
  "host": "ipam.illinois.edu",
  "version": "v2.12",
  "view": "default",
  "usernameFile": "/etc/infoblox/username",
  "passwordFile": "/etc/infoblox/password"
}
```

## Mounting Credentials

Credentials should be mounted as volume files in the webhook container. For example, using a Kubernetes secret:

```yaml
volumes:
  - name: infoblox-credentials
    secret:
      secretName: infoblox-credentials
volumeMounts:
  - name: infoblox-credentials
    mountPath: /etc/infoblox
    readOnly: true
```
