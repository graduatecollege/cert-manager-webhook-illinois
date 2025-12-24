# cert-manager Webhook for Illinois Infoblox

This is a cert-manager ACME DNS01 webhook solver for the Illinois Infoblox DNS system.

## Configuration

### Prerequisites

1. Access to Illinois Infoblox system (IPAM)
2. Valid Infoblox credentials (username and password)
3. The account being used must be exempt from 2FA,
   see [Using the IPAM API](https://netwiki.techservices.illinois.edu/public/home/ipamdocs/using-ipam/using-the-ipam-api/).
4. cert-manager installed in your Kubernetes cluster

### Installation

1. Create a secret with your Infoblox credentials as files:

   ```bash
   kubectl create secret generic infoblox-credentials \
     --from-literal=username=<your-username> \
     --from-literal=password=<your-password> \
     -n cert-manager
   ```

2. Deploy the webhook with credential volume mounts:

   The webhook deployment should mount the credentials secret as volume files. Update your
   `deploy/example-webhook/templates/deployment.yaml` to include:

   ```yaml
   volumeMounts:
     - name: infoblox-credentials
       mountPath: /etc/infoblox
       readOnly: true
   volumes:
     - name: infoblox-credentials
       secret:
         secretName: infoblox-credentials
   ```

3. Install the webhook:

   ```bash
   helm install infoblox-webhook ./deploy/example-webhook \
     --namespace cert-manager \
     --set groupName=ipam.illinois.edu
   ```

### Issuer Configuration

Create an Issuer or ClusterIssuer with the Infoblox webhook configuration:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: letsencrypt-staging
  namespace: default
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: your-email@example.com
    privateKeySecretRef:
      name: letsencrypt-staging
    solvers:
      - dns01:
          webhook:
            groupName: ipam.illinois.edu
            solverName: infoblox
            config:
              host: ipam.illinois.edu
              version: v2.12
              view: default
              usernameFile: /etc/infoblox/username
              passwordFile: /etc/infoblox/password
```

### Configuration Options

| Field           | Required | Default                | Description                                                           |
|-----------------|----------|------------------------|-----------------------------------------------------------------------|
| `host`          | Yes      | -                      | Infoblox WAPI host (e.g., ipam.illinois.edu or dev.ipam.illinois.edu) |
| `version`       | No       | v2.12                  | Infoblox WAPI version                                                 |
| `view`          | No       | default                | DNS view name                                                         |
| `ttl`           | No       | 300                    | DNS record TTL in seconds                                             |
| `usernameFile`  | No       | /etc/infoblox/username | Path to file containing username (mounted from secret)                |
| `passwordFile`  | No       | /etc/infoblox/password | Path to file containing password (mounted from secret)                |
| `skipTLSVerify` | No       | false                  | Skip TLS certificate verification (not recommended for production)    |

## Testing

The above [Configuration Options](#configuration-options) are also defined in `testdata/infoblox/config.json`.

Place your credentials in this repository under `./etc/username` and `./etc/password` or modify the paths in
`testdata/infoblox/config.json` to point to your credential files.

> [!WARNING]
> The tests don't currently work against the dev environment because not all the nameservers
> for `dev.ipam.illinois.edu` work, and the cert-manager test suite validates against all nameservers.

Run the test suite. **Note** that you must be on the University of Illinois network or connected via VPN.

```bash
TEST_ZONE_NAME=grad.illinois.edu. make test
```
