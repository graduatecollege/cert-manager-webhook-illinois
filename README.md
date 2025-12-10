<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>

# cert-manager Webhook for Illinois Infoblox

This is a cert-manager ACME DNS01 webhook solver for the Illinois Infoblox DNS system.

This webhook solver integrates with the Illinois Infoblox WAPI (Web API) to automatically create and delete DNS TXT records required for ACME DNS-01 challenge validation.

## Supported Infoblox Hosts

- Production: `ipam.illinois.edu`
- Development: `dev.ipam.illinois.edu`

## Why not in core?

As the project & adoption has grown, there has been an influx of DNS provider
pull requests to our core codebase. As this number has grown, the test matrix
has become un-maintainable and so, it's not possible for us to certify that
providers work to a sufficient level.

By creating this 'interface' between cert-manager and DNS providers, we allow
users to quickly iterate and test out new integrations, and then packaging
those up themselves as 'extensions' to cert-manager.

We can also then provide a standardised 'testing framework', or set of
conformance tests, which allow us to validate that a DNS provider works as
expected.

## Creating your own webhook

Webhook's themselves are deployed as Kubernetes API services, in order to allow
administrators to restrict access to webhooks with Kubernetes RBAC.

This is important, as otherwise it'd be possible for anyone with access to your
webhook to complete ACME challenge validations and obtain certificates.

To make the set up of these webhook's easier, we provide a template repository
that can be used to get started quickly.

When implementing your webhook, you should set the `groupName` in the
[values.yml](deploy/example-webhook/values.yaml) of your chart to a domain name that 
you - as the webhook-author - own. It should not need to be adjusted by the users of
your chart.

### Creating your own repository

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

An example Go test file has been provided in [main_test.go](https://github.com/cert-manager/webhook-example/blob/master/main_test.go).

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com. make test
```

The example file has a number of areas you must fill in and replace with your
own options in order for tests to pass.

## Configuration

### Prerequisites

1. Access to Illinois Infoblox system (ipam.illinois.edu or dev.ipam.illinois.edu)
2. Valid Infoblox credentials (username and password)
3. cert-manager installed in your Kubernetes cluster

### Installation

1. Create a secret with your Infoblox credentials:

```bash
kubectl create secret generic infoblox-credentials \
  --from-literal=username=<your-username> \
  --from-literal=password=<your-password> \
  -n cert-manager
```

2. Deploy the webhook:

```bash
helm install infoblox-webhook ./deploy/example-webhook \
  --namespace cert-manager \
  --set groupName=acme.illinois.edu
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
          groupName: acme.illinois.edu
          solverName: infoblox
          config:
            host: ipam.illinois.edu
            version: v2.12
            view: default
            usernameSecretRef:
              name: infoblox-credentials
              key: username
            passwordSecretRef:
              name: infoblox-credentials
              key: password
```

### Configuration Options

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `host` | Yes | - | Infoblox WAPI host (e.g., ipam.illinois.edu or dev.ipam.illinois.edu) |
| `version` | No | v2.12 | Infoblox WAPI version |
| `view` | No | default | DNS view name |
| `usernameSecretRef` | Yes | - | Reference to secret containing username |
| `passwordSecretRef` | Yes | - | Reference to secret containing password |
| `skipTLSVerify` | No | false | Skip TLS certificate verification (not recommended for production) |

### Development

For development against the dev.ipam.illinois.edu server:

```yaml
config:
  host: dev.ipam.illinois.edu
  version: v2.12
  view: default
  skipTLSVerify: false  # Set to true only if needed for testing
  usernameSecretRef:
    name: infoblox-credentials
    key: username
  passwordSecretRef:
    name: infoblox-credentials
    key: password
```

## Testing

Run the test suite:

```bash
TEST_ZONE_NAME=example.com. make test
```

Note: The conformance tests use a mock DNS server. To test against actual Infoblox, you need to configure the test environment with valid credentials.

## Troubleshooting

### Common Issues

1. **Authentication Failures**: Verify your credentials are correct and the secret is in the same namespace as the certificate.

2. **TXT Record Not Created**: Check the webhook logs for detailed error messages:
   ```bash
   kubectl logs -n cert-manager deployment/infoblox-webhook
   ```

3. **Permissions**: Ensure your Infoblox user has permissions to create and delete TXT records in the specified view.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
