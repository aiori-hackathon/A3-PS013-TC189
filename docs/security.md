# Security

- Evidence files are preserved separately from reports.
- Uploads are validated by extension and size.
- Evidence hashes detect modification after collection.
- No secrets are embedded in code; database URLs come from environment variables.
- The application is intended for local or trusted-network use.
- Agent bearer tokens are stored as SHA-256 hashes.
- Authorization is not implemented beyond deployment-level controls.
