# Security Policy

## Scope
- This project demonstrates Bitcoin signature analysis for audit and education. It must not be used for unauthorized access or wallet draining.
- No private keys or seeds should ever be provided to the application. The server rejects oversized or suspicious payloads.

## Reporting Vulnerabilities
- Please open a private security advisory or contact the maintainers with details.
- Include reproduction steps, impacted endpoints, and any logs you can share without exposing secrets.

## Operational Guidance
- Run behind HTTPS and with trusted explorer endpoints.
- Configure `LOG_LEVEL` and monitor logs for repeated failures that may indicate abuse.
- Keep dependencies updated and run the provided validation tests before deployment.
