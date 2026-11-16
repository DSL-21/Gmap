# Security Policy

## Supported versions

Only the latest published Gmap release is supported for security fixes. Older release APKs are not maintained.

## Reporting a vulnerability

Please do not publish suspected vulnerabilities, exploit details, private network data or personal information in a public issue.

Use GitHub's private vulnerability reporting feature for this repository when available. Include the affected release/commit, Android version and device model, concise reproduction steps, expected versus observed behaviour, and logs with secrets and IP addresses redacted.

## Intended security boundary

Gmap is a user-operated, read-only network inspection tool. It is not intended to exploit hosts, authenticate to services, brute-force credentials, execute commands on targets, or perform background scanning. Use it only on systems you own or are authorized to assess.

The current Web audit has a documented DNS-rebinding limitation because DNS results are not pinned to the socket connection. Do not audit untrusted hostnames. HTTP auditing is intentionally supported and is unencrypted; never enter credentials or sensitive URL parameters.
