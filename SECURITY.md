# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.
Use GitHub's **"Report a vulnerability"** button (Security → Advisories) on this repository instead.
We aim to respond within 7 days.

## Threat model (summary)

| Threat | Mitigation |
|---|---|
| Eavesdropping on the network | WebRTC DTLS/SRTP end-to-end encryption |
| Malicious / compromised signaling server (MITM) | 8-digit security code from both DTLS fingerprints; unattended-access proof is bound to those fingerprints |
| Connection without consent | Explicit accept dialog, 60 s timeout, one session at a time |
| Password guessing | PBKDF2-SHA256 (210k), HMAC challenge/response with fresh nonce per attempt, 5 attempts → 5 min lockout |
| Malicious files | Sanitized names, size limit, saved to `Downloads\NexDesk` only, never auto-opened |
| Renderer compromise | Sandbox, context isolation, strict CSP, validated IPC, numeric-only input protocol |

## Known limitations

- The executable is not code-signed yet.
- Unattended-access verifier is stored in the user profile (`%APPDATA%\NexDesk\config.json`);
  anyone with access to that user account can read it.
- Input cannot be injected into elevated (Administrator) windows unless NexDesk itself runs elevated
  (a Windows UIPI restriction), and the secure desktop (UAC prompt, Ctrl+Alt+Del) cannot be controlled.
