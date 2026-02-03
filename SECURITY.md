# Security Policy

## Reporting Security Issues

Please report security vulnerabilities **privately** to our security team:

**Email**: `security@handshake-p2p.dev`

**Please DO NOT** report security issues through:
- Public GitHub issues
- Public discussions
- Public Discord/Telegram channels
- Twitter/Reddit/Social media

## Supported Versions

Only the **latest version** of Handshake is supported with security updates.

## Security Update Timeline

| Severity | Response Time | Fix Time | Disclosure |
|----------|--------------|----------|------------|
| **Critical** (RCE, key theft) | 24 hours | 7 days | Coordinated |
| **High** (DoS, metadata leak) | 48 hours | 30 days | After fix |
| **Medium** (Info disclosure) | 7 days | 90 days | After fix |
| **Low** (Best practices) | 30 days | Future release | Public |

## Security Features

Handshake includes multiple security layers:
- **Noise Protocol XX**: Forward-secret authenticated key exchange
- **XChaCha20-Poly1305**: Authenticated encryption
- **Argon2id**: Memory-hard key derivation
- **Replay Protection**: Counter-based sliding window
- **Zero-persistence**: RAM-only key storage
- **Early Drop**: Zero-cost DoS prevention

## PGP Key

For encrypted security communications, use our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Key will be added when available]
-----END PGP PUBLIC KEY BLOCK-----
```

## Bug Bounty

We currently do not have a formal bug bounty program, but critical security issues may be eligible for acknowledgment in release notes.

## Known Security Limitations

- **Passphrase entropy**: Security depends on strong passphrases (recommend 60+ characters)
- **Relay metadata**: WAN Assist relay sees encrypted offers and timing metadata
- **UPnP/NAT-PMP**: Gateway devices see port mappings (operational requirement)
- **LAN exposure**: Broadcast discovery visible on local network (stealth mode mitigates)
- **Tor: Use onion services for stronger anonymity

See [docs/threat_model_visibility.md](docs/threat_model_visibility.md) for detailed visibility analysis.

## Coordinated Disclosure

We practice responsible disclosure:
1. Vulnerability reported privately
2. We investigate and develop fix
3. Fix tested and validated
4. Coordinated release with reporter
5. Public disclosure after fix deployed

## Security Research

Security researchers are welcome to analyze Handshake. We request:
- Responsible disclosure to our security team
- Reasonable time to develop and deploy fixes
- Coordinated public disclosure with our timeline

## Security Resources

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Rust Security Guidelines](https://rust-lang.github.io/rust-clippy/master/index.html#correctness)
- [Our Threat Model](docs/threat_model_visibility.md)

## Contact

For non-security-related questions, please use regular GitHub issues or discussions.

For security issues only: security@handshake-p2p.dev

Response time: Typically within 48 hours for security reports.
