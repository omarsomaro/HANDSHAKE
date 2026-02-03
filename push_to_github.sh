#!/bin/bash
# Handshake Git Commands - Push to GitHub
# Replace 'omarsomaro' with your actual GitHub username

echo "=== Handshake GitHub Setup ==="

# 1. Initialize git repository (if not already initialized)
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
fi

# 2. Check git status
echo "Git status:"
git status

# 3. Add all files (excluding gitignored)
echo "Adding files to git..."
git add .

# 4. Check what was added
echo "Files that will be committed:"
git status --short

# 5. Create initial commit
echo "Creating initial commit..."
git commit -m "Initial commit: Handshake P2P communication framework

Features:
- Deterministic P2P communication without servers
- Multi-transport NAT traversal (LAN, UPnP/STUN, Relay, Tor)
- Noise protocol encryption (XChaCha20-Poly1305)
- Real TLS DPI evasion
- WebSocket/QUIC/HTTP2 mimicry
- TCP and ICMP hole punching
- Academic security case study
- Operational threat model analysis

Security: See docs/threat_model_visibility.md and SECURITY.md"

# 6. Add GitHub remote (replace with your username)
GITHUB_USER="YOUR_GITHUB_USERNAME"
REPO_NAME="handshacke"

echo "Adding GitHub remote..."
git remote add origin "https://github.com/${GITHUB_USER}/${REPO_NAME}.git"

# 7. Verify remote
echo "Git remote:"
git remote -v

# 8. Push to GitHub
echo "Pushing to GitHub..."
git push -u origin main

# 9. Verify
echo "Push completed!"
echo "View your repository at: https://github.com/${GITHUB_USER}/${REPO_NAME}"

echo ""
echo "=== Next Steps ==="
echo "1. Create GitHub release: git tag v0.1.0 && git push origin v0.1.0"
echo "2. Set up GitHub Actions for CI/CD"
echo "3. Enable Security tab in GitHub repository settings"
echo "4. Add repository topics: p2p, cryptography, privacy, rust"
echo "5. Pin important issues"

# Optional: Keep this script for future updates
echo ""
echo "For future commits:"
echo "git add ."
echo "git commit -m 'Your message'"
echo "git push"
