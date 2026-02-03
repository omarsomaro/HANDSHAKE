# Contributing to Handshake

Contributions are welcome! Please follow these guidelines when contributing to this project.

## Code of Conduct

Please read and follow our Code of Conduct to ensure a welcoming environment for all contributors.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/yourusername/handshake.git
   cd handshake
   ```
3. Ensure you have Rust 1.70+ installed:
   ```bash
   rustc --version
   ```
4. Build the project:
   ```bash
   cargo build --release
   ```

## Development Setup

```bash
# Clone and build
git clone https://github.com/yourusername/handshake.git
cd handshake
cargo build --release

# Run tests
cargo test

# Feature combinations
cargo test --no-default-features
cargo test --no-default-features --features pq
cargo test --no-default-features --features quic
cargo test --no-default-features --features webrtc

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the existing code style

3. Add or update tests as necessary

4. Ensure all checks pass:
   ```bash
   cargo test
   cargo fmt
   cargo clippy
   ```

5. Update documentation if needed

6. Commit with clear, descriptive messages:
   ```bash
   git commit -m "feat: add new DPI evasion technique"
   ```

We follow conventional commits format:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `test:` test additions/modifications
- `refactor:` code refactoring
- `perf:` performance improvements

## Testing

Before submitting a PR, ensure:
- All existing tests pass: `cargo test`
- Feature combinations compile and pass
- Ignored integration tests are run when relevant (see docs/testing.md)
- New features have tests
- Integration tests run successfully
- No warnings from `cargo clippy`
- Code is formatted with `cargo fmt`

## Documentation

- Update README.md for user-facing changes
- Update docs/ for new features
- Add code comments for complex logic
- Update CHANGELOG.md

## Security Issues

Please report security vulnerabilities privately via SECURITY.md, not through public issues.

## Questions?

Feel free to open an issue for questions or join our discussions.

Thank you for contributing!
