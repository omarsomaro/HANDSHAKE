# Testing

## Unit tests
```
cargo test
```

## Feature combinations
```
cargo test --no-default-features
cargo test --no-default-features --features pq
cargo test --no-default-features --features quic
cargo test --no-default-features --features webrtc
```

## Ignored tests
Some tests require a real ICE/UDP environment and are marked ignored:
```
cargo test --test high_level_webrtc -- --ignored
```
