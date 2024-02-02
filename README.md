# app

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

### DDoS mitigation

Run BPF program:

```bash
RUST_LOG=info cargo xtask run --bin ddos_mitigation -- --port 80 --port 443 --pps 1
```

- The restricted local ports are `443` and `80`
- Restriction will be imposted if the packets per second exceed `1` for each port

Trust an IP:

```bash
curl -X PUT http://127.0.0.1:6969/ip/1.1.1.1
```

Forget an IP:

```bash
curl -X DELETE http://127.0.0.1:6969/ip/1.1.1.1
```
