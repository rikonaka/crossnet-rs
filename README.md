# cross-net

`crossnet` is a cross-platform Rust library for network path introspection.

Given a destination IP, it helps you resolve routing details such as **dev/interface**, **via/gateway**, and **src/preferred source IP** across **Linux, Windows, macOS**.  
It also provides neighbor lookup capabilities (e.g. **IP → MAC** via ARP/NDP), making it easier to build diagnostics, observability, and network tooling in a unified way.

## Features

- Cross-platform route resolution
- Routing table parsing and normalization
- Destination-based best-route lookup (`dev`, `via`, `src`, etc.)
- Neighbor discovery lookup (`IP -> MAC`)
- Consistent Rust API across different OS backends

## Use Cases

- Network diagnostics CLI tools
- Agent/daemon connectivity checks
- Multi-platform infrastructure tooling
- Troubleshooting route and neighbor state

## Status

Early stage, API may evolve.
Contributions and feedback are welcome.