# Merkle Sum Sparse Merkle Tree

A Rust implementation of the Merkle Sum Sparse Merkle Tree (MSSMT) based on [Lightning Labs' implementation](https://github.com/lightninglabs/taproot-assets/tree/main/mssmt).


<a href="https://github.com/keep-starknet-strange/merkle-sum-sparse-merkle-tree/actions/workflows/ci.yml"><img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/keep-starknet-strange/merkle-sum-sparse-merkle-tree/ci.yml?style=for-the-badge" height=30></a>
<a href="https://bitcoin.org/"> <img alt="Bitcoin" src="https://img.shields.io/badge/Bitcoin-000?style=for-the-badge&logo=bitcoin&logoColor=white" height=30></a>
<a href="https://codecov.io/gh/keep-starknet-strange/mssmt-rs" ><img src="https://codecov.io/gh/keep-starknet-strange/mssmt-rs/graph/badge.svg?token=sgQKy8tpS5"/></a>
<a href="https://exploration.starkware.co/"><img src="https://img.shields.io/badge/Exploration Team-000.svg?&style=for-the-badge&logo=data:image/svg%2bxml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJhIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxODEgMTgxIj48ZGVmcz48c3R5bGU+LmJ7ZmlsbDojZmZmO308L3N0eWxlPjwvZGVmcz48cGF0aCBjbGFzcz0iYiIgZD0iTTE3Ni43Niw4OC4xOGwtMzYtMzcuNDNjLTEuMzMtMS40OC0zLjQxLTIuMDQtNS4zMS0xLjQybC0xMC42MiwyLjk4LTEyLjk1LDMuNjNoLjc4YzUuMTQtNC41Nyw5LjktOS41NSwxNC4yNS0xNC44OSwxLjY4LTEuNjgsMS44MS0yLjcyLDAtNC4yN0w5Mi40NSwuNzZxLTEuOTQtMS4wNC00LjAxLC4xM2MtMTIuMDQsMTIuNDMtMjMuODMsMjQuNzQtMzYsMzcuNjktMS4yLDEuNDUtMS41LDMuNDQtLjc4LDUuMThsNC4yNywxNi41OGMwLDIuNzIsMS40Miw1LjU3LDIuMDcsOC4yOS00LjczLTUuNjEtOS43NC0xMC45Ny0xNS4wMi0xNi4wNi0xLjY4LTEuODEtMi41OS0xLjgxLTQuNCwwTDQuMzksODguMDVjLTEuNjgsMi4zMy0xLjgxLDIuMzMsMCw0LjUzbDM1Ljg3LDM3LjNjMS4zNiwxLjUzLDMuNSwyLjEsNS40NCwxLjQybDExLjQtMy4xMSwxMi45NS0zLjYzdi45MWMtNS4yOSw0LjE3LTEwLjIyLDguNzYtMTQuNzYsMTMuNzNxLTMuNjMsMi45OC0uNzgsNS4zMWwzMy40MSwzNC44NGMyLjIsMi4yLDIuOTgsMi4yLDUuMTgsMGwzNS40OC0zNy4xN2MxLjU5LTEuMzgsMi4xNi0zLjYsMS40Mi01LjU3LTEuNjgtNi4wOS0zLjI0LTEyLjMtNC43OS0xOC4zOS0uNzQtMi4yNy0xLjIyLTQuNjItMS40Mi02Ljk5LDQuMyw1LjkzLDkuMDcsMTEuNTIsMTQuMjUsMTYuNzEsMS42OCwxLjY4LDIuNzIsMS42OCw0LjQsMGwzNC4zMi0zNS43NHExLjU1LTEuODEsMC00LjAxWm0tNzIuMjYsMTUuMTVjLTMuMTEtLjc4LTYuMDktMS41NS05LjE5LTIuNTktMS43OC0uMzQtMy42MSwuMy00Ljc5LDEuNjhsLTEyLjk1LDEzLjg2Yy0uNzYsLjg1LTEuNDUsMS43Ni0yLjA3LDIuNzJoLS42NWMxLjMtNS4zMSwyLjcyLTEwLjYyLDQuMDEtMTUuOGwxLjY4LTYuNzNjLjg0LTIuMTgsLjE1LTQuNjUtMS42OC02LjA5bC0xMi45NS0xNC4xMmMtLjY0LS40NS0xLjE0LTEuMDgtMS40Mi0xLjgxbDE5LjA0LDUuMTgsMi41OSwuNzhjMi4wNCwuNzYsNC4zMywuMTQsNS43LTEuNTVsMTIuOTUtMTQuMzhzLjc4LTEuMDQsMS42OC0xLjE3Yy0xLjgxLDYuNi0yLjk4LDE0LjEyLTUuNDQsMjAuNDYtMS4wOCwyLjk2LS4wOCw2LjI4LDIuNDYsOC4xNiw0LjI3LDQuMTQsOC4yOSw4LjU1LDEyLjk1LDEyLjk1LDAsMCwxLjMsLjkxLDEuNDIsMi4wN2wtMTMuMzQtMy42M1oiLz48L3N2Zz4=" alt="Exploration Team" height="30"></a>
</div>


## Overview

The Merkle Sum Sparse Merkle Tree combines the properties of both Merkle Sum Trees and Sparse Merkle Trees, providing:
- Efficient sparse storage with compact proofs
- Sum aggregation at each level
- Cryptographic verification
- Flexible storage backend through the `Db` trait
- Support for both regular and compact tree implementations

## Features

- Generic over hash size and hasher type
- Thread-safe with optional multi-threading support
- Memory-efficient storage with compact leaf nodes
- Proof compression and decompression
- Comprehensive test coverage including BIP test vectors
- CI/CD pipeline with code coverage reporting

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
merkle-sum-sparse-merkle-tree = "0.6.0"
```

Basic example using regular tree:

```rust
use merkle_sum_sparse_merkle_tree::{MSSMT, MemoryDb, Leaf};
use sha2::Sha256;

// Create a new tree with 32-byte hashes using SHA256
let db = Box::new(MemoryDb::<32, Sha256>::new());
let mut tree = MSSMT::<32, Sha256, ()>::new(db);

// Insert a leaf
let leaf = Leaf::new(vec![1, 2, 3], 100);
tree.insert(&[1; 32], leaf).unwrap();

// Get and verify a merkle proof
let proof = tree.merkle_proof(&[1; 32]).unwrap();
let root = tree.root().unwrap();
proof.verify_merkle_proof(&[1; 32], leaf, root.hash()).unwrap();
```

Example using compact tree for better memory efficiency:

```rust
use merkle_sum_sparse_merkle_tree::{CompactMSSMT, MemoryDb, Leaf};
use sha2::Sha256;

// Create a new compact tree
let db = Box::new(MemoryDb::<32, Sha256>::new());
let mut tree = CompactMSSMT::<32, Sha256, ()>::new(db);

// Insert leaves
let leaf = Leaf::new(vec![1, 2, 3], 100);
tree.insert(&[1; 32], leaf.clone()).unwrap();

// Get and verify compressed proofs
let proof = tree.merkle_proof(&[1; 32]).unwrap();
let compressed = proof.compress();
let decompressed = compressed.decompress().unwrap();
```

## Development

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Code Coverage

```bash
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
```

### Benchmarking

```bash
cargo bench
```

