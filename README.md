# sss256

This project provides command-line utilities for splitting and and restoring
secrets using [Shamir's secret sharing
scheme](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing).

## Requirements

- Currently, only Linux is supported.
- [Zig](https://ziglang.org/download/) 0.13.0 (exact version) is required.

## Security

The secret is split byte-by-byte over the Galois field GF(256), hence the name
`sss256`. Partial knowledge of a threshold number of shares may be sufficient to
reconstruct parts of the secret.

### Known security limitations

- The current implementation is **not side-channel resistant**. Operations in
  GF(256) rely on lookup tables and conditional branching, which may leak
  information.
- The utilities **do not verify the integrity** of shares or the reconstructed
  secret. Corrupted shares could go unnoticed, potentially leading to incorrect
  secret recovery.
- Sensitive data is **not locked into RAM**. Under memory pressure, particularly
  with long secrets, the operating system could swap sensitive data to disk.

This list may be incomplete. If security is critical for your use case,
carefully assess whether these utilities meet your requirements.

For a comparison of other secret-sharing libraries, see
[here](https://github.com/dsprenkels/sss?tab=readme-ov-file#comparison-of-secret-sharing-libraries).

## Building from source

To run the tests:
```
zig build test
```

To build in debug mode:
```
zig build
```

To create a release build:
```
zig build --release
```

## Command-line usage

### `sss256-split`

Split a secret into multiple shares using Shamir's secret sharing scheme. Use
the `sss256-combine` tool to reconstruct the secret.

Bytes of the secret can only be reconstructed when corresponding bytes from a
user-specified threshold number of shares, along with the indices of the shares,
are known.

The secret is read from standard input, and the shares are written to standard
output. Each share consists of an index and a byte sequence of the same length
as the secret, both written in hexadecimal format.

A digest of the cryptographically secure random bytes used is printed to
standard error for sanity checking.

**Options:**

- `-h`, `--help`: Show this help message and exit.
- `-t`, `--threshold`: Number of shares required to reconstruct the secret.
- `-n`, `--shares`: Total number of shares to generate.

**Example:**

```
sss256-split --threshold=3 --shares=5
```

### `sss256-combine`

Reconstruct a secret from shares generated by the `sss256-split` tool using
Shamir's secret sharing scheme.

A threshold number of shares is required to reconstruct the secret. Even if only
partial data is available from the required number of shares, corresponding
bytes of the secret can still be recovered.

Shares are read from standard input, one per line. Any input beyond the
threshold number of lines is ignored. The reconstructed secret is written to
standard output.

**Options:**

- `-h`, `--help`: Show this help message and exit.
- `-t`, `--threshold`: Must match the threshold used during share generation.

**Example:**

```
sss256-combine --threshold=3
```

## License

`sss256` is released under the [MIT (Expat) license](LICENSE).
