# pm

A cross-platform, offline password manager with first-class Windows support.

## Usage

```powershell
pm --help
```

## Security

- Key derivation: Argon2id
- Data encryption: XChaCha20-Poly1305
- Fully offline, with plaintext protected throughout its lifecycle.

## Build

Requires Go 1.26.5 or later:

```powershell
go run -buildvcs=false ./tools/test
```
