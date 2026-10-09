# pm

A cross-platform, offline password manager with first-class Windows support.

## Usage

```powershell
pm --help
```

Run a program with secret references resolved from the inherited environment:

```powershell
$env:XXX_TOKEN = "pm://acme/github-token"
pm run -- xxx.exe
```

References can also be stored in a standard `.env` file:

```dotenv
XXX_TOKEN=pm://acme/github-token
LOG_LEVEL=debug
```

```powershell
pm run --env-file=.env -- xxx.exe
```

Values from the environment file override inherited variables. Only values whose
entire contents use the `pm://organization/project` form are resolved.

## Security

- Key derivation: Argon2id
- Data encryption: XChaCha20-Poly1305
- Fully offline, with plaintext protected throughout its lifecycle.

## Build

Requires Go 1.26.5 or later:

```powershell
go run -buildvcs=false ./tools/test
```
