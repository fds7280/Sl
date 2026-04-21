# ◈ Statelock

> A terminal-based password manager with AES-256-GCM encryption, built in Rust.

```
┌─────────────────────────────────────────────┐
│           ◈  S T A T E L O C K  ◈           │
│                                             │
│   ╭─ Entries (3) ──────────────────────╮    │
│   │ ▶ github                           │    │
│   │   gmail                            │    │
│   │   aws                              │    │
│   ╰────────────────────────────────────╯    │
└─────────────────────────────────────────────┘
```

---

## Download

No Rust or build tools needed — just download and run.

```
|  Linux   | [statelock-linux] https://github.com/fds7280/Sl/releases/latest/download/statelock-linux 
|  Windows | [statelock-windows.exe] https://github.com/fds7280/Sl/releases/latest/download/statelock-windows.exe
```

Or go to the [Releases page](https://github.com/fds7280/Sl/releases) and grab the latest version.

### Linux-> make it executable after download
```bash
chmod +x statelock-linux
./statelock-linux
```

### Windows
Just double click `statelock-windows.exe` or run it in PowerShell:
```powershell
.\statelock-windows.exe
```

---

## Features

- **AES-256-GCM** encryption on every field
- **Argon2id** key derivation (64MB memory, 3 iterations)
- **Double salt layer** — independent vault salt + per-entry field salt
- **`.sl` vault format** — custom binary format with magic header
- **Atomic writes** — crash-safe save via temp file + rename
- **Memory safety** — master password and keys zeroized after use
- **Owner-only file permissions** — `0o600` on Unix
- **Full TUI** — keyboard driven, no mouse needed

---

## Build from Source

If you prefer to build it yourself:

### Prerequisites
- [Rust](https://rustup.rs) (stable)

```bash
git clone https://github.com/fds7280/Sl.git
cd Sl
cargo run --release
```

---

## Dependencies


`ratatui`   ->  Terminal UI framework
`crossterm` -> Cross-platform terminal input/output
`aes-gcm`   ->   AES-256-GCM authenticated encryption
`argon2`    -> Argon2id password hashing / key derivation
`serde`     -> Serialization of vault data
`zeroize`   -> Securely wipe secrets from memory
`dirs`      -> Cross-platform data directory paths

---

## Vault Location

Your encrypted vault is stored at:

```bash
Linux   ->  `~/.local/share/statelock/vault.sl` 
Windows -> `C:\Users\<name>\AppData\Roaming\statelock\vault.sl` 
```
The vault file is a custom binary format:

```
[4  bytes] Magic header "SL01"
[32 bytes] Vault salt   (Argon2id key derivation)
[12 bytes] AES-GCM nonce
[ N bytes] Encrypted JSON payload
```

Each entry inside additionally has its own `field_salt` and per-field nonces — two completely independent encryption layers.

---

## Usage

### Keybindings
```bash
 Screen            Key        Action                     
                                                     
Login      - Enter   - Unlock / create vault
Login      - Esc     - Quit
Browse     - ↑ ↓     - Navigate entries
Browse     - Enter   - View entry detail
Browse     - A       - Add new entry
Browse     - Esc     - Quit
View       - Space   - Toggle password visibility
View       - →       - Edit entry
View       - ↑ ↓     - Navigate entries
View       - Esc     - Back to list
Edit / Add - Tab     - Switch field
Edit / Add - Enter   - Save
Edit / Add - Esc     - Cancel
```


## Security

- Passwords are never stored in plaintext anywhere on disk
- The master password is zeroized from memory on exit
- AES-256-GCM provides both encryption and authentication — tampered files are detected and rejected
- Argon2id with hardened parameters makes brute force attacks expensive
- Each entry is encrypted with its own independently derived key

---


