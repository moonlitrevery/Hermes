# Hermes

Hermes is a messaging app inspired by Ordem Carmesim, built for security and encryption.

It has group chats only. One member creates a group and gets an **invite code**. Friends paste
that code into Hermes to join. Messages are encrypted on the device before they leave it.
[Supabase](https://supabase.com) only stores and relays ciphertext. You run no server of your own.

## Layout

```
crates/hermes-core/   Rust core: crypto, local storage, Supabase REST + Realtime client
app/src-tauri/        Tauri 2 shell (desktop, Android, iOS) exposing the core as commands
app/ui/               Plain HTML/CSS/JS frontend (no bundler, no frameworks)
supabase/migrations/  Database schema, row-level security and RPCs
```

## Security model

| Thing                   | What the server sees                         |
|-------------------------|----------------------------------------------|
| Message text            | Ciphertext only (XChaCha20-Poly1305)         |
| Display names           | Nothing; they're inside the encrypted message|
| Group names             | Ciphertext only                              |
| Group identity          | `BLAKE3-derive(secret)`, not reversible      |
| Who is in which group   | Anonymous user ids + Ed25519 public keys     |
| When and how much       | Timestamps and ciphertext sizes              |

- **Invite code** = base58(`version ‖ 32-byte group secret ‖ checksum`). It *is* the group
  key, so anyone holding it can read the full history. Share it only over a channel you trust.
- Every message is **signed** with the sender's Ed25519 device key and checked before display.
  Members can't impersonate each other, and the server can't forge or alter messages.
  Each sender's key fingerprint is shown next to their name.
- Row-level security only lets members read a group. A message can only be posted with the
  signing key the poster registered for that group. Messages can't be edited or deleted.
  When the last member leaves, the group and all its ciphertext are deleted.

**Known limitations (v0.1)**

- One static key per group: no forward secrecy, and removing someone means making a new group.
  The next step would be [MLS](https://www.rfc-editor.org/rfc/rfc9420) via `openmls`.
- Local state (`hermes.json` in the app data dir) holds the identity key and invite secrets.
  It's readable only by the owner (mode 0600) but **not encrypted at rest**. Moving it into the
  OS keystore (Android Keystore, iOS Keychain, Secret Service) is planned.
- Supabase still sees metadata: which anonymous users are in which group, and when they post.
- Text messages only, with no attachments yet.

## Setup

### 1. Supabase

1. Create a project.
2. **Authentication → Sign In / Providers → enable "Allow anonymous sign-ins".**
   Turning on CAPTCHA and keeping the default rate limits is recommended.
3. Run the migration, either with the CLI (`supabase link && supabase db push`) or by pasting
   `supabase/migrations/20261028000000_hermes_init.sql` into the SQL editor.
4. Copy the project URL and the **anon / publishable** key from Project Settings → API.
   Never ship the `service_role` key in the app.

### 2. Build

Prerequisites: Rust (stable), Node + pnpm, and the
[Tauri 2 system dependencies](https://v2.tauri.app/start/prerequisites/).

```sh
export HERMES_SUPABASE_URL=https://YOUR-PROJECT.supabase.co
export HERMES_SUPABASE_ANON_KEY=YOUR-ANON-KEY

cd app
pnpm install
pnpm tauri dev        # desktop, hot reload
pnpm tauri build      # desktop installers
```

The two variables are compiled into the binary (required on mobile, where there is no shell
environment). On desktop they can also be supplied at runtime.

**Mobile:** `pnpm tauri android init && pnpm tauri android dev`, or `ios init` / `ios dev` on a
Mac. Android needs the SDK and NDK, and TLS (`aws-lc-rs`) also needs `cmake` on the build machine.

### Tests

```sh
cargo test -p hermes-core
```
