# Hermes

Hermes is a messaging app inspired by Ordem Carmesim, built for security and encryption.

It has group chats only. An admin generates a short invite code that works **once** and only
for **5 minutes**. A friend types it into Hermes, and the admin's app lets them in automatically.
Messages are encrypted with [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420) on the device.
[Supabase](https://supabase.com) only stores and orders ciphertext; you run no server of your own.

## Layout

```
crates/hermes-core/   Rust core: MLS (openmls), keystore vault, Supabase REST + Realtime, sync
  tests/              integration tests against a local Supabase stack
app/src-tauri/        Tauri 2 shell (desktop; Android/iOS see below) exposing the core as commands
app/ui/               Plain HTML/CSS/JS frontend (no bundler, no frameworks)
supabase/migrations/  schema, row-level security, RPCs and rate limits
supabase/tests/       pgTAP tests
```

## Security model

### Groups are MLS groups

- Ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, via `openmls`.
- Every message is an MLS PrivateMessage, and so is every commit. The server can't see
  message content, and it can't see who a commit adds or removes.
- Every device has one Ed25519 signature key. It is the device's MLS credential, and members
  see its fingerprint next to each sender's name.
- The group name lives in an encrypted GroupContext extension, so a new member gets it inside
  the Welcome.

### Invites carry no keys

- Only admins (and the owner) can create codes. A code is 16 Crockford base32 characters
  (80 random bits), shown as `XXXX-XXXX-XXXX-XXXX`.
- The server stores only `SHA-256(code)`. A code expires after 5 minutes and is consumed by the
  first valid use. Wrong, used and expired codes all get the same answer.
- Using a code files a join request carrying the joiner's KeyPackage. Any online admin's app
  validates it (including that its identity matches the request) and commits an MLS Add. The
  Welcome is stored together with the new membership, in one transaction. An admin can only
  accept a request while its code is still valid.

### What membership means

| | |
|---|---|
| Joining | You can read from your join epoch on. Older messages are hidden by RLS, and MLS never gave you their keys anyway. |
| Removal | An MLS Remove commit. The removed device can't decrypt anything sent afterwards, and the server stops serving it the group. |
| Leaving | The server stops serving you at once. An admin's app then commits the MLS Remove for your leaf. An admin first steps down (a commit), because only the owner may remove an admin. |
| Roles | **Owner** (exactly one, can't be removed, promotes and demotes). **Admin** creates codes and removes members. **Member** chats. Only the owner can remove an admin. |

### Roles are part of the group state, and every client enforces them

Roles are stored in the MLS group itself. A private GroupContext extension names the owner and
the admins. The GroupContext feeds the MLS key schedule, so all members provably hold the same
roles, and only a commit can change them (promotion, demotion, removing an admin).

Before merging any commit, every client checks it against the roles in force *before* the commit:

| Commit | Allowed from |
|---|---|
| Add a member | owner or admin |
| Remove a member | owner or admin |
| Remove an admin | owner only |
| Remove the owner | nobody |
| Promote or demote | owner only (an admin may step down) |
| Change the owner or the group name | nobody |
| Any other proposal type | nobody |

After the commit, everyone holding a role must still be in the group. Whoever joins also checks
that their Welcome was signed by an owner or admin.

If a commit breaks these rules, even one the server accepted, the client **doesn't merge it**: the
epoch stays where it was, the group is frozen, and the app warns that the group received an
invalid change. Every later commit builds on the bad one, so the honest members can't continue in
that group. The owner should create a new one. The server checks the same rules (defence in
depth), but clients don't rely on it.

### The server orders epochs

`groups.epoch` is the MLS epoch. A commit is accepted only for the group's *current* epoch, and
the epoch then advances. This is enforced under a row lock and by a unique index (one commit per
epoch), so two concurrent commits for the same epoch can't both be accepted. Application messages
also have to be for the current epoch, and clients apply rows in id order. If a client loses that
race, it fetches the newer commits and retries.

### Keys on the device

All local state is one file, `state.hermes`, encrypted with XChaCha20-Poly1305. It holds the
identity key, MLS group secrets, session, device secret and message history. The 32-byte key for
that file exists only in the OS keystore, accessed through the `keyring` crate: Secret Service on
Linux, Credential Manager on Windows, Keychain on macOS. If no keystore is available, Hermes
refuses to start rather than write secrets in clear. The v0.1 plaintext `hermes.json` is deleted
when the app opens.

### Lost anonymous sessions

Each device registers `SHA-256(device secret)` with the server. If its anonymous session is lost,
the app signs in as a new anonymous user and presents the secret. The server then moves the
device's memberships and pending join requests to the new user and deletes the abandoned
anonymous user, so no ghost member stays behind. The MLS leaf doesn't change.

### Abuse

The anon key ships inside the binary, so assume anyone can call the API. Limits are enforced
in the database, per user:

| Action | Limit |
|---|---|
| create a group | 10 / hour |
| create an invite code | 20 / hour |
| request to join (*every attempt counts, including wrong codes*) | 10 / hour |
| send a message | 60 / minute |
| claim a device | 10 / hour |

Because anonymous users are cheap, **turn on CAPTCHA for sign-ins** in the hosted project:

1. Create an hCaptcha or Cloudflare Turnstile site and get its site key and secret.
2. Dashboard → Authentication → Attack Protection → **Enable CAPTCHA protection**, pick the
   provider and paste the secret.
3. The client must then send `gotrue_meta_security.captcha_token` with the anonymous sign-up
   (`POST /auth/v1/signup`). Hermes doesn't do this yet: the widget needs a page that can run the
   provider's script. Until then, keep CAPTCHA off and rely on the per-IP limit below.
4. Keep Authentication → Rate Limits → *anonymous sign-ins* at the default (30/hour per IP) or
   lower.

### What the server still sees

- which anonymous users are in which group, and their roles
- when each member posts, how much, and when commits happen
- each device's public signature key

### Known limitations

- **Android and iOS:** the `keyring` v1 API used here covers desktop only. On mobile Hermes
  refuses to open (it never falls back to plaintext) until the Android Keystore and iOS Keychain
  stores are wired in through `keyring-core`. That code hasn't been written or tested.
- History lives only on devices (MLS deletes keys after use). A new device starts empty.
- Members don't post self-updates, so post-compromise security only advances when an admin
  commits (adds or removes).
- A malicious server can't sneak in a member, but it can *freeze* a group by accepting an invalid
  commit (denial of service, which it could do anyway by dropping messages).
- Text messages only, with no attachments.

## Setup

### 1. Supabase project

1. Create a project.
2. Authentication → Sign In / Providers → enable **Allow anonymous sign-ins**.
3. Apply the migrations: `pnpm exec supabase link && pnpm exec supabase db push`.
4. Copy the project URL and the **anon / publishable** key from Project Settings → API.
   Never ship the `service_role` key.

### 2. Build

Prerequisites: Rust (stable), Node and pnpm, and the
[Tauri 2 system dependencies](https://v2.tauri.app/start/prerequisites/). On Linux a Secret
Service provider (GNOME Keyring or KWallet) must be running.

```sh
export HERMES_SUPABASE_URL=https://YOUR-PROJECT.supabase.co
export HERMES_SUPABASE_ANON_KEY=YOUR-ANON-KEY

cd app
pnpm install
pnpm tauri dev        # desktop, hot reload
pnpm tauri build      # desktop installers
```

The two variables are compiled into the binary. On desktop they can also be given at runtime.

## Tests

```sh
pnpm install                 # Supabase CLI
cargo test -p hermes-core    # unit tests (MLS and role rules, vault, invite codes); integration tests show as ignored
pnpm db:start                # local stack on ports 553xx (separate from other projects)
pnpm test:db                 # pgTAP: every policy and RPC, plus meta tests
pnpm test:e2e                # Rust integration tests with real clients against the local stack,
                             # including one where the server's admin check is switched off
```
