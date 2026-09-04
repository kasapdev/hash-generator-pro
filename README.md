# Hash Generator Pro

Generate MD5, SHA-1, SHA-256, SHA-384 and SHA-512 hashes of text or files, and compare a hash against an expected value — fast, private, and fully offline.

> A zero-dependency hashing workbench. Type text or pick a file and instantly see all five hashes, each ready to copy. Paste an "expected" hash and it's auto-detected by length and checked for a match — nothing ever leaves your machine.

## Overview

Hash Generator Pro is part of the **Web Utility Suite**. It runs entirely in the browser with no build step, no frameworks, and no network calls — open `index.html` from disk and it works. SHA-1/256/384/512 use the browser's native `crypto.subtle.digest`; MD5 (which the Web Crypto API doesn't provide) is computed by a small pure-JavaScript implementation written from the RFC 1321 specification and verified against the standard's own test vectors, including the official million-character stress vector.

## Features

- **Two input modes** — paste text directly, or choose a file (hashed from raw bytes via `FileReader`).
- **Five hashes at once** — MD5, SHA-1, SHA-256, SHA-384, SHA-512, all computed and shown together as lowercase hex.
- **Pure-JS MD5** — a from-scratch RFC 1321 implementation (padding, message schedule, F/G/H/I round functions, 32-bit wraparound arithmetic), verified against known test vectors.
- **Native SHA family** — SHA-1/256/384/512 computed via `crypto.subtle.digest`, no libraries.
- **Per-hash copy buttons** — copy any single hash to the clipboard.
- **Compare mode** — paste an expected hash; the algorithm is auto-detected by hex length (32/40/64/96/128 characters) and compared case-insensitively against the matching computed hash, with a clear match / no-match badge.
- **Live hashing** — debounced re-hash as you type; files hash immediately on selection.
- **Auto-persist** — your last text input and compare field are saved to `localStorage` and restored on return (file selections are not persisted).
- **Dark & light themes**, fully responsive down to 360px, accessible, and keyboard-driven.
- **100% offline** — hashing runs entirely in your browser; nothing is ever uploaded.

## Installation

No dependencies, no build step.

```bash
git clone https://github.com/kasapdev/hash-generator-pro.git
cd hash-generator-pro
```

Then simply open `index.html` in any modern browser (double-click it, or `file://` it). That's it.

## Usage

1. Choose **Text** or **File** as your input source.
2. For text, type or paste into the input area — hashing updates live. For a file, click **Choose file** and pick one.
3. All five hashes appear instantly (MD5 first, then the SHA family as the browser computes them). Click **Copy** next to any hash to copy it.
4. To verify a download or check for tampering, paste the **expected hash** into the compare field — the algorithm is detected automatically and you'll see a clear match / no-match badge.
5. **Clear** resets the input, results, and compare field.

## Keyboard Shortcuts

| Action                  | Shortcut                       |
| ------------------------ | ------------------------------ |
| Hash current text now   | <kbd>Ctrl/⌘</kbd> + <kbd>Enter</kbd> |
| Show shortcuts help      | <kbd>?</kbd>                    |
| Close dialog             | <kbd>Esc</kbd>                  |

## Screenshots

> _Screenshots coming soon._

![screenshot](docs/screenshot-1.png)
![screenshot](docs/screenshot-2.png)

## Roadmap

- [ ] Streamed/chunked hashing for very large files, off the main thread via a Web Worker
- [ ] CRC32 and SHA3 (Keccak) support
- [ ] HMAC generation with a user-supplied key
- [ ] Drag-and-drop file input
- [ ] Batch-hash multiple files at once

## License

MIT Licensed. Part of the [Web Utility Suite](https://github.com/kasapdev/web-utility-suite).
