# Hash Generator Pro

Generate MD5, SHA-1, SHA-256, SHA-384 and SHA-512 hashes of text or files, plus a hash-compare mode — fast, private, and fully offline.

> A premium, zero-dependency hashing workbench. Type text or drop a file, and instantly see all five digests at once — each ready to copy. Paste an expected hash to verify a checksum with a live, color-coded match indicator. Nothing ever leaves your browser.

## Overview

Hash Generator Pro is part of the **Web Utility Suite**. It runs entirely in the browser with no build step, no frameworks, and no network calls — open `index.html` from disk and it works. Switch between **Text** and **File** input, and every supported algorithm hashes automatically: SHA-1/256/384/512 via the browser's native Web Crypto API, and MD5 via a from-scratch, RFC 1321-compliant pure-JavaScript implementation (Web Crypto does not expose MD5). Results appear as labeled rows with per-row copy buttons, and a dedicated compare panel checks a pasted hash against the live results with an explicit algorithm selector.

## Features

- **Text or File input**, toggled with a segmented control — a textarea for text, and a click-or-drag dropzone for files.
- **Five hashes computed at once**: MD5, SHA-1, SHA-256, SHA-384, SHA-512 — displayed as labeled rows in lowercase monospace hex.
- **Per-row Copy** buttons for each hash, plus a shared toast confirmation.
- **From-scratch MD5** — a complete, correct RFC 1321 implementation (message padding, 512-bit block processing, the four rounds with the standard 64-entry sine-derived constants table, per-round shift amounts, and little-endian hex digest). Verified against the official test vectors: `md5("") = d41d8cd98f00b204e9800998ecf8427e` and `md5("abc") = 900150983cd24fb0d6963f7d28e17f72`.
- **Drag & drop** file upload, plus a standard file picker; shows filename, size, and MIME type.
- **Live input size** (bytes / KB / MB) and character count for text input.
- **Compare mode** — paste an expected hash, pick its algorithm from an explicit dropdown (or leave it on Auto-detect, which infers the algorithm from hash length), and see a live, case-insensitive **Match** / **No match** badge as you type or as hashes finish computing.
- **Busy status badge** — shows "Hashing…" while `crypto.subtle.digest` and the MD5 loop run, then "Done".
- **Auto-persist** — your last text input (never files) and compare settings are saved to `localStorage` and restored, re-hashing automatically on return.
- **Dark & light themes**, fully responsive down to 360px, accessible, and keyboard-driven.

## Installation

No dependencies, no build step.

```bash
git clone https://github.com/kasapdev/hash-generator-pro.git
cd hash-generator-pro
```

Then simply open `index.html` in any modern browser (double-click it, or `file://` it). That's it.

## Usage

1. Choose **Text** or **File** input. For text, type or paste directly into the box; for file, click the dropzone or drag a file onto it.
2. All five hashes compute automatically (debounced while typing, immediately on file select) and appear in the **Hashes** panel.
3. Click **Copy** next to any hash to copy it to the clipboard.
4. To verify a checksum, paste it into **Compare against an expected hash**, pick its algorithm (or leave **Auto-detect**), and watch the badge update live as **Match** or **No match**.
5. Use **Clear** to reset everything, including the file selection and persisted text.

Large files (well past 100 MB) may hash slowly, since the pure-JS MD5 pass runs synchronously on the main thread — SHA-1/256/384/512 remain fast via native Web Crypto regardless of size.

## Keyboard Shortcuts

| Action               | Shortcut                       |
| -------------------- | ------------------------------ |
| Hash current text    | <kbd>Ctrl/⌘</kbd> + <kbd>Enter</kbd> |
| Show shortcuts help  | <kbd>?</kbd>                    |
| Close dialog         | <kbd>Esc</kbd>                  |

## Screenshots

> _Screenshots coming soon._

![screenshot](docs/screenshot-1.png)
![screenshot](docs/screenshot-2.png)

## Roadmap

- [ ] Additional algorithms (CRC32, SHA-3, BLAKE2/3) where browser support allows
- [ ] Batch-hash multiple files at once with a results table
- [ ] Drag-and-drop reordering / pinning of favorite algorithms
- [ ] HMAC mode with a user-supplied secret key
- [ ] Streaming/chunked hashing for very large files via a Web Worker

## License

MIT Licensed. Part of the Web Utility Suite.
