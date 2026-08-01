# loothound

Two small offline tools I built for the boring, repetitive parts of working a box: figuring out what a hash or a file is, reading loot out of noisy tool output, and remembering the right enumeration command. They run straight from Kali with no install and no dependencies, just Python 3.

I built loothound because I kept doing the same things by hand on every machine: googling which hash type I was looking at, forgetting a tool's exact syntax mid-box, and squinting through output looking for a password. It automates that, and it explains the reasoning while it does it, so I actually learn instead of copy pasting.

## What is honest about this

There are bigger, more complete tools than this. name-that-hash and haiti have larger hash databases. AutoRecon and nmapAutomator do heavier scan automation. HackTricks is the methodology reference everyone uses. loothound is not trying to beat any of them. It is my own offline version, tuned to how I work AD and OSCP style boxes, small enough that I understand every line of it.

The hash mode tables and the methodology recipes are curated, not exhaustive. Commands assume a Kali toolset (netexec/nxc, impacket, enum4linux-ng, ffuf, kerbrute, certipy). The source and output matchers are deliberately loose: they cast a wide net and will sometimes flag a placeholder, because on a box a wasted glance is cheap and a missed credential is not.

## Usage

One command, a handful of subcommands:

```
loothound hash    <hash|file> [--why]     # what hash is this + how to crack it
loothound file    <type|list>             # what file type is this + how to read it
loothound loot    [file]                  # read nxc/enum4linux output, highlight loot
loothound source  [file]                  # find hardcoded creds in source/config
loothound scan    <nmap.txt> [--ip ...]   # per-service methodology + DC detection
loothound recon   <task> [--ip ...]       # recall how to do a task (kerberoast, vhost...)
loothound service <name>                  # one service's playbook
loothound list                            # everything it knows
```

Most subcommands read from stdin when you skip the file, so you can pipe tools straight in.

## Identify a hash

It uses context, which is the whole point. A bare 32 character hex string is genuinely MD5 or NTLM or MD4, you cannot tell them apart from the hash alone. But the same string inside a secretsdump line is certainly NTLM:

```
$ loothound hash 8846f7eaee8fb117ad06bdd830b7586c
  [GUESS] MD5   (could be: MD5, NTLM, MD4, LM ...)

$ echo 'svc:1104:aad3...:8846f7eaee8fb117ad06bdd830b7586c:::' | loothound hash
  [CERTAIN] NTLM (NT hash)   why: user:RID:LM:NT::: layout
```

Run with `--why` to see the tell it matched on, so it trains your recognition instead of replacing it.

## Explain a file type

```
loothound file ccache     # kerberos ticket -> how to pass it
loothound file .kdbx      # keepass -> keepass2john then hashcat -m 13400
loothound file list       # everything it knows
```

## Read tool output for loot

```
nxc smb 10.10.10.10 -u guest -p '' --rid-brute | loothound loot
enum4linux-ng -A 10.10.10.10 | loothound loot
```

Pulls valid credential hits (admin ones flagged), usernames, hashes, and passwords hiding in description fields out of the noise, with the important part highlighted.

## Find hardcoded creds in source

Works even when the source is garbled or minified onto one line:

```
loothound source config.php
```

Catches PHP define() constants, connection strings, user:pass@host URIs, base64 Basic auth headers (decoded), and plain variable assignments.

## Enumeration methodology

Feed it an nmap scan and get per service methodology, plus it detects a Domain Controller and prints the AD kill chain:

```
loothound scan nmap.txt --ip 10.10.10.10 --domain corp.local --dc 10.10.10.10
```

Or ask for one thing when you forget the syntax:

```
loothound recon vhost --ip 10.10.10.10 --domain corp.local
loothound recon kerberoast --domain corp.local --user svc --password Pass123 --dc 10.10.10.10
loothound service smb
```

Every entry leads with the reason before the command, on purpose, so it reinforces the methodology.

## Reference sheets

Two markdown cheat sheets I keep alongside the tools:

- `hash-recognition.md` recognise a hash by its shape and know where to paste it
- `hash-recognition-apps.md` product specific formats (password managers, databases, CMS, network gear)

## Layout

- `loothound.py` the launcher, the command you run
- `hashhound.py` the hash, file, loot, and source engine (also runs standalone)
- `advisor.py` the scan, recon, and service engine (also runs standalone)

## Requirements

Python 3.8 or newer. No pip install. The commands it prints assume standard Kali tooling.

## License

MIT. See LICENSE.
