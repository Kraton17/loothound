# Product-Specific Hashes (the "which app made this" layer)

Fundamentals live in `hash-recognition.md`. This is the next layer: individual
products pick their own scheme and stamp a signature on it. Recognise the
PRODUCT and the mode is fixed.

Meta-rule, so you never google a mode again:

```
hashcat --example-hashes | less     # the whole catalogue with samples
hashcat -hh | grep -i <product>     # e.g. grep -i keepass  -> 13400
```

`EXTRACT` below = the tool that turns a file into a crackable hash.
`ROCK` = `/usr/share/wordlists/rockyou.txt`.

---

## Password managers and credential stores

Almost none of these are a bare hash. You either extract a hash from the vault
file, or you decrypt the store with a key. Know which.

| Product                    | How you get it              | Extract / handle          | Crack |
|----------------------------|-----------------------------|---------------------------|-------|
| **KeePass** (.kdbx)  [Keeper]| loot the database file      | `keepass2john db.kdbx`    | `-m 13400` |
| KeePass with a keyfile     | need .kdbx AND the .key     | `keepass2john -k file.key db.kdbx` | `-m 13400` |
| **LastPass**               | sniffed vault / local blob  | build the string          | `-m 6800` |
| **1Password** (Agile)      | older `.agilekeychain`      | extract keychain          | `-m 6600` |
| **1Password** (OPVault)    | newer cloud keychain        | extract keychain          | `-m 8200` |
| **Bitwarden**              | local `data.json`           | it's PBKDF2-SHA256; no clean stock mode, use community tooling / decrypt with the master pw | (crack the PBKDF2 or just decrypt) |
| **Windows DPAPI** masterkey| `%APPDATA%\...\Protect\`     | this decrypts Chrome/Edge saved pws | `-m 15300` (v1), `-m 15310` (v2) |
| **Chrome / Edge** saved pw | `Login Data` + masterkey    | DPAPI-decrypt, do NOT crack | n/a, decrypt |
| **Firefox** saved pw       | `key4.db` + `logins.json`   | `firefox_decrypt`         | n/a, decrypt |
| **macOS Keychain**         | `login.keychain-db`         | `chainbreaker` / keychain2john | varies |

Rule of thumb: **KeePass and vaults you CRACK (extract then hashcat). Browser
password stores you DECRYPT (find the masterkey, don't run hashcat).** Mixing
those up is the classic time-waster.

---

## Databases

| Product / version          | Tell                          | hashcat | john |
|----------------------------|-------------------------------|---------|------|
| MySQL 3.23 (ancient)       | 16 hex                        | `-m 200`| `mysql` |
| MySQL 4.1 / 5.x            | 40 hex with leading `*`       | `-m 300`| `mysql-sha1` |
| PostgreSQL (md5)           | `md5` + username as salt      | `-m 12` | `postgres` |
| PostgreSQL (SCRAM-SHA-256) | `SCRAM-SHA-256$...`           | `-m 28600` | |
| MSSQL 2000                 | `0x0100` + long hex           | `-m 131`| `mssql` |
| MSSQL 2005                 | `0x0100` shorter              | `-m 132`| `mssql05` |
| MSSQL 2012/2014/2016/2019  | `0x0200` + hex                | `-m 1731`| `mssql12` |
| Oracle 7-10g (DES)         | user:hash pair                | `-m 3100`| `oracle` |
| Oracle 11g                 | `S:` + long hex               | `-m 112`| `oracle11` |
| Oracle 12c+                | `H:...T:...`                  | `-m 12300`| |
| MongoDB SCRAM-SHA-1        | from `system.users`           | `-m 24100`| |
| MongoDB SCRAM-SHA-256      | from `system.users`           | `-m 24200`| |

The MSSQL `0x0100` vs `0x0200` prefix is your version tell: `0100` is old
(2000/2005), `0200` is 2012+.

---

## CMS and web frameworks

| Platform                   | Tell                          | hashcat | john |
|----------------------------|-------------------------------|---------|------|
| WordPress / phpBB3         | `$P$` or `$H$`                | `-m 400`| `phpass` |
| Drupal 7                   | `$S$`                         | `-m 7900`| `drupal7` |
| Joomla (old)               | `hash:salt` md5               | `-m 20` (md5($pass.$salt)) | |
| Joomla (modern)            | `$2y$`                        | `-m 3200` (bcrypt) | `bcrypt` |
| vBulletin < 3.8.5          | `hash:salt`                   | `-m 2611`| |
| vBulletin >= 3.8.5         | longer salt                   | `-m 2711`| |
| MyBB / IPB                  | `hash:salt`                   | `-m 2811`| |
| MediaWiki                  | `$B$salt$hash`                | `-m 3711`| |
| Django (modern)            | `pbkdf2_sha256$...`           | `-m 10000`| `django` |
| Django (old)               | `sha1$salt$hash`              | `-m 124`| |
| osCommerce / xt:Commerce   | `hash:salt`                   | `-m 21` | |

If a web app hash has a `$` prefix, it self-describes (go to fundamentals). If
it's `hash:salt` with no prefix, the platform is the only way to know the recipe,
which is why this table exists.

---

## Network appliances

Includes the reversible ones, which you must NOT throw at hashcat.

| Vendor / type              | Tell                          | Handle |
|----------------------------|-------------------------------|--------|
| Cisco IOS type 5           | `$1$` in config               | md5crypt, `-m 500` |
| Cisco IOS **type 7**       | `password 7 0822...`          | REVERSIBLE: `ciscot7.py -p <hex>` |
| Cisco IOS type 8           | `$8$`                         | `-m 9200` (PBKDF2-SHA256) |
| Cisco IOS type 9           | `$9$`                         | `-m 9300` (scrypt) |
| Cisco ASA/PIX              | base64-ish, no `$`            | `-m 2400` (PIX) / `-m 2410` (ASA) |
| **Juniper `$9$`**          | `$9$...` in JunOS config      | REVERSIBLE: `junos-decrypt` / online $9$ decoder |
| Juniper ScreenOS           | `nsHash`                      | `-m 22` |
| FortiGate (FortiOS)        | `SH2...` / long base64        | `-m 7000` |
| Citrix NetScaler (old)     | `1` + sha1                    | `-m 8100` |
| Citrix NetScaler (new)     | sha512-based                  | `-m 22200` |
| Palo Alto PAN-OS           | `$1$` md5crypt variant        | `-m 500` |

Watch the collision: Cisco `$9$` is scrypt (crack it), but Juniper `$9$` is
reversible (decode it). Same prefix, opposite action. The surrounding config
tells you the vendor.

---

## Windows / AD secrets (recap, you know these)

| Type                       | hashcat | Note |
|----------------------------|---------|------|
| NTLM (NT hash)             | `-m 1000`| PTH instead of crack when you can |
| NetNTLMv1 / v2             | `-m 5500` / `-m 5600` | v2 can't PTH |
| Kerberoast TGS-REP (RC4)   | `-m 13100`| AES etypes -> 19600/19700 |
| AS-REP roast (RC4)         | `-m 18200`| AES -> 19800/19900 |
| DCC1 / DCC2 (cached creds) | `-m 1100` / `-m 2100`| from registry, not the DC |
| DPAPI masterkey v1 / v2    | `-m 15300` / `-m 15310`| unlocks browser + saved creds |

---

## When you hit something not on any list

1. `hashcat --example-hashes | grep -iA2 <guess>` to eyeball a sample.
2. `hashcat -hh | grep -i <product-or-scheme>` to find the mode.
3. `name-that-hash -t '<hash>'` or `haiti '<hash>'` for a prefix/length opinion.
4. Still stuck: the ENVELOPE is the clue. A `$word$` prefix names the scheme;
   a filename extension names the extractor (`somefile.<x>2john`).
