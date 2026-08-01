# Hash Recognition and Placement

Stop googling mid-box. Three reflexes: recognise the shape, know where it goes,
and spot the things that are not hashes at all.

Boxes named in brackets are ones you actually cracked this on, so the pattern
has a memory hook.

---

## 1. Recognise it by the TELL, not by reading it

There are only three kinds of tell. Check them in this order.

### Tell A: a prefix (certain, self-describing)

The hash literally announces itself. If it starts with one of these, you are done.

| You see            | It is                          | Certainty |
|--------------------|--------------------------------|-----------|
| `$1$`              | md5crypt (old Unix)            | certain   |
| `$5$`              | sha256crypt (Unix)             | certain   |
| `$6$`              | sha512crypt (Unix, /etc/shadow)| certain   |
| `$2a$ $2b$ $2y$`   | bcrypt                         | certain   |
| `$y$`              | yescrypt (modern Unix shadow)  | certain   |
| `$P$` or `$H$`     | phpass (WordPress, phpBB)      | certain   |
| `$S$`              | Drupal 7                       | certain   |
| `{SSHA}`           | LDAP salted SHA1               | certain   |
| `pbkdf2_sha256$`   | Django                         | certain   |
| `$DCC2$`           | Domain Cached Creds v2 (mscash2)| certain  |
| `$krb5tgs$23$`     | Kerberoast (TGS-REP)  [Active, Support] | certain |
| `$krb5asrep$23$`   | AS-REP roast          [Sauna]  | certain   |
| `$krb5pa$`         | Kerberos pre-auth              | certain   |
| `$sspr$` `$keepass$`| KeePass (from keepass2john)   | certain   |

Mental model: **if it has `$id$...$` structure, the id IS the answer.** You never
guess these.

### Tell B: a delimiter layout (certain, from context)

Not the hash itself but the line it sits in. These are the AD money hashes.

| You see                                             | It is                        | Where it came from |
|-----------------------------------------------------|------------------------------|--------------------|
| `user:1103:aad3b435...:31d6cfe0...:::`              | NTLM (the NT half)  [Cicada] | secretsdump / NTDS.dit |
| the `aad3b435b51404eeaad3b435b51404ee` LM half      | blank LM, ignore it          | same line          |
| `user::DOMAIN:1122334455667788:hex:hex...`          | NetNTLMv1                    | Responder (v1)     |
| `user::DOMAIN:16hexchallenge:32hexproof:longblob`   | NetNTLMv2                    | Responder / relay  |
| `cpassword="edBSHOwh..."`                           | GPP cpassword  [Active]      | SYSVOL Groups.xml  |
| `*A4B6157319...` (40 hex, leading `*`)              | MySQL 4.1+                   | DB dump            |

The `:::` triple-colon tail is your instant "this is NTLM from a DC dump" flag.

### Tell C: length + charset (AMBIGUOUS, this is the honest bit)

No prefix, no delimiters, just a naked string. Now you are counting characters,
and you CANNOT be certain, because many hash types share a length. This is why
hashid spits multiple answers. It is not being unhelpful, the information is
genuinely not in the hash.

| Length | All hex? | Most likely (context decides) |
|--------|----------|-------------------------------|
| 16     | yes      | MySQL323, or half-LM          |
| 32     | yes      | **MD5 or NTLM** (also MD4, LM) |
| 40     | yes      | SHA1 (or MySQL5 if it had a `*`) |
| 56     | yes      | SHA-224                       |
| 64     | yes      | SHA-256                       |
| 96     | yes      | SHA-384                       |
| 128    | yes      | SHA-512 (or Whirlpool)        |

**The 32-hex decision rule** (the one you hit constantly):
- Came out of a DC / NTDS / secretsdump / any AD context  -> **NTLM, `-m 1000`**
- Came out of a web app, database, or a Linux app  -> **MD5, `-m 0`**
- No idea  -> try NTLM and MD5 both, they run in milliseconds anyway.

That context switch is the entire skill. The hash looks identical either way.

---

## 2. Where to paste it

Once you have the name, this is pure lookup. `HASH` = the file with the hash in it.
`ROCK` = `/usr/share/wordlists/rockyou.txt`.

| Type              | hashcat            | john                         | note |
|-------------------|--------------------|------------------------------|------|
| MD5               | `-m 0`             | `--format=raw-md5`           | |
| SHA1              | `-m 100`           | `--format=raw-sha1`          | |
| SHA256            | `-m 1400`          | `--format=raw-sha256`        | |
| SHA512            | `-m 1700`          | `--format=raw-sha512`        | |
| **NTLM**          | `-m 1000`          | `--format=nt`                | often you PTH instead of crack |
| LM                | `-m 3000`          | `--format=lm`                | only if LM half not blank |
| NetNTLMv1         | `-m 5500`          | `--format=netntlm`           | |
| NetNTLMv2         | `-m 5600`          | `--format=netntlmv2`         | can't PTH, must crack |
| **Kerberoast TGS**| `-m 13100`         | `--format=krb5tgs`           | etype 17 -> 19600, 18 -> 19700 |
| **AS-REP roast**  | `-m 18200`         | `--format=krb5asrep`         | |
| md5crypt `$1$`    | `-m 500`           | `--format=md5crypt`          | |
| sha256crypt `$5$` | `-m 7400`          | `--format=sha256crypt`       | |
| sha512crypt `$6$` | `-m 1800`          | `--format=sha512crypt`       | shadow default |
| bcrypt `$2y$`     | `-m 3200`          | `--format=bcrypt`            | slow, keep wordlist tight |
| phpass / WordPress| `-m 400`           | `--format=phpass`            | |
| Drupal 7 `$S$`    | `-m 7900`          | `--format=drupal7`           | |
| mscash2 `$DCC2$`  | `-m 2100`          | `--format=mscash2`           | |
| MySQL323 (16 hex) | `-m 200`           | `--format=mysql`             | |
| MySQL4.1+ (`*`+40)| `-m 300`           | `--format=mysql-sha1`        | strip the `*` for hashcat |
| KeePass           | `-m 13400`         | `--format=keepass`           | see section 3 |
| JWT (HS256)       | `-m 16500`         | n/a                          | cracks the signing secret |
| WPA/WPA2          | `-m 22000`         | `--format=wpapsk`            | from a .hc22000 |
| LDAP {SSHA}       | `-m 111`           | `--format=ssha`              | |
| Django pbkdf2     | `-m 10000`         | `--format=django`            | |

Default command shape you will type a hundred times:

```
hashcat -m <mode> -a 0 HASH ROCK
john --format=<fmt> --wordlist=ROCK HASH
```

If the file still has `user:hash` lines, add `--username` to hashcat so it doesn't
choke on the username column.

---

## 3. It's loot, but it's not a hash YET

This is the section that saves you the most time. You cannot paste a KeePass
database or an SSH key into hashcat. You run it through a `2john` extractor first,
which spits out a crackable hash. Then you crack that.

| You looted        | Turn it into a hash with        | Then crack with |
|-------------------|---------------------------------|-----------------|
| `.kdbx` KeePass   | `keepass2john db.kdbx`   [Keeper]| `-m 13400` |
| `id_rsa` SSH key  | `ssh2john id_rsa`               | `--format=ssh` |
| `.pfx` / `.p12`   | `pfx2john cert.pfx`     [Timelapse] | `--format=pfx` or `crackpkcs12` |
| `.zip`            | `zip2john file.zip`             | |
| `.rar`            | `rar2john file.rar`             | |
| `.7z`             | `7z2john.pl file.7z`            | |
| password `.pdf`   | `pdf2john.py file.pdf`          | |
| Office doc        | `office2john.py file.docx`      | |
| GPG key           | `gpg2john secring.gpg`          | |

Whole reflex: **file I can't read + wants a password = find its `2john`.**

---

## 4. Traps: decode or decrypt, do NOT crack

Recognising these saves you from burning an hour running hashcat on something that
was never a hash.

| You see              | It is                          | Do this |
|----------------------|--------------------------------|---------|
| `cpassword="..."`    | GPP, AES with a PUBLIC key [Active] | `gpp-decrypt '<b64>'` |
| `enable ... 7 08224...`| Cisco type 7, reversible     | `ciscot7.py -p <hex>` |
| `eyJ...eyJ....`      | JWT, base64 not a hash         | decode header/payload first |
| JWT `alg: none`      | forgeable                      | strip signature, forge |
| JWT `alg: RS256`     | try key confusion              | `jwt_tool <tok> -X k` |
| long base64 blob     | maybe wrapped data             | `echo x | base64 -d | xxd` first |

Cisco type 7 and GPP are reversible in a second because the key is public. bcrypt
and sha512crypt are the opposite, deliberately slow. Knowing which bucket you are
in decides whether you wait 1 second or 6 hours.

---

## The whole thing in one breath

1. Prefix `$...$`?  -> name is literally in the prefix, go to the table.
2. Colons and `:::`?  -> AD hash, it's NTLM or a Kerberos roast.
3. Naked hex?  -> count length, then let CONTEXT pick MD5 vs NTLM.
4. Can't read the file?  -> `2john` it first.
5. `cpassword`, Cisco `7`, or `eyJ`?  -> decrypt/decode, don't crack.
