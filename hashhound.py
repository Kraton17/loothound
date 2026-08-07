#!/usr/bin/env python3
"""
hashhound v2 - context-aware hash / credential identifier + crack-command generator

Paste it any junk (secretsdump output, /etc/shadow, a config file, a Kerberos
ticket, a JWT, GPP XML, a directory listing, a vault file path). It will:

  1. scan the blob and pull out credential-shaped things,
  2. resolve the type from CONTEXT where possible (certain), self-describing
     prefixes next (certain), and fall back to length ranking for naked hashes
     (honest guess), plus recognise product-specific formats (KeePass, DPAPI,
     Postgres, MSSQL, MongoDB, MediaWiki, Cisco/Juniper, CMS salted-md5),
  3. tell you WHERE to paste it: hashcat mode, john format, the correct non-crack
     tool (GPP -> gpp-decrypt, JWT -> decode, Cisco/Juniper reversible), or the
     `2john` extractor when the loot is a file, not a hash yet.

Run with --why to see the exact tell each identification matched on, so running
it drills your recognition instead of replacing it.

It also answers "what is this file and how do I read it?" for the pentest file
zoo (AD secrets, Kerberos tickets, disk/memory images, config files with creds,
reversing targets, encrypted archives):

    python3 hashhound.py --ext ccache      # explain a type + how to handle it
    python3 hashhound.py --ext list        # everything it knows

Usage:
    python3 hashhound.py <file>            # scan a blob for hashes + loot files
    cat dump.txt | python3 hashhound.py --why
    python3 hashhound.py -s '$krb5tgs$23$*svc$...'
    python3 hashhound.py --ext .kdbx
    nxc smb $IP -u guest -p '' --users | python3 hashhound.py --loot   # read tool output
    python3 hashhound.py --source app.php    # find hardcoded creds in source/config

No third-party deps. Pure stdlib.
"""

import sys
import re
import argparse
import base64

WORDLIST = "/usr/share/wordlists/rockyou.txt"


# --------------------------------------------------------------------------- #
class C:
    on = sys.stdout.isatty()
    def _w(code):
        return (lambda s: f"\033[{code}m{s}\033[0m" if C.on else s)
    bold = staticmethod(_w("1"))
    red  = staticmethod(_w("31"))
    grn  = staticmethod(_w("32"))
    ylw  = staticmethod(_w("33"))
    blu  = staticmethod(_w("34"))
    cyn  = staticmethod(_w("36"))
    dim  = staticmethod(_w("2"))


class Finding:
    def __init__(self, secret, kind, confidence, why, username=None, note=None,
                 candidates=None, commands=None, extra=None, category=None, line=None):
        self.secret     = secret
        self.kind       = kind
        self.confidence = confidence      # certain | likely | ambiguous
        self.why        = why             # the tell we matched on
        self.username   = username
        self.note       = note
        self.candidates = candidates or []
        self.commands   = commands or []
        self.extra      = extra or {}
        self.category   = category        # user | cred | hash | file | note (for --loot)
        self.line       = line            # source line, for highlighting


def hc(mode: str | None, hashfile: str = "hash.txt", username: bool = False) -> str:
    u = " --username" if username else ""
    return f"hashcat -m {mode} -a 0{u} {hashfile} {WORDLIST}"

def john(fmt: str | None, hashfile: str = "hash.txt") -> str:
    return f"john --format={fmt} --wordlist={WORDLIST} {hashfile}"


# --------------------------------------------------------------------------- #
#  self-describing prefixes -> (label, hashcat_mode, john_format)
#  NOTE: $9$ is deliberately NOT here - it collides (Cisco scrypt vs Juniper
#  reversible) and is resolved by config context in sig_dollar9().
# --------------------------------------------------------------------------- #
PREFIX_DB = [
    (re.compile(r'^\$1\$'),                    "md5crypt (Unix / Cisco type5 / PAN-OS)", "500",  "md5crypt"),
    (re.compile(r'^\$5\$'),                    "sha256crypt (Unix)",       "7400",  "sha256crypt"),
    (re.compile(r'^\$6\$'),                    "sha512crypt (Unix)",       "1800",  "sha512crypt"),
    (re.compile(r'^\$2[abxy]\$\d\d\$'),        "bcrypt",                   "3200",  "bcrypt"),
    (re.compile(r'^\$y\$'),                    "yescrypt (Unix)",          None,    "crypt"),
    (re.compile(r'^\$7\$'),                    "scrypt",                   "8900",  None),
    (re.compile(r'^\$8\$'),                    "Cisco IOS type 8 (PBKDF2)","9200",  None),
    (re.compile(r'^\$P\$|^\$H\$'),             "phpass (WordPress / phpBB)","400",  "phpass"),
    (re.compile(r'^\$S\$'),                    "Drupal 7",                 "7900",  "drupal7"),
    (re.compile(r'^\$B\$'),                    "MediaWiki",                "3711",  None),
    (re.compile(r'^\$ml\$'),                   "macOS PBKDF2-SHA512",      "7100",  "pbkdf2-hmac-sha512"),
    (re.compile(r'^\$(DCC2|dcc2)\$'),          "Domain Cached Creds 2 (mscash2)","2100","mscash2"),
    (re.compile(r'^\{SSHA\}'),                 "LDAP {SSHA} (salted SHA1)","111",   "ssha"),
    (re.compile(r'^\{SHA\}'),                  "LDAP {SHA}",               "101",   "raw-sha1"),
    (re.compile(r'^\{MD5\}'),                  "LDAP {MD5}",               "90",    "raw-md5"),
    (re.compile(r'^pbkdf2_sha256\$'),          "Django PBKDF2-SHA256",     "10000", "django"),
    (re.compile(r'^\$pbkdf2-sha256\$'),        "PBKDF2-SHA256 (passlib)",  "10900", None),
    (re.compile(r'^sha1\$'),                   "Django SHA1",              "124",   "django"),
    (re.compile(r'^SCRAM-SHA-256\$'),          "PostgreSQL SCRAM-SHA-256", "28600", None),
    (re.compile(r'^\$argon2(id|i|d)\$', re.I), "Argon2",                   None,    "argon2"),
    (re.compile(r'^\$keepass\$'),              "KeePass (from keepass2john)","13400","keepass"),
    (re.compile(r'^\$DPAPImk\$1'),             "DPAPI masterkey v1",       "15300", "DPAPImk"),
    (re.compile(r'^\$DPAPImk\$2'),             "DPAPI masterkey v2",       "15310", "DPAPImk"),
    (re.compile(r'^\$mongodb-scram\$\*0'),     "MongoDB SCRAM-SHA-1",      "24100", None),
    (re.compile(r'^\$mongodb-scram\$\*1'),     "MongoDB SCRAM-SHA-256",    "24200", None),
    (re.compile(r'^\$krb5asrep\$'),            "Kerberos AS-REP (roast)",  "18200", "krb5asrep"),
    (re.compile(r'^\$krb5pa\$'),               "Kerberos preauth",         "7500",  "krb5pa-md5"),
]

# raw hex hashes: length -> ranked candidate list
RAW_HEX_DB = {
    16:  [("MySQL323", "200", "mysql"), ("half-LM / DES", None, None)],
    32:  [("MD5", "0", "raw-md5"), ("NTLM (NT hash)", "1000", "nt"),
          ("MD4", "900", "raw-md4"), ("LM", "3000", "lm"),
          ("double MD5", "2600", None)],
    40:  [("SHA1", "100", "raw-sha1"), ("MySQL4.1+ (had a *)", "300", "mysql-sha1"),
          ("RIPEMD-160", "6000", "ripemd-160")],
    56:  [("SHA-224", "1300", "raw-sha224"), ("SHA3-224", "17300", None)],
    64:  [("SHA-256", "1400", "raw-sha256"), ("SHA3-256", "17400", None),
          ("Keccak-256", "17800", None)],
    96:  [("SHA-384", "10800", "raw-sha384"), ("SHA3-384", "17500", None)],
    128: [("SHA-512", "1700", "raw-sha512"), ("Whirlpool", "6100", "whirlpool"),
          ("SHA3-512", "17600", None)],
}

# --------------------------------------------------------------------------- #
#  FILE KNOWLEDGE BASE
#  One source of truth for "what is this file and how do I read it".
#  Drives both --ext lookups AND scan-time loot detection.
#  Each entry:
#    keys    : names you can look up with --ext
#    match   : filename regex for scan-time detection
#    name    : human label
#    what    : what the file is
#    offense : why a pentester cares
#    cmds    : how to read / handle it
#    loot    : (extractor, crack-with) IF it yields a crackable hash, else None
# --------------------------------------------------------------------------- #
FILE_TYPES = [
    # --- password vaults / private keys (crackable loot) -------------------- #
    {"keys": ("kdbx",), "match": r'\.kdbx$',
     "name": "KeePass database",
     "what": "Encrypted password vault.",
     "offense": "Crack the master password, then open the whole vault.",
     "cmds": ["keepass2john FILE > hash", "hashcat -m 13400 hash rockyou.txt", "then: keepassxc / kpcli to open"],
     "loot": ("keepass2john {f}", "hashcat -m 13400")},
    {"keys": ("pfx", "p12"), "match": r'\.(pfx|p12)$',
     "name": "PKCS12 / PFX certificate bundle",
     "what": "Cert + private key, password protected. Shows up in ADCS/PKI boxes.",
     "offense": "Crack it, then use the cert for PKINIT auth (certipy/gettgtpkinit).",
     "cmds": ["pfx2john FILE > hash  (or crackpkcs12 -v FILE)", "openssl pkcs12 -in FILE -info"],
     "loot": ("pfx2john {f}", "john --format=pfx  (or crackpkcs12)")},
    {"keys": ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "ssh"), "match": r'(^|/)id_(rsa|dsa|ecdsa|ed25519)$',
     "name": "SSH private key",
     "what": "Private key for SSH auth. May be passphrase protected.",
     "offense": "If unprotected, ssh straight in. If protected, crack the passphrase.",
     "cmds": ["chmod 600 FILE && ssh -i FILE user@host", "ssh2john FILE > hash  (if passphrase-protected)"],
     "loot": ("ssh2john {f}", "hashcat -m 22911  (or john --format=ssh)")},
    {"keys": ("ppk",), "match": r'\.ppk$',
     "name": "PuTTY private key",
     "what": "Windows PuTTY key format.",
     "offense": "Convert to OpenSSH, or crack the passphrase.",
     "cmds": ["puttygen FILE -O private-openssh -o id_rsa", "putty2john FILE > hash"],
     "loot": ("putty2john {f}", "john --format=PuTTY")},
    {"keys": ("jks", "keystore"), "match": r'\.(jks|keystore)$',
     "name": "Java KeyStore",
     "what": "Java cert/key store, password protected.",
     "offense": "Crack the store password, then extract keys with keytool.",
     "cmds": ["keytool -list -v -keystore FILE", "keystore2john FILE > hash", "hashcat -m 15500 hash rockyou.txt"],
     "loot": ("keystore2john {f}", "hashcat -m 15500")},

    # --- AD / Windows secrets ---------------------------------------------- #
    {"keys": ("ntds", "dit"), "match": r'ntds\.dit$',
     "name": "NTDS.dit (AD database)",
     "what": "The whole domain's user database, including every NT hash.",
     "offense": "Dump every domain hash offline. You also need the SYSTEM hive.",
     "cmds": ["secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL"],
     "loot": None},
    {"keys": ("sam", "system", "security", "hive"), "match": r'(^|/)(SAM|SYSTEM|SECURITY)$',
     "name": "Windows registry hive (SAM/SYSTEM/SECURITY)",
     "what": "Registry hives holding local hashes and LSA secrets.",
     "offense": "Dump local NT hashes and cached creds offline.",
     "cmds": ["secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL", "pypykatz registry --sam SAM SYSTEM"],
     "loot": None},
    {"keys": ("dmp", "minidump"), "match": r'\.dmp$',
     "name": "Memory dump (often lsass.dmp)",
     "what": "Process memory dump. An lsass dump holds live creds/tickets.",
     "offense": "Parse it for plaintext, NT hashes, and Kerberos tickets.",
     "cmds": ["pypykatz lsa minidump FILE", "(mimikatz) sekurlsa::minidump FILE  then sekurlsa::logonpasswords"],
     "loot": None},
    {"keys": ("kirbi",), "match": r'\.kirbi$',
     "name": "Kerberos ticket (Windows / Rubeus format)",
     "what": "A TGT or TGS ticket. This is what pass-the-ticket (PTT) injects.",
     "offense": "Inject it and become that user, no password needed.",
     "cmds": ["Rubeus.exe ptt /ticket:FILE", "ticketConverter.py FILE ticket.ccache  (to use on Linux)"],
     "loot": None},
    {"keys": ("ccache",), "match": r'\.ccache$',
     "name": "Kerberos credential cache (Linux / Impacket)",
     "what": "Linux Kerberos ticket cache. The Impacket/PTT equivalent of .kirbi.",
     "offense": "Export it and every -k impacket tool authenticates as that user.",
     "cmds": ["export KRB5CCNAME=FILE", "klist   # inspect", "psexec.py -k -no-pass DOMAIN/user@host"],
     "loot": None},
    {"keys": ("reg",), "match": r'\.reg$',
     "name": "Registry export",
     "what": "Exported registry keys as text.",
     "offense": "Grep for autologon creds, VNC/PuTTY passwords, stored secrets.",
     "cmds": ["grep -iE 'password|DefaultPassword|autologon' FILE"],
     "loot": None},

    # --- config / source (credential hunting) ------------------------------ #
    {"keys": ("config", "webconfig", "conf", "ini", "properties"), "match": r'(web\.config$|\.(config|conf|ini|properties)$)',
     "name": "Config file",
     "what": "App/server config. web.config, appsettings, connection strings.",
     "offense": "Grep for DB connection strings, passwords, API keys.",
     "cmds": ["grep -iE 'password|connectionString|pwd=|secret|api[_-]?key' FILE"],
     "loot": None},
    {"keys": ("env",), "match": r'(^|/)\.env$',
     "name": "Environment file (.env)",
     "what": "Key=value secrets for an app.",
     "offense": "API keys, DB creds, JWT secrets sit here in plaintext.",
     "cmds": ["cat FILE"],
     "loot": None},
    {"keys": ("ps1", "psd1", "psm1"), "match": r'\.(ps1|psd1|psm1)$',
     "name": "PowerShell script/module",
     "what": "Windows scripting. Often automates auth.",
     "offense": "Look for plaintext creds and ConvertTo-SecureString reversal.",
     "cmds": ["grep -iE 'password|securestring|-key|credential' FILE"],
     "loot": None},
    {"keys": ("bak", "old", "orig", "save"), "match": r'\.(bak|old|orig|save|backup)$',
     "name": "Backup file",
     "what": "A backup of source or config, frequently forgotten.",
     "offense": "Often the un-sanitised version with creds still in it. Just read it.",
     "cmds": ["cat FILE   # or diff against the live version"],
     "loot": None},
    {"keys": ("swp", "swo"), "match": r'(^|/)\..*\.sw[po]$|\.sw[po]$',
     "name": "Vim swap file",
     "what": "Vim's recovery file, left behind mid-edit.",
     "offense": "Recovers the file someone was editing, sometimes with secrets.",
     "cmds": ["vim -r FILE", "strings FILE"],
     "loot": None},
    {"keys": ("git",), "match": r'(^|/)\.git(/|$)',
     "name": "Git repository",
     "what": "Version history. Old commits keep deleted secrets.",
     "offense": "Read history for creds removed in later commits.",
     "cmds": ["git log --all -p | grep -iE 'password|key|secret'", "(remote) git-dumper http://host/.git out/"],
     "loot": None},

    # --- databases --------------------------------------------------------- #
    {"keys": ("db", "sqlite", "sqlite3"), "match": r'\.(db|sqlite|sqlite3)$',
     "name": "SQLite database",
     "what": "Self-contained DB file. App data, users, session tokens.",
     "offense": "Dump the users table for hashes and secrets.",
     "cmds": ["sqlite3 FILE .tables", "sqlite3 FILE 'select * from users'"],
     "loot": None},
    {"keys": ("mdb", "accdb"), "match": r'\.(mdb|accdb)$',
     "name": "MS Access database",
     "what": "Access DB file.",
     "offense": "Extract tables for creds.",
     "cmds": ["mdb-tables FILE", "mdb-export FILE <table>"],
     "loot": None},
    {"keys": ("sql",), "match": r'\.sql$',
     "name": "SQL dump",
     "what": "Text dump of a database.",
     "offense": "Grep INSERTs into user/admin tables for hashes.",
     "cmds": ["grep -iE 'insert into .*(user|admin|password)' FILE"],
     "loot": None},

    # --- captures / logs --------------------------------------------------- #
    {"keys": ("pcap", "pcapng"), "match": r'\.(pcap|pcapng)$',
     "name": "Network capture",
     "what": "Recorded traffic.",
     "offense": "Extract cleartext creds, NetNTLM, HTTP basic auth, followed streams.",
     "cmds": ["wireshark FILE", "tshark -r FILE -Y 'http.authorization || ntlmssp'", "pcredz -f FILE"],
     "loot": None},
    {"keys": ("cap", "hccapx", "hc22000"), "match": r'\.(cap|hccapx|hc22000)$',
     "name": "WiFi handshake capture",
     "what": "WPA/WPA2 EAPOL handshake.",
     "offense": "Crack the WiFi PSK.",
     "cmds": ["hcxpcapngtool -o hash.hc22000 FILE", "hashcat -m 22000 hash.hc22000 rockyou.txt"],
     "loot": None},
    {"keys": ("evtx",), "match": r'\.evtx$',
     "name": "Windows event log",
     "what": "Binary Windows logs.",
     "offense": "Hunt logon events, PowerShell logs, sometimes creds in cmdlines.",
     "cmds": ["evtx_dump.py FILE", "chainsaw hunt FILE"],
     "loot": None},

    # --- disk / memory images ---------------------------------------------- #
    {"keys": ("vhd", "vhdx", "vmdk"), "match": r'\.(vhd|vhdx|vmdk)$',
     "name": "Virtual disk image",
     "what": "A whole disk. Mount it and it's a filesystem.",
     "offense": "Mount, then grab SAM/SYSTEM or SSH keys from the filesystem.",
     "cmds": ["guestmount -a FILE -i --ro /mnt/x   (or 7z l FILE)", "then loot /mnt/x/Windows/System32/config/"],
     "loot": None},
    {"keys": ("ova", "ovf"), "match": r'\.(ova|ovf)$',
     "name": "VM appliance",
     "what": "Packaged VM (a tar of a vmdk + metadata).",
     "offense": "Unpack to get the virtual disk, then treat as vmdk.",
     "cmds": ["tar xvf FILE   # yields a .vmdk", "then handle the .vmdk"],
     "loot": None},
    {"keys": ("iso", "img"), "match": r'\.(iso|img)$',
     "name": "Disk / optical image",
     "what": "Filesystem image.",
     "offense": "Mount and browse for anything left inside.",
     "cmds": ["7z x FILE   (or sudo mount -o loop FILE /mnt/x)"],
     "loot": None},
    {"keys": ("e01",), "match": r'\.e01$',
     "name": "EnCase forensic image",
     "what": "Forensic disk image.",
     "offense": "Mount it, then carve the filesystem.",
     "cmds": ["ewfmount FILE /mnt/ewf", "mount -o ro,loop /mnt/ewf/ewf1 /mnt/x"],
     "loot": None},
    {"keys": ("raw", "mem", "vmem", "core"), "match": r'\.(raw|mem|vmem|core|lime)$',
     "name": "Memory image",
     "what": "Full RAM capture.",
     "offense": "Volatility for processes, hashes, cmdlines, secrets.",
     "cmds": ["vol.py -f FILE windows.info", "vol.py -f FILE windows.hashdump"],
     "loot": None},

    # --- binaries / reversing ---------------------------------------------- #
    {"keys": ("exe", "dll"), "match": r'\.(exe|dll)$',
     "name": "Windows binary",
     "what": "PE executable or library. Could be native or .NET.",
     "offense": "strings first. If .NET, decompile to source; else Ghidra.",
     "cmds": ["strings -n 8 FILE | grep -iE 'pass|key|http'", ".NET: ilspycmd FILE  (or dnSpy)", "native: ghidra / r2 FILE"],
     "loot": None},
    {"keys": ("jar", "war"), "match": r'\.(jar|war)$',
     "name": "Java archive",
     "what": "Compiled Java, a zip of .class files.",
     "offense": "Decompile to Java source and read it.",
     "cmds": ["jadx FILE   (or procyon / jd-gui)", "unzip -l FILE"],
     "loot": None},
    {"keys": ("class",), "match": r'\.class$',
     "name": "Java bytecode",
     "what": "A single compiled Java class.",
     "offense": "Decompile to source.",
     "cmds": ["procyon FILE   (or jadx)"],
     "loot": None},
    {"keys": ("pyc", "pyo"), "match": r'\.(pyc|pyo)$',
     "name": "Compiled Python",
     "what": "Python bytecode.",
     "offense": "Decompile back to .py.",
     "cmds": ["uncompyle6 FILE   (py<=3.8)", "pycdc FILE   (newer python)"],
     "loot": None},
    {"keys": ("apk",), "match": r'\.apk$',
     "name": "Android package",
     "what": "Android app, a zip.",
     "offense": "Decompile for hardcoded creds, endpoints, keys.",
     "cmds": ["jadx -d out FILE", "grep -riE 'http|password|api' out/"],
     "loot": None},

    # --- keys / certs ------------------------------------------------------ #
    {"keys": ("pem", "key"), "match": r'\.(pem|key)$',
     "name": "PEM key / cert",
     "what": "Base64 cert or private key.",
     "offense": "If a private key, use it; if encrypted, crack it.",
     "cmds": ["openssl rsa -in FILE -check   (or openssl x509 -in FILE -text)", "ssh2john FILE > hash  (if a protected key)"],
     "loot": ("ssh2john {f}", "john --format=ssh")},
    {"keys": ("crt", "cer", "der"), "match": r'\.(crt|cer|der)$',
     "name": "Certificate",
     "what": "X.509 certificate.",
     "offense": "Read subject/SAN/issuer, sometimes reveals internal hostnames/users.",
     "cmds": ["openssl x509 -in FILE -noout -text   (add -inform der for .der)"],
     "loot": None},

    # --- archives / documents (crackable if encrypted) --------------------- #
    {"keys": ("zip",), "match": r'\.zip$',
     "name": "ZIP archive",
     "what": "Archive, maybe password protected.",
     "offense": "If encrypted, crack it. Else just unzip.",
     "cmds": ["unzip FILE   (if open)", "zip2john FILE > hash  (if encrypted)"],
     "loot": ("zip2john {f}", "hashcat -m 13600 (AES) / 17200s (pkzip)")},
    {"keys": ("rar",), "match": r'\.rar$',
     "name": "RAR archive", "what": "Archive, maybe password protected.",
     "offense": "If encrypted, crack it.",
     "cmds": ["unrar x FILE", "rar2john FILE > hash"],
     "loot": ("rar2john {f}", "hashcat -m 13000 (RAR5) / 12500 (RAR3)")},
    {"keys": ("7z",), "match": r'\.7z$',
     "name": "7-Zip archive", "what": "Archive, maybe password protected.",
     "offense": "If encrypted, crack it.",
     "cmds": ["7z x FILE", "7z2john.pl FILE > hash"],
     "loot": ("7z2john.pl {f}", "hashcat -m 11600")},
    {"keys": ("tar", "gz", "tgz", "bz2", "xz"), "match": r'\.(tar|gz|tgz|bz2|xz)$',
     "name": "Tar/compressed archive", "what": "Not encrypted, just packed.",
     "offense": "Extract and browse.",
     "cmds": ["tar xvf FILE   (or 7z x FILE)"],
     "loot": None},
    {"keys": ("pdf",), "match": r'\.pdf$',
     "name": "PDF", "what": "Document, maybe password protected.",
     "offense": "If protected, crack it. Else read metadata/text.",
     "cmds": ["pdftotext FILE -   /  exiftool FILE", "pdf2john.py FILE > hash  (if protected)"],
     "loot": ("pdf2john.py {f}", "hashcat -m 10500/10700")},
    {"keys": ("docx", "xlsx", "pptx", "doc", "xls"), "match": r'\.(docx|xlsx|pptx|doc|xls)$',
     "name": "Office document", "what": "Office file, maybe protected, maybe has macros.",
     "offense": "If protected, crack it. Check macros (olevba) for payloads/creds.",
     "cmds": ["olevba FILE   (macros)", "office2john.py FILE > hash  (if protected)"],
     "loot": ("office2john.py {f}", "hashcat -m 9400/9500/9600")},
    {"keys": ("gpg", "asc", "pgp"), "match": r'\.(gpg|asc|pgp)$',
     "name": "GPG/PGP file", "what": "Encrypted or signed data / a private key.",
     "offense": "If it's a symmetric-encrypted file or a key, crack the passphrase.",
     "cmds": ["gpg --decrypt FILE", "gpg2john FILE > hash"],
     "loot": ("gpg2john {f}", "hashcat -m 17010+")},

    # --- misc high-value --------------------------------------------------- #
    {"keys": ("msg", "eml"), "match": r'\.(msg|eml)$',
     "name": "Email", "what": "Saved email. .msg is Outlook, .eml is standard.",
     "offense": "Read for creds, internal info, attachments.",
     "cmds": ["(.msg) extract_msg FILE   /  msgconvert FILE", "(.eml) cat FILE"],
     "loot": None},
    {"keys": ("lnk",), "match": r'\.lnk$',
     "name": "Windows shortcut", "what": "Points at a target, sometimes with args/creds.",
     "offense": "Read the target path and arguments.",
     "cmds": ["lnkinfo FILE   (or exiftool FILE)"],
     "loot": None},
    {"keys": ("htpasswd",), "match": r'(^|/)\.?htpasswd$',
     "name": ".htpasswd", "what": "Apache basic-auth user:hash file.",
     "offense": "Crack the hashes. Format after the : tells you the type.",
     "cmds": ["cat FILE   # $apr1$ -> md5apr1 (-m 1600), {SHA} -> (-m 101), $2y$ -> bcrypt"],
     "loot": None},
    {"keys": ("netrc", "npmrc", "dockercfg", "git-credentials"), "match": r'(^|/)\.(netrc|npmrc|docker/config|git-credentials)$',
     "name": "Credential dotfile", "what": "Config files that store tokens/passwords in plaintext.",
     "offense": "Read directly, they hold live tokens or basic-auth creds.",
     "cmds": ["cat FILE"],
     "loot": None},
]

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


# --------------------------------------------------------------------------- #
#  context signatures (line-oriented, run first, mostly certain)
# --------------------------------------------------------------------------- #
def sig_secretsdump(line):
    m = re.match(r'^(?P<u>[^:\s]+):(?P<rid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::', line)
    if not m:
        return None
    empty_lm = m.group("lm").lower() == "aad3b435b51404eeaad3b435b51404ee"
    note = ("LM half is blank, only the NT hash matters." if empty_lm
            else "LM half present too, crackable separately with -m 3000.")
    return Finding(
        secret=m.group("nt"),
        kind="NTLM (NT hash)",
        confidence="certain",
        why="line is `user:RID:LM:NT:::` (secretsdump / NTDS.dit layout)",
        username=m.group("u"),
        note=note + " Pass-the-hash often beats cracking it.",
        commands=[("hashcat", hc("1000")), ("john", john("nt"))],
        extra={"rid": m.group("rid"), "lm": m.group("lm")},
    )

def sig_netntlmv2(line):
    m = re.match(r'^(?P<u>[^:\s]+)::(?P<d>[^:]*):(?P<c>[0-9a-fA-F]{16}):(?P<p>[0-9a-fA-F]{32}):(?P<b>[0-9a-fA-F]+)$', line.strip())
    if not m:
        return None
    return Finding(
        secret=line.strip(),
        kind="NetNTLMv2 (Responder / relay)",
        confidence="certain",
        why="layout `user::domain:16hex:32hex:blob` = NetNTLMv2 challenge/response",
        username=m.group("u"),
        note="Not the NT hash, cannot PTH. Must crack.",
        commands=[("hashcat", hc("5600")), ("john", john("netntlmv2"))],
    )

def sig_netntlmv1(line):
    m = re.match(r'^(?P<u>[^:\s]+)::(?P<d>[^:]*):(?P<a>[0-9a-fA-F]{48}):(?P<b>[0-9a-fA-F]{48}):(?P<c>[0-9a-fA-F]{16})$', line.strip())
    if not m:
        return None
    return Finding(
        secret=line.strip(),
        kind="NetNTLMv1 (challenge/response)",
        confidence="certain",
        why="layout `user::domain:48hex:48hex:16hex` = NetNTLMv1",
        username=m.group("u"),
        note="If you control the challenge (1122334455667788), crack->NTLM via crack.sh.",
        commands=[("hashcat", hc("5500")), ("john", john("netntlm"))],
    )

def sig_krb5tgs(line):
    m = re.search(r'\$krb5tgs\$(?P<et>\d+)\$[^\s]+', line)
    if not m:
        return None
    et = m.group("et")
    mode = {"23": "13100", "17": "19600", "18": "19700"}.get(et)
    um = re.search(r'\*([^*$]+)\*', m.group(0))
    return Finding(
        secret=m.group(0),
        kind=f"Kerberos TGS-REP (Kerberoast, etype {et})",
        confidence="certain",
        why=f"`$krb5tgs$` prefix, etype {et}",
        username=um.group(1) if um else None,
        note="Service account TGS. Crack offline, no lockout.",
        commands=[("hashcat", hc(mode)), ("john", john("krb5tgs"))] if mode else [("john", john("krb5tgs"))],
        extra={"etype": et},
    )

def sig_shadow(line):
    m = re.match(r'^(?P<u>[^:\s]+):(?P<h>\$[0-9a-zA-Z]{1,4}\$[^:\s]{4,}):', line)
    if not m:
        return None
    f = identify_token(m.group("h"))
    if f:
        f.username = m.group("u")
        f.kind += " (from /etc/shadow)"
        f.confidence = "certain"
        f.why = f"in a shadow line, {f.why}"
    return f

def sig_gpp(line):
    m = re.search(r'cpassword\s*=\s*["\'](?P<c>[A-Za-z0-9+/=]+)["\']', line)
    if not m:
        return None
    return Finding(
        secret=m.group("c"),
        kind="GPP cpassword (Group Policy Preferences)",
        confidence="certain",
        why="`cpassword=` attribute in Groups.xml",
        note="NOT a hash. AES-256 with a key Microsoft published. Decrypt.",
        commands=[("gpp-decrypt", f"gpp-decrypt '{m.group('c')}'")],
    )

def sig_jwt(line):
    m = re.search(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', line)
    if not m:
        return None
    tok = m.group(0)
    header  = _b64url(tok.split(".")[0])
    payload = _b64url(tok.split(".")[1])
    alg = ""
    mm = re.search(r'"alg"\s*:\s*"([^"]+)"', header or "")
    if mm:
        alg = mm.group(1)
    cmds, note = [], f"Decoded below. alg={alg or '?'}. "
    if alg.upper() == "NONE":
        note += "alg=none -> forge directly, no key."
    elif alg.upper().startswith("HS"):
        note += "HMAC -> crack the signing secret."
        cmds = [("hashcat", hc("16500")), ("jwt_tool", f"jwt_tool {tok} -C -d {WORDLIST}")]
    elif alg.upper().startswith(("RS", "ES", "PS")):
        note += "Asymmetric -> try RS256->HS256 key confusion."
        cmds = [("jwt_tool", f"jwt_tool {tok} -X k")]
    return Finding(
        secret=tok, kind="JSON Web Token (JWT)", confidence="certain",
        why="three base64url parts starting `eyJ` = a JWT",
        note=note, commands=cmds, extra={"header": header, "payload": payload},
    )

def sig_mssql(line):
    m = re.search(r'0x0(?P<v>[12])00[0-9A-Fa-f]{40,}', line)
    if not m:
        return None
    if m.group("v") == "2":
        return Finding(m.group(0), "MSSQL 2012/2014/2016/2019", "certain",
                       "`0x0200` prefix = MSSQL 2012+",
                       note="SHA-512 based.",
                       commands=[("hashcat", hc("1731")), ("john", john("mssql12"))])
    return Finding(m.group(0), "MSSQL 2000/2005", "likely",
                   "`0x0100` prefix = MSSQL 2000 or 2005",
                   note="Longer hash -> 2000 (-m 131). Shorter -> 2005 (-m 132), the common case.",
                   commands=[("hashcat 2005", hc("132")), ("hashcat 2000", hc("131"))])

def sig_pg_md5(line):
    m = re.search(r'\bmd5(?P<h>[0-9a-f]{32})\b', line)
    if not m:
        return None
    return Finding(
        secret=m.group(0), kind="PostgreSQL md5", confidence="likely",
        why="`md5` + 32 hex = PostgreSQL pg_authid format",
        note="The username is the salt. Feed hashcat as md5hash:username.",
        commands=[("hashcat", hc("12", username=True) + "  # format: md5hash:username")],
    )

def sig_salted_md5(line):
    m = re.match(r'^(?P<h>[0-9a-fA-F]{32}):(?P<s>[^\s:]{1,32})$', line.strip())
    if not m:
        return None
    return Finding(
        secret=line.strip(), kind="salted MD5 (CMS family)", confidence="ambiguous",
        why="`32hex:salt` = a salted-MD5 CMS scheme, recipe varies by platform",
        candidates=[("md5($salt.$pass) Joomla", "20", None),
                    ("md5($pass.$salt)", "10", None),
                    ("vBulletin <3.8.5", "2611", None),
                    ("vBulletin >=3.8.5", "2711", None),
                    ("IPB / MyBB", "2811", None)],
        note="Platform decides which. Try 20 and 10 first, then vBulletin/IPB modes.",
        commands=[("hashcat (Joomla 20)", hc("20")), ("hashcat (md5.salt 10)", hc("10"))],
    )

def sig_mysql5(line):
    if not re.fullmatch(r'\*[0-9A-Fa-f]{40}', line.strip()):
        return None
    return Finding(line.strip(), "MySQL 4.1+ / 5.x", "certain",
                   "40 hex with a leading `*` = MySQL 4.1+",
                   note="Strip the * for hashcat, keep it for john.",
                   commands=[("hashcat", hc("300") + "  # feed WITHOUT the *"),
                             ("john", john("mysql-sha1"))])

def sig_bcrypt(line):
    m = re.search(r'\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}', line)
    if not m:
        return None
    return Finding(m.group(0), "bcrypt", "certain",
                   "`$2y$NN$` prefix = bcrypt",
                   note="Slow by design, keep the wordlist tight.",
                   commands=[("hashcat", hc("3200")), ("john", john("bcrypt"))])

def sig_cisco_type7(line):
    m = re.search(r'\b(?:password|secret)\s+7\s+([0-9A-Fa-f]{4,})\b', line)
    if not m:
        return None
    return Finding(m.group(1), "Cisco IOS type 7 (reversible)", "certain",
                   "`password 7 <hex>` = Cisco type 7 Vigenere",
                   note="NOT a hash. Reverses instantly.",
                   commands=[("ciscot7", f"ciscot7.py -p {m.group(1)}")])

def sig_dollar9(line):
    m = re.search(r'\$9\$[./A-Za-z0-9]{6,}', line)
    if not m:
        return None
    tok = m.group(0)
    jun = re.search(r'\b(set|junos|groups\s*\{|security\s*\{|interfaces\s*\{)\b', line, re.I)
    cis = re.search(r'\b(enable|service\s+password|line\s+con|hostname|ios)\b', line, re.I)
    if jun and not cis:
        return Finding(tok, "Juniper JunOS $9$ (reversible)", "certain",
                       "`$9$` in a JunOS config (set/groups) = reversible",
                       note="NOT a hash. Decode it.",
                       commands=[("junos-decrypt", f"junos-decrypt '{tok}'"),
                                 ("alt", "any '$9$ juniper decrypt' decoder")])
    if cis and not jun:
        return Finding(tok, "Cisco IOS type 9 (scrypt)", "certain",
                       "`$9$` in a Cisco config = type 9 scrypt",
                       commands=[("hashcat", hc("9300"))])
    return Finding(tok, "$9$ - Cisco type9 OR Juniper", "ambiguous",
                   "`$9$` prefix collides across vendors, no config context to decide",
                   note="Cisco $9$ = scrypt (crack, -m 9300). Juniper $9$ = reversible (decode). "
                        "Check the surrounding config to tell which.",
                   commands=[("if Cisco", hc("9300")),
                             ("if Juniper", "junos-decrypt '<value>'")])

def match_file(tok: str) -> Finding | None:
    for e in FILE_TYPES:
        if not re.search(e["match"], tok, re.I):
            continue
        if e["loot"]:
            extractor, crack = e["loot"]
            return Finding(
                secret=tok, kind=f"loot file: {e['name']}", confidence="certain",
                why=f"filename matches {e['name']} (crackable, not a hash yet)",
                note=e["offense"],
                commands=[("extract", extractor.format(f=tok) + " > hash.txt"),
                          ("crack",   crack)],
            )
        return Finding(
            secret=tok, kind=f"file: {e['name']}", confidence="certain",
            why=f"filename matches {e['name']}",
            note=e["offense"],
            commands=[("read/handle", c.replace("FILE", tok)) for c in e["cmds"]],
        )
    return None


def lookup_ext(arg: str) -> dict | None:
    """Resolve a --ext argument (`.kdbx`, `kdbx`, or a path/name) to an entry."""
    base = arg.strip().split("/")[-1].split("\\")[-1]
    key  = base.lstrip(".").lower()
    for e in FILE_TYPES:                       # exact key hit
        if key in e["keys"]:
            return e
    for e in FILE_TYPES:                        # else match the name/path
        if re.search(e["match"], base, re.I) or re.search(e["match"], arg, re.I):
            return e
    return None


def explain_ext(arg):
    e = lookup_ext(arg)
    if not e:
        print(C.bold(f"\nUnknown: {arg}\n"))
        print("  Not in the knowledge base. Fall back to identifying it by content:")
        print(f"    {C.blu('$')} {C.grn('file ' + arg)}          {C.dim('# what is it, by magic bytes')}")
        print(f"    {C.blu('$')} {C.grn('strings -n 8 ' + arg + ' | less')}   {C.dim('# readable text, creds, paths')}")
        print(f"    {C.blu('$')} {C.grn('binwalk ' + arg)}       {C.dim('# embedded/appended files')}")
        print(f"    {C.blu('$')} {C.grn('xxd ' + arg + ' | head')}      {C.dim('# eyeball the header')}")
        print(C.dim("\n  Add it to FILE_TYPES once you know what it is.\n"))
        return
    print(C.bold(f"\n== {e['name']} ==\n"))
    print(f"  {C.cyn('what')}    : {e['what']}")
    print(f"  {C.cyn('offense')} : {e['offense']}")
    if e["loot"]:
        print(f"  {C.ylw('note')}    : this yields a crackable hash, extract it first.")
    print(f"  {C.cyn('how to read / handle')}:")
    for cmd in e["cmds"]:
        print(f"    {C.blu('$')} {C.grn(cmd)}")
    print()


def list_exts():
    print(C.bold("\nKnown file types (look up any with --ext <name>):\n"))
    for e in FILE_TYPES:
        loot = C.ylw(" [crackable]") if e["loot"] else ""
        print(f"  {C.grn(', '.join('.'+k for k in e['keys'][:4])):40}  {e['name']}{loot}")
    print()

SIGNATURES = [
    sig_secretsdump, sig_netntlmv2, sig_netntlmv1, sig_krb5tgs, sig_jwt,
    sig_gpp, sig_shadow, sig_mssql, sig_mysql5, sig_bcrypt,
    sig_cisco_type7, sig_dollar9, sig_pg_md5, sig_salted_md5,
]


# --------------------------------------------------------------------------- #
def _b64url(s):
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    except Exception:
        return None


def classify_raw(token: str) -> tuple[str | None, str | None, list, str | None]:
    t = token.strip()
    if HEX_RE.match(t) and len(t) in RAW_HEX_DB:
        return RAW_HEX_DB[len(t)][0][0], "ambiguous", RAW_HEX_DB[len(t)], \
               f"{len(t)}-char hex, no prefix or delimiters"
    if HEX_RE.match(t):
        return f"unknown {len(t)}-char hex", "ambiguous", [], f"{len(t)}-char hex, unrecognised length"
    if B64_RE.match(t) and len(t) >= 24 and (len(t) % 4 == 0 or t.endswith("=")):
        return "base64 blob", "ambiguous", [], "looks like base64, not a recognised hash shape"
    return None, None, [], None


def identify_token(token: str, blob: str = "") -> Finding | None:
    t = token.strip()
    if re.match(r'^\$9\$', t):
        return sig_dollar9(blob if blob else t)
    for rx, label, mode, jfmt in PREFIX_DB:
        if rx.search(t):
            cmds = []
            if mode:
                cmds.append(("hashcat", hc(mode)))
            if jfmt:
                cmds.append(("john", john(jfmt)))
            note = None if mode else "No standard hashcat mode, use john or a dedicated tool."
            return Finding(secret=t, kind=label, confidence="certain",
                           why=f"prefix `{rx.pattern.lstrip('^')}` is self-describing",
                           note=note, commands=cmds)
    label, conf, cands, why = classify_raw(t)
    if label is None:
        return None
    if label == "base64 blob":
        return Finding(t, label, conf, why,
                       note="Might wrap a hash or be a GPP cpassword. Decode first.",
                       commands=[("decode", f"echo '{t}' | base64 -d | xxd | head")])
    commands = []
    top = cands[0] if cands else None
    if top and top[1]:
        commands.append((f"hashcat (top: {top[0]})", hc(top[1])))
    if top and top[2]:
        commands.append(("john (top)", john(top[2])))
    note = ("Genuinely ambiguous, same length = many types. Context decides."
            if cands else None)
    return Finding(t, label, conf, why, note=note, candidates=cands, commands=commands)


def boost_ad_context(text, findings):
    if not re.search(r'secretsdump|:::|\bDC=|\.local\b|krbtgt|Administrator|NTLM|sAMAccountName', text, re.I):
        return
    for f in findings:
        if f.confidence == "ambiguous" and f.candidates:
            names = [c[0] for c in f.candidates]
            if "NTLM (NT hash)" in names and names[0] == "MD5":
                f.candidates.sort(key=lambda c: 0 if c[0].startswith("NTLM") else 1)
                f.kind = "NTLM (NT hash)"
                f.why += " + blob smells like AD, so NTLM promoted over MD5"
                f.note = "AD context promotes NTLM above MD5. Still ambiguous as a raw hash."
                f.commands = [("hashcat (NTLM)", hc("1000")), ("hashcat (if MD5)", hc("0"))]


# --------------------------------------------------------------------------- #
#  LOOT SIGNATURES  (only run in --loot mode: read tool OUTPUT, surface creds)
#  Each returns a Finding with category set (user | cred | note) and the source
#  line stored for highlighting.
# --------------------------------------------------------------------------- #
def loot_nxc_login(line):
    # nxc/cme: SMB 10.10.10.1 445 DC01 [+] domain.local\user:Password1 (Pwn3d!)
    m = re.search(r'\b(SMB|LDAP|WINRM|MSSQL|RDP|SSH|FTP|SMTP|WMI)\b.*\[\+\]\s+'
                  r'(?:([^\s\\]+)\\)?([^\s:]+):(\S+?)(\s+\(Pwn3d!\))?\s*$', line)
    if not m:
        return None
    proto, dom, user, secret, pwn = m.groups()
    pwned = bool(pwn)
    return Finding(
        secret=f"{user}:{secret}", kind="VALID credential" + (" (Pwn3d!/admin)" if pwned else ""),
        confidence="certain", why=f"nxc [+] success on {proto}" + (" with admin" if pwned else ""),
        username=user, category="cred", line=line,
        note="Confirmed working. " + ("Local admin here." if pwned else "Use it to pivot/enumerate."),
    )

def loot_secret_pair(line):
    # generic user:pass NOT hash-shaped, e.g. from configs / app output
    m = re.match(r'^([A-Za-z0-9._\-\\]{1,40}):([^\s:]{3,60})$', line.strip())
    if not m:
        return None
    user, val = m.group(1), m.group(2)
    if re.fullmatch(r'[0-9a-fA-F]{16,}', val) or val.startswith("$"):  # that's a hash, not a pass
        return None
    if re.search(r'\d', user) and re.fullmatch(r'[0-9a-fA-F]+', user):  # skip hex:hex
        return None
    return Finding(
        secret=line.strip(), kind="credential pair (user:pass)", confidence="likely",
        why="`name:value` where the value isn't hash-shaped", username=user,
        category="cred", line=line, note="Verify it: nxc smb $IP -u user -p pass.",
    )

def loot_keyword_pw(line):
    # password = X / pwd: X / secret: X
    m = re.search(r'(?i)(pass(?:word)?|pwd|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*["\']?([^\s"\']{3,})', line)
    if not m:
        return None
    return Finding(
        secret=m.group(2), kind=f"possible {m.group(1).lower()} (keyword)", confidence="likely",
        why=f"line contains `{m.group(1)}=` / `{m.group(1)}:`", category="cred", line=line,
        note="Keyword match, eyeball it, could be a placeholder.",
    )

def loot_description(line):
    # LDAP/SMB description field, classic place for a leaked password
    m = re.search(r'(?i)\bdescription\b\s*[:=]\s*(.+)$', line)
    if not m or len(m.group(1).strip()) < 3:
        return None
    return Finding(
        secret=m.group(1).strip(), kind="description field (check for creds)", confidence="likely",
        why="description fields are where admins leave passwords", category="note", line=line,
        note="Read it, boxes stash creds here constantly.",
    )

def loot_sidtype_user(line):
    # nxc --rid-brute / lookupsid: 1104: DOMAIN\jdoe (SidTypeUser)
    m = re.search(r'\d+:\s*(?:([^\s\\]+)\\)?([A-Za-z0-9._\-$]+)\s*\(SidType(?:User)\)', line)
    if not m:
        return None
    return Finding(secret=m.group(2), kind="username", confidence="certain",
                   why="RID-brute / lookupsid SidTypeUser entry", username=m.group(2),
                   category="user", line=line)

def loot_enum4linux_user(line):
    # enum4linux:  user:[svc_backup] rid:[0x455]
    m = re.search(r'user:\[([^\]]+)\]', line)
    if not m:
        return None
    return Finding(secret=m.group(1), kind="username", confidence="certain",
                   why="enum4linux user:[...] entry", username=m.group(1),
                   category="user", line=line)

LOOT_SIGNATURES = [
    loot_nxc_login, loot_sidtype_user, loot_enum4linux_user,
    loot_description, loot_keyword_pw, loot_secret_pair,
]


# --------------------------------------------------------------------------- #
#  SOURCE mode: hardcoded creds in source/config, even garbled or minified.
#  Scans the WHOLE blob (not line-by-line) so it works on one-line minified JS.
# --------------------------------------------------------------------------- #
def _ctx(text, s, e, pad=35):
    a, b = max(0, s - pad), min(len(text), e + pad)
    snip = re.sub(r'\s+', ' ', text[a:b].replace('\n', ' ').replace('\t', ' '))
    return ("..." if a > 0 else "") + snip.strip() + ("..." if b < len(text) else "")


def scan_source(text):
    out, seen = [], set()

    def add(secret, kind, cat, s, e, why, user=None):
        secret = (secret or "").strip()
        if cat == "user" and not user:
            user = secret
        key = (cat, secret)
        if secret and key not in seen:
            seen.add(key)
            out.append(Finding(secret=secret, kind=kind, confidence="likely", why=why,
                               username=user, category=cat, line=_ctx(text, s, e)))

    # 1) credential-named variable = "quoted string"  ($db_pass, apiSecret, AUTH_TOKEN...)
    for m in re.finditer(r'(?i)([A-Za-z0-9_\-]*(?:pass|pwd|pw|secret|token|api[_-]?key|auth|cred)[A-Za-z0-9_\-]*)'
                         r'\s*[:=]\s*["\'`]([^"\'`]{2,80})["\'`]', text):
        add(m.group(2), f"{m.group(1)} (hardcoded)", "cred", m.start(2), m.end(2),
            "credential-named variable assigned a quoted string")

    # 2) PHP define('DB_PASSWORD', '...')
    for m in re.finditer(r'(?i)define\(\s*["\']([^"\']*(?:pass|pwd|secret|key|token)[^"\']*)["\']'
                         r'\s*,\s*["\']([^"\']+)["\']', text):
        add(m.group(2), f"{m.group(1)} (PHP define)", "cred", m.start(2), m.end(2),
            "PHP define() of a credential constant")

    # 3) connection string:  Password=...;  User Id=...;
    for m in re.finditer(r'(?i)(?:password|pwd)\s*=\s*([^;\s"\'>]{2,})', text):
        add(m.group(1), "connection-string password", "cred", m.start(1), m.end(1),
            "Password= inside a connection string")
    for m in re.finditer(r'(?i)(?:user id|uid|user)\s*=\s*([^;\s"\'>]{2,})', text):
        add(m.group(1), "connection-string user", "user", m.start(1), m.end(1),
            "User= inside a connection string")

    # 4) URI with creds:  scheme://user:pass@host   (postgres, mongodb, ftp, http...)
    for m in re.finditer(r'([a-zA-Z][a-zA-Z0-9+.\-]*)://([^:/\s@]+):([^@/\s]+)@([^\s/:"\'`]+)', text):
        add(f"{m.group(2)}:{m.group(3)}", f"{m.group(1)} URI creds (@{m.group(4)})", "cred",
            m.start(2), m.end(3), "user:pass@host embedded in a URI", user=m.group(2))

    # 5) HTTP Basic auth header -> decode
    for m in re.finditer(r'(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})', text):
        dec = None
        try:
            dec = base64.b64decode(m.group(1) + "==").decode("utf-8", "replace")
        except Exception:
            pass
        add(dec or m.group(1), "HTTP Basic auth" + (" (decoded)" if dec else ""), "cred",
            m.start(1), m.end(1), "Authorization: Basic header",
            user=(dec.split(":")[0] if dec and ":" in dec else None))

    # 6) username-named variable
    for m in re.finditer(r'(?i)\b(user(?:name)?|login|uid)\s*[:=]\s*["\'`]?([A-Za-z0-9._\-\\@]{2,40})', text):
        add(m.group(2), "username (hardcoded)", "user", m.start(2), m.end(2),
            "username-named variable")

    return out


# --------------------------------------------------------------------------- #
def scan(text, loot=False):
    findings, seen = [], set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        matched = False
        for sig in SIGNATURES:
            f = sig(line)
            if f:
                key = (f.kind, f.secret)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
                matched = True
                break
        if loot and not matched:
            for sig in LOOT_SIGNATURES:
                f = sig(line)
                if f:
                    key = (f.category, f.secret)
                    if key not in seen:
                        seen.add(key)
                        findings.append(f)
                    break
    for tok in re.findall(r'[^\s"\'<>,;()\[\]{}]+', text):
        if len(tok) < 6:
            continue
        if any(tok in f.secret or f.secret in tok for f in findings):
            continue
        f = match_file(tok) or identify_token(tok, blob=text)
        if f:
            key = (f.kind, f.secret)
            if key not in seen:
                seen.add(key)
                findings.append(f)
    boost_ad_context(text, findings)
    return findings


def conf_badge(c):
    return {"certain": C.grn("[CERTAIN]"), "likely": C.ylw("[LIKELY ]"),
            "ambiguous": C.red("[GUESS  ]")}.get(c, f"[{c}]")


def hl(line, token):
    """Return the line with token highlighted (reverse-video) for --loot."""
    if not token or token not in line:
        return line
    mark = f"\033[7m{token}\033[0m" if C.on else f">>{token}<<"
    return line.replace(token, mark)


def render_loot(findings):
    users = sorted({f.username for f in findings if f.category == "user" and f.username})
    creds = [f for f in findings if f.category == "cred"]
    notes = [f for f in findings if f.category == "note"]
    hashes = [f for f in findings if f.category not in ("user", "cred", "note", "file")]
    files = [f for f in findings if f.category == "file" or f.kind.startswith(("loot file", "file:"))]

    print(C.bold("\n== LOOT ==\n"))
    if not (users or creds or notes or hashes or files):
        print(C.dim("  Nothing jumped out. Pipe in nxc/enum4linux/ldapsearch/rpcclient output."))
        print()
        return

    if creds:
        print(C.bold(C.grn(f"  CREDENTIALS ({len(creds)})")))
        for f in creds:
            badge = C.red("  <-- ADMIN") if "Pwn3d" in f.kind or "admin" in f.kind else ""
            print(f"    {C.grn(f.secret)}   {C.dim(f.kind)}{badge}")
            if f.line and f.line.strip() != f.secret:
                print(f"      {C.dim(hl(f.line.strip(), f.secret.split(':')[-1]))}")
        print()
    if users:
        print(C.bold(C.cyn(f"  USERNAMES ({len(users)})")))
        print("    " + ", ".join(users))
        print(C.dim(f"    -> save these: printf '%s\\n' {' '.join(users[:6])}{' ...' if len(users)>6 else ''} > users.txt"))
        print()
    if hashes:
        print(C.bold(C.ylw(f"  HASHES ({len(hashes)})")))
        for f in hashes:
            u = f"{f.username}  " if f.username else ""
            print(f"    {u}{C.ylw(f.secret[:60])}   {C.dim(f.kind)}")
        print(C.dim("    -> run these back through:  hashhound.py --why <file>"))
        print()
    if files:
        print(C.bold(C.blu(f"  FILES ({len(files)})")))
        for f in files:
            print(f"    {f.secret}   {C.dim(f.kind)}")
        print()
    if notes:
        print(C.bold(f"  WORTH A LOOK ({len(notes)})"))
        for f in notes:
            print(f"    {hl(f.line.strip(), f.secret) if f.line else f.secret}")
        print()


def render(findings, show_why):
    if not findings:
        print(C.dim("No credential-shaped strings, hashes, tokens, or loot files found."))
        return
    print(C.bold(f"\n== hashhound: {len(findings)} finding(s) ==\n"))
    for i, f in enumerate(findings, 1):
        print(f"{C.bold('#'+str(i))}  {conf_badge(f.confidence)} {C.cyn(f.kind)}")
        if f.username:
            print(f"    user   : {C.bold(f.username)}")
        short = f.secret if len(f.secret) <= 74 else f.secret[:70] + " ..."
        print(f"    value  : {short}")
        if show_why:
            print(f"    why    : {C.ylw(f.why)}")
        if f.candidates and f.confidence == "ambiguous":
            print(f"    could be: {C.ylw(', '.join(c[0] for c in f.candidates[:6]))}")
        if f.note:
            print(f"    note   : {C.dim(f.note)}")
        if f.extra.get("header"):
            print(f"    header : {f.extra['header']}")
        if f.extra.get("payload"):
            print(f"    payload: {f.extra['payload']}")
        for label, cmd in f.commands:
            print(f"    {C.blu('$')} {C.grn(cmd)}   {C.dim('# '+label)}")
        print()


def main():
    ap = argparse.ArgumentParser(description="context-aware hash/cred identifier + crack-command generator")
    ap.add_argument("file", nargs="?", help="file to scan (or pipe via stdin)")
    ap.add_argument("-s", "--string", help="identify a single string directly")
    ap.add_argument("--why", action="store_true", help="show the tell each identification matched on")
    ap.add_argument("--loot", action="store_true", help="read tool output (nxc/enum4linux/ldapsearch) and highlight creds, users, hashes")
    ap.add_argument("--source", action="store_true", help="scan source/config (even garbled/minified) for hardcoded creds")
    ap.add_argument("-e", "--ext", help="explain a file type and how to read it, e.g. --ext ccache (use 'list' to see all)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    if args.no_color:
        C.on = False
    if args.ext:
        list_exts() if args.ext.lower() == "list" else explain_ext(args.ext)
        return
    if args.string:
        text = args.string
    elif args.file:
        with open(args.file, "r", errors="replace") as fh:
            text = fh.read()
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        ap.print_help()
        sys.exit(1)
    if args.source:
        combined, seen = [], set()
        for f in scan(text) + scan_source(text):
            key = (f.category, f.secret)
            if key not in seen:
                seen.add(key)
                combined.append(f)
        render_loot(combined)
    elif args.loot:
        render_loot(scan(text, loot=True))
    else:
        render(scan(text), args.why)


if __name__ == "__main__":
    try:
        import signal
        if hasattr(signal, "SIGPIPE"):
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
