#!/usr/bin/env python3
"""
loothound - offensive security triage toolkit

One command for the repetitive parts of working a box: identify hashes and
files, read tool output for creds, dig hardcoded creds out of source, and
recall enumeration methodology.

    loothound hash    <hash|file> [--why]     # what hash is this + how to crack it
    loothound file    <type|list>             # what file type is this + how to read it
    loothound loot    [file]                   # read nxc/enum4linux output, highlight loot
    loothound source  [file]                   # find hardcoded creds in source/config
    loothound scan    <nmap.txt> [--ip ...]    # per-service methodology + DC detection
    loothound recon   <task> [--ip ...]        # recall how to do a task (kerberoast, vhost...)
    loothound service <name>                   # one service's playbook
    loothound list                             # everything it knows

Target flags (fill placeholders): --ip --domain --dc --user --password --attacker
Reads from stdin when no file is given, so you can pipe tools straight in:

    nxc smb 10.10.10.10 -u guest -p '' --rid-brute | loothound loot

Wraps hashhound.py and advisor.py, which also still run standalone.
No third-party deps. Pure stdlib.
"""

import sys
import os
import argparse

import hashhound as hh
import advisor as ad


def read_input(arg):
    if arg and arg != "-":
        with open(arg, errors="replace") as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def set_color(no_color):
    if no_color:
        hh.C.on = False
        ad.C.on = False


def set_vars(args):
    for flag, key in [("ip", "$IP"), ("domain", "$DOMAIN"), ("dc", "$DC"),
                      ("user", "$USER"), ("pw", "$PASS"), ("attacker", "$ATTACKER")]:
        v = getattr(args, flag, None)
        if v:
            ad.VARS[key] = v


def add_target_flags(sp):
    sp.add_argument("--ip")
    sp.add_argument("--domain")
    sp.add_argument("--dc")
    sp.add_argument("--user")
    sp.add_argument("--password", dest="pw")
    sp.add_argument("--attacker")
    sp.add_argument("--no-color", action="store_true")


def source_findings(text):
    combined, seen = [], set()
    for f in hh.scan(text) + hh.scan_source(text):
        key = (f.category, f.secret)
        if key not in seen:
            seen.add(key)
            combined.append(f)
    return combined


def main():
    p = argparse.ArgumentParser(
        prog="loothound",
        description="offensive security triage toolkit: identify hashes and files, "
                    "read tool output for loot, and recall enum methodology")
    sub = p.add_subparsers(dest="cmd")

    h = sub.add_parser("hash", help="identify a hash and get the crack command")
    h.add_argument("target", nargs="?", help="a hash string or a file")
    h.add_argument("--why", action="store_true")
    h.add_argument("--no-color", action="store_true")

    f = sub.add_parser("file", help="explain a file type and how to read it (or 'list')")
    f.add_argument("ext")
    f.add_argument("--no-color", action="store_true")

    l = sub.add_parser("loot", help="read tool output and highlight creds/users/hashes")
    l.add_argument("file", nargs="?")
    l.add_argument("--no-color", action="store_true")

    s = sub.add_parser("source", help="find hardcoded creds in source/config, even minified")
    s.add_argument("file", nargs="?")
    s.add_argument("--no-color", action="store_true")

    sc = sub.add_parser("scan", help="analyse an nmap scan -> methodology + DC detection")
    sc.add_argument("file", nargs="?")
    add_target_flags(sc)

    r = sub.add_parser("recon", help="recall how to do a task, e.g. loothound recon kerberoast")
    r.add_argument("task")
    add_target_flags(r)

    sv = sub.add_parser("service", help="one service's playbook, e.g. loothound service smb")
    sv.add_argument("name")
    add_target_flags(sv)

    li = sub.add_parser("list", help="list everything the toolkit knows")
    li.add_argument("--no-color", action="store_true")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return
    set_color(getattr(args, "no_color", False))
    set_vars(args)

    if args.cmd == "hash":
        if args.target and "\n" not in args.target and len(args.target) < 400 \
                and not os.path.exists(args.target):
            text = args.target
        else:
            text = read_input(args.target)
        hh.render(hh.scan(text), args.why)

    elif args.cmd == "file":
        hh.list_exts() if args.ext.lower() == "list" else hh.explain_ext(args.ext)

    elif args.cmd == "loot":
        hh.render_loot(hh.scan(read_input(args.file), loot=True))

    elif args.cmd == "source":
        hh.render_loot(source_findings(read_input(args.file)))

    elif args.cmd == "scan":
        ad.advise_scan(ad.parse_nmap(read_input(args.file)))
        print()

    elif args.cmd == "recon":
        t = ad.find_task(args.task)
        ad.print_task(t) if t else print(f"No task '{args.task}'. Try: loothound list")
        print()

    elif args.cmd == "service":
        svc = ad.find_service(-1, args.name)
        ad.print_service(svc) if svc else print(f"No service '{args.name}'. Try: loothound list")
        print()

    elif args.cmd == "list":
        ad.list_all()
        hh.list_exts()


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
