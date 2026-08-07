#!/usr/bin/env python3
"""
Unit tests for hashhound.py's identification logic.

Run with: python3 -m unittest tests.test_hashhound -v
(or just: python3 tests/test_hashhound.py)

Pure stdlib, same as the rest of the project, no pytest required.

These tests exist to catch regressions in the identification tables, not to
prove the tool is bug-free against every hash format that exists. Each case
below is a real, recognisable sample of the format it claims to be.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hashhound as hh


class TestIdentifyTokenPrefixes(unittest.TestCase):
    """Self-describing $prefix$ hashes should resolve with certain confidence
    and the right hashcat mode, independent of surrounding context."""

    def test_md5crypt(self):
        f = hh.identify_token("$1$abcdefgh$dummyhashvalueforthistest1")
        self.assertIsNotNone(f)
        self.assertIn("md5crypt", f.kind)
        self.assertEqual(f.confidence, "certain")
        self.assertTrue(any("-m 500" in cmd for _, cmd in f.commands))

    def test_sha512crypt(self):
        f = hh.identify_token("$6$saltsalt$" + "a" * 86)
        self.assertIsNotNone(f)
        self.assertIn("sha512crypt", f.kind)
        self.assertTrue(any("-m 1800" in cmd for _, cmd in f.commands))

    def test_bcrypt(self):
        sample = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        f = hh.identify_token(sample)
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "bcrypt")
        self.assertTrue(any("-m 3200" in cmd for _, cmd in f.commands))

    def test_phpass_wordpress(self):
        f = hh.identify_token("$P$B" + "x" * 30)
        self.assertIsNotNone(f)
        self.assertIn("phpass", f.kind)
        self.assertTrue(any("-m 400" in cmd for _, cmd in f.commands))

    def test_drupal7(self):
        f = hh.identify_token("$S$D" + "y" * 51)
        self.assertIsNotNone(f)
        self.assertIn("Drupal", f.kind)
        self.assertTrue(any("-m 7900" in cmd for _, cmd in f.commands))

    def test_django_pbkdf2(self):
        f = hh.identify_token("pbkdf2_sha256$260000$somesalt$" + "b" * 44)
        self.assertIsNotNone(f)
        self.assertIn("Django", f.kind)
        self.assertTrue(any("-m 10000" in cmd for _, cmd in f.commands))

    def test_kerberoast_etype23(self):
        # $krb5tgs$ tickets aren't self-describing prefixes in PREFIX_DB
        # (identify_token's table) - they're recognised by the dedicated
        # sig_krb5tgs() signature that scan() runs line-by-line.
        sample = "$krb5tgs$23$*svc_sql$CORP.LOCAL$CORP.LOCAL/svc_sql*$" + "c" * 32 + "$" + "d" * 64
        f = hh.sig_krb5tgs(sample)
        self.assertIsNotNone(f)
        self.assertIn("Kerberoast", f.kind)
        self.assertEqual(f.extra.get("etype"), "23")
        self.assertTrue(any("-m 13100" in cmd for _, cmd in f.commands))


class TestIdentifyTokenRawHex(unittest.TestCase):
    """Bare hex with no delimiters or prefix is genuinely ambiguous: the tool
    should rank candidates by length, not pretend to be certain."""

    def test_32_char_hex_is_ambiguous_not_certain(self):
        f = hh.identify_token("8846f7eaee8fb117ad06bdd830b7586c")
        self.assertIsNotNone(f)
        self.assertEqual(f.confidence, "ambiguous")
        candidate_names = [c[0] for c in f.candidates]
        self.assertIn("MD5", candidate_names)
        self.assertIn("NTLM (NT hash)", candidate_names)

    def test_32_char_hex_top_guess_is_md5_without_context(self):
        f = hh.identify_token("8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(f.kind, "MD5")

    def test_40_char_hex_is_sha1(self):
        f = hh.identify_token("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "SHA1")

    def test_64_char_hex_is_sha256(self):
        # SHA-256 of an empty string, a well-known reference value.
        f = hh.identify_token("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "SHA-256")

    def test_unrecognised_hex_length_still_flagged_not_dropped(self):
        # 20 hex chars matches no entry in RAW_HEX_DB; the tool should say so
        # rather than silently returning nothing.
        f = hh.identify_token("a" * 20)
        self.assertIsNotNone(f)
        self.assertIn("unknown", f.kind)
        self.assertEqual(f.confidence, "ambiguous")

    def test_non_hex_non_hash_returns_none(self):
        self.assertIsNone(hh.identify_token("just a sentence, not a hash"))


class TestSecretsdumpContext(unittest.TestCase):
    """Context should resolve what a bare hash can't: the same 32-hex value
    is certain-confidence NTLM once it's sitting in a secretsdump line."""

    def test_secretsdump_line_is_certain_ntlm(self):
        line = "svc:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        f = hh.sig_secretsdump(line)
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "NTLM (NT hash)")
        self.assertEqual(f.confidence, "certain")
        self.assertEqual(f.username, "svc")
        self.assertEqual(f.secret, "8846f7eaee8fb117ad06bdd830b7586c")

    def test_secretsdump_flags_blank_lm_half(self):
        line = "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        f = hh.sig_secretsdump(line)
        self.assertIn("only the NT hash matters", f.note)

    def test_non_secretsdump_line_returns_none(self):
        self.assertIsNone(hh.sig_secretsdump("this is not a secretsdump line"))


class TestOtherSignatures(unittest.TestCase):
    def test_netntlmv2(self):
        line = r"jdoe::CORP:1122334455667788:aabbccddeeff00112233445566778899:0101000000000000"
        f = hh.sig_netntlmv2(line)
        self.assertIsNotNone(f)
        self.assertIn("NetNTLMv2", f.kind)
        self.assertTrue(any("-m 5600" in cmd for _, cmd in f.commands))

    def test_gpp_cpassword(self):
        line = '<Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" ... />'
        f = hh.sig_gpp(line)
        self.assertIsNotNone(f)
        self.assertIn("GPP", f.kind)
        self.assertIn("gpp-decrypt", f.commands[0][0])

    def test_cisco_type7(self):
        line = "password 7 08351E1A0A1516041C1A"
        f = hh.sig_cisco_type7(line)
        self.assertIsNotNone(f)
        self.assertIn("type 7", f.kind)
        self.assertIn("NOT a hash", f.note)

class TestFileTypeLookup(unittest.TestCase):
    def test_kdbx_is_recognised_and_marked_crackable(self):
        e = hh.lookup_ext("vault.kdbx")
        self.assertIsNotNone(e)
        self.assertEqual(e["name"], "KeePass database")
        self.assertIsNotNone(e["loot"])

    def test_unknown_extension_returns_none(self):
        self.assertIsNone(hh.lookup_ext("weird.notarealextension"))

    def test_match_file_on_ntds(self):
        f = hh.match_file("ntds.dit")
        self.assertIsNotNone(f)
        self.assertIn("NTDS.dit", f.kind)

if __name__ == "__main__":
    unittest.main()
