#!/usr/bin/env python3
"""
Unit tests for the dossh client keymap: terminal input bytes -> BIOS
(scancode, ascii, modifiers) events and KEY wire frames.

Run: python3 test/test_keymap.py

MIT License. Copyright (c) 2026 Sergey Subbotin.
"""
import importlib.machinery
import importlib.util
import os
import unittest

CLIENT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "client", "dossh")

loader = importlib.machinery.SourceFileLoader("dossh_client", CLIENT)
spec = importlib.util.spec_from_loader("dossh_client", loader)
dossh = importlib.util.module_from_spec(spec)
loader.exec_module(dossh)


class KeymapTest(unittest.TestCase):
    def events(self, data, flush=False):
        events, rest = dossh.parse_input(data, flush)
        return events, rest

    def test_lowercase_letter(self):
        events, rest = self.events(b"a")
        self.assertEqual(events, [(0x1E, ord("a"), 0)])
        self.assertEqual(rest, b"")

    def test_uppercase_letter_same_scancode(self):
        events, _ = self.events(b"A")
        self.assertEqual(events, [(0x1E, ord("A"), 0)])

    def test_digits_and_punctuation(self):
        events, _ = self.events(b"1")
        self.assertEqual(events, [(0x02, ord("1"), 0)])
        events, _ = self.events(b"\\")
        self.assertEqual(events, [(0x2B, ord("\\"), 0)])

    def test_enter(self):
        events, _ = self.events(b"\r")
        self.assertEqual(events, [(0x1C, 0x0D, 0)])

    def test_tab(self):
        events, _ = self.events(b"\t")
        self.assertEqual(events, [(0x0F, 0x09, 0)])

    def test_terminal_backspace_becomes_bios_backspace(self):
        # terminals send DEL (0x7F) for the backspace key
        events, _ = self.events(b"\x7f")
        self.assertEqual(events, [(0x0E, 0x08, 0)])

    def test_ctrl_c(self):
        events, _ = self.events(b"\x03")
        self.assertEqual(events, [(0x2E, 0x03, 0)])

    def test_space(self):
        events, _ = self.events(b" ")
        self.assertEqual(events, [(0x39, ord(" "), 0)])

    def test_arrow_up_is_extended_key(self):
        events, rest = self.events(b"\x1b[A")
        self.assertEqual(events, [(0x48, 0x00, 0)])
        self.assertEqual(rest, b"")

    def test_arrow_keys(self):
        for seq, scan in ((b"\x1b[B", 0x50), (b"\x1b[C", 0x4D),
                          (b"\x1b[D", 0x4B)):
            events, _ = self.events(seq)
            self.assertEqual(events, [(scan, 0x00, 0)], seq)

    def test_home_end_pgup_pgdn_ins_del(self):
        for seq, scan in ((b"\x1b[H", 0x47), (b"\x1b[F", 0x4F),
                          (b"\x1b[5~", 0x49), (b"\x1b[6~", 0x51),
                          (b"\x1b[2~", 0x52), (b"\x1b[3~", 0x53)):
            events, _ = self.events(seq)
            self.assertEqual(events, [(scan, 0x00, 0)], seq)

    def test_function_keys_ss3(self):
        # xterm F1-F4: ESC O P..S
        for seq, scan in ((b"\x1bOP", 0x3B), (b"\x1bOQ", 0x3C),
                          (b"\x1bOR", 0x3D), (b"\x1bOS", 0x3E)):
            events, _ = self.events(seq)
            self.assertEqual(events, [(scan, 0x00, 0)], seq)

    def test_function_keys_csi(self):
        for seq, scan in ((b"\x1b[15~", 0x3F), (b"\x1b[17~", 0x40),
                          (b"\x1b[21~", 0x44)):
            events, _ = self.events(seq)
            self.assertEqual(events, [(scan, 0x00, 0)], seq)

    def test_lone_escape_pends_without_flush(self):
        events, rest = self.events(b"\x1b", flush=False)
        self.assertEqual(events, [])
        self.assertEqual(rest, b"\x1b")

    def test_lone_escape_is_esc_key_on_flush(self):
        events, rest = self.events(b"\x1b", flush=True)
        self.assertEqual(events, [(0x01, 0x1B, 0)])
        self.assertEqual(rest, b"")

    def test_partial_csi_pends(self):
        events, rest = self.events(b"\x1b[", flush=False)
        self.assertEqual(events, [])
        self.assertEqual(rest, b"\x1b[")

    def test_mixed_text_run(self):
        events, rest = self.events(b"dir\r")
        self.assertEqual([e[1] for e in events],
                         [ord("d"), ord("i"), ord("r"), 0x0D])
        self.assertEqual(rest, b"")

    def test_key_frame_wire_format(self):
        self.assertEqual(dossh.key_frame(0x1E, ord("a"), 0),
                         b"DSSH\x02\x1e\x61\x00")


if __name__ == "__main__":
    unittest.main(verbosity=1)
