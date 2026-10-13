import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from support import KEY_B64, ea, encrypt_row, make_db, otpauth


def make_icon_root(root: Path) -> Path:
    """A small copy of Ente Auth's bundled icon layout."""
    (root / "custom-icons/_data").mkdir(parents=True)
    (root / "custom-icons/icons").mkdir(parents=True)
    (root / "simple-icons/_data").mkdir(parents=True)
    (root / "simple-icons/icons").mkdir(parents=True)
    (root / "custom-icons/_data/custom-icons.json").write_text(json.dumps({"icons": [
        {"title": "GitHub", "slug": "github", "hex": "181717"},
        {"title": "Google", "altNames": ["Gmail"]},
        {"title": "Ente", "hex": "1db954"},
        {"title": "Broken", "slug": "../../outside", "hex": "112233"},
        {"title": "BadHex", "hex": "zzzzzz"},
        {"title": "NoFile"},
    ]}))
    (root / "simple-icons/_data/simple-icons.json").write_text(json.dumps([
        {"title": "Discord", "hex": "5865F2"},
        {"title": "Ente", "hex": "000000"},
        {"title": "Tailscale", "slug": "tailscale", "hex": "242424"},
        {"title": "Société Générale", "hex": "E9041E"},
    ]))
    for rel in ("custom-icons/icons/github.svg", "custom-icons/icons/google.svg",
                "custom-icons/icons/ente.svg", "custom-icons/icons/badhex.svg",
                "simple-icons/icons/discord.svg", "simple-icons/icons/ente.svg",
                "simple-icons/icons/tailscale.svg", "simple-icons/icons/societegenerale.svg"):
        (root / rel).write_text("<svg/>")
    (root.parent / "outside.svg").write_text("<svg/>")
    return root


class ResolveIconTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = make_icon_root(Path(self.tmp.name) / "assets")
        self.index = ea.load_icon_index(self.root)

    def resolve(self, name):
        return ea.resolve_icon(name, self.index, self.root)

    def path(self, rel):
        return str((self.root / rel).resolve())

    def test_custom_icon_with_colour(self):
        self.assertEqual(self.resolve("GitHub"), (self.path("custom-icons/icons/github.svg"), "181717"))

    def test_custom_icon_without_colour_keeps_its_own_colours(self):
        self.assertEqual(self.resolve("Google"), (self.path("custom-icons/icons/google.svg"), ""))

    def test_alt_name(self):
        self.assertEqual(self.resolve("Gmail"), (self.path("custom-icons/icons/google.svg"), ""))

    def test_simple_icon(self):
        self.assertEqual(self.resolve("Discord"), (self.path("simple-icons/icons/discord.svg"), "5865F2"))

    def test_custom_wins_over_simple(self):
        self.assertEqual(self.resolve("Ente"), (self.path("custom-icons/icons/ente.svg"), "1DB954"))

    def test_case_and_spaces_ignored(self):
        self.assertEqual(self.resolve("  git hub "), self.resolve("GitHub"))

    def test_part_before_bracket_or_dot(self):
        self.assertEqual(self.resolve("Google (work)"), self.resolve("Google"))
        self.assertEqual(self.resolve("discord.com"), self.resolve("Discord"))

    def test_accented_simple_icon_without_slug(self):
        self.assertEqual(self.resolve("Société Générale"),
                         (self.path("simple-icons/icons/societegenerale.svg"), "E9041E"))

    def test_no_match_empty_name_or_missing_file(self):
        for name in ("Unknown Bank", "", "   ", "NoFile"):
            with self.subTest(name=name):
                self.assertEqual(self.resolve(name), ("", ""))

    def test_path_outside_icon_folder_refused(self):
        self.assertEqual(self.resolve("Broken"), ("", ""))

    def test_symlink_out_of_icon_folder_refused(self):
        os.remove(self.root / "simple-icons/icons/discord.svg")
        os.symlink(Path(self.tmp.name) / "outside.svg", self.root / "simple-icons/icons/discord.svg")
        self.assertEqual(self.resolve("Discord"), ("", ""))

    def test_bad_colour_dropped(self):
        self.assertEqual(self.resolve("BadHex"), (self.path("custom-icons/icons/badhex.svg"), ""))

    def test_missing_or_corrupt_index_means_no_icons(self):
        empty = ea.load_icon_index(Path(self.tmp.name) / "nope")
        self.assertEqual(ea.resolve_icon("GitHub", empty, self.root), ("", ""))
        (self.root / "custom-icons/_data/custom-icons.json").write_text("{not json")
        (self.root / "simple-icons/_data/simple-icons.json").write_text("[1, 2]")
        broken = ea.load_icon_index(self.root)
        self.assertEqual(ea.resolve_icon("Discord", broken, self.root), ("", ""))


class EntryIconTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.root = make_icon_root(self.dir / "assets")
        p = mock.patch.object(ea, "ICON_ROOT", self.root)
        p.start()
        self.addCleanup(p.stop)

    def entries(self, *uris):
        make_db(self.dir / ea.ONLINE_DB, [(f"id{i}", *encrypt_row(u)) for i, u in enumerate(uris)])
        return ea.list_entries(1, now=59, data_dir=self.dir, keys={"auth_secret_key": KEY_B64})["entries"]

    def test_entries_carry_icon_from_issuer(self):
        e = self.entries(otpauth("Discord:me", issuer="Discord"))[0]
        self.assertEqual((e["icon"], e["iconColor"]),
                         (str((self.root / "simple-icons/icons/discord.svg").resolve()), "5865F2"))

    def test_icon_picked_in_ente_wins_over_issuer(self):
        e = self.entries(otpauth("Work:me", issuer="Work",
                                 code_display={"iconSrc": "customIcon", "iconID": "github"}))[0]
        self.assertEqual(e["icon"], str((self.root / "custom-icons/icons/github.svg").resolve()))

    def test_no_icon(self):
        e = self.entries(otpauth("Nowhere:me", issuer="Nowhere"))[0]
        self.assertEqual((e["icon"], e["iconColor"]), ("", ""))


if __name__ == "__main__":
    unittest.main()
