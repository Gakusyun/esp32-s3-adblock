import pathlib
import subprocess
import sys
import tempfile
import unittest

# Make "from build_blocklist import ..." work whether this file is run directly,
# via `python -m unittest` or via pytest.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from build_blocklist import HASH_BYTES, fnv  # noqa: E402


def build(sources: dict[str, str]) -> set[int]:
    """Run build_blocklist.py over the given {filename: contents} and return the hashes."""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        output = root / 'blocklist.bin'
        paths = []
        for name, text in sources.items():
            p = root / name
            p.write_text(text, encoding='utf-8')
            paths.append(str(p))
        subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                        str(output), *paths], check=True, capture_output=True, text=True)
        data = output.read_bytes()
        return {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                for i in range(0, len(data), HASH_BYTES)}


class BuildBlocklistTests(unittest.TestCase):
    def test_hosts_line_includes_every_domain(self):
        hashes = build({'hosts': '0.0.0.0 ads.example.com tracker.example.com # comment\n'
                                 '127.0.0.1 metrics.example.com\n'})
        self.assertEqual(hashes, {fnv(d.encode()) for d in
                                  ('ads.example.com', 'tracker.example.com', 'metrics.example.com')})

    def test_allow_rule_removes_domain(self):
        # @@||domain^ must cancel a block rule, or the device would over-block.
        hashes = build({'rules': '||ads.example.com^\n||ok.example.com^\n@@||ok.example.com^\n'})
        self.assertEqual(hashes, {fnv(b'ads.example.com')})

    def test_modifiers_and_paths_are_skipped(self):
        hashes = build({'rules': '||ads.example.com^$third-party\n||tracker.example.com/path\n'
                                 '||plain.example.com^\n'})
        self.assertEqual(hashes, {fnv(b'plain.example.com')})

    def test_duplicates_are_deduped(self):
        hashes = build({'rules': 'a.example.com\nb.example.com\na.example.com\n'})
        self.assertEqual(hashes, {fnv(b'a.example.com'), fnv(b'b.example.com')})


if __name__ == '__main__':
    unittest.main()
