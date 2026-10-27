#!/usr/bin/env python3
"""Render the actual menu with mock services; check terminal cells and both columns."""
from pathlib import Path
import re
import subprocess
import unicodedata

root = Path(__file__).resolve().parents[1]
command = r'''
source <(sed '$d' "$1")
clear() { printf '\033[2J\033[H'; }
find() { echo snell.service; }
systemctl() { return 0; }
latest_snell_version_cache=v6.0.0rc123
latest_snell_v6_version_cache=v6.0.0rc123
show_menu
'''
output = subprocess.check_output(
    ["bash", "-c", command, "preview", str(root / "snell-ai.sh")], text=True
)
csi = re.compile(r"\x1b\[([0-9;]*)([A-Za-z])")
plain = csi.sub("", output)


def columns(text):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


rows = [line for line in plain.splitlines() if re.match(r"^   \[ *\d+\] ", line)]
assert len(rows) == 7, rows
keys = []
for line in rows:
    items = list(re.finditer(r"\[( *\d+)\] (\S+)", line))
    assert len(items) == 2, line
    assert [columns(line[:item.start()]) for item in items] == [3, 30], line
    assert all(len(item[2]) == 6 and columns(item[2]) == 12 for item in items), line
    keys.extend(item[1].strip() for item in items)
assert keys == [str(n) for n in range(1, 13)] + ["0", "00"], keys
print("PASS layout: 7 rows, exactly 2 items per row, columns 4 and 31")

# Reproduce a light terminal whose bright-white palette entry renders black.
# Neither a default background reset nor SGR 97 may hide actual menu text.
foreground, background = 30, 47
offset = 0
for match in csi.finditer(output + "\x1b[0m"):
    text = output[offset:match.start()]
    if any(not c.isspace() for c in text):
        assert background == 40, (foreground, background, text)
        assert foreground in {31, 32, 33, 36}, (foreground, text)
    values, operation = match.groups()
    if operation == "m":
        for value in (values or "0").split(";"):
            code = int(value or "0")
            if code == 0:
                foreground, background = 30, 47
            elif 30 <= code <= 37 or 90 <= code <= 97:
                foreground = code
            elif 40 <= code <= 47 or code == 49:
                background = code
    elif operation == "J":
        assert background == 40, "Screen cleared with the wrong background"
    offset = match.end()
print("PASS colors: text stays visible with a black bright-white palette entry")
print(plain)
