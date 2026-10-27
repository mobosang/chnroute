#!/usr/bin/env python3
"""Check exit cleanup through a real PTY, including blank terminal cells."""
from pathlib import Path
import errno
import os
import re
import subprocess

root = Path(__file__).resolve().parents[1]
master, slave = os.openpty()
command = r'''
source <(sed '$d' "$1")
printf '\033[40m\033[2J\033[Hmenu\033[3;1H'
cleanup_ui
printf 'shell$ '
'''
try:
    subprocess.run(
        ["bash", "-c", command, "exit-test", str(root / "snell-ai.sh")],
        stdout=slave, check=True,
    )
finally:
    os.close(slave)
chunks = []
try:
    while True:
        try:
            chunk = os.read(master, 4096)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        chunks.append(chunk)
finally:
    os.close(master)
output = b"".join(chunks).decode()

width, height = 40, 8
backgrounds = ["default"] * (width * height)
characters = [" "] * (width * height)
row, column, background = 0, 0, "default"
for token in re.findall(r"\x1b\[[0-9;]*[A-Za-z]|[^\x1b]", output):
    if token.startswith("\x1b["):
        values, operation = token[2:-1], token[-1]
        if operation == "m":
            for value in (values or "0").split(";"):
                if value in {"0", "49"}:
                    background = "default"
                elif value == "40":
                    background = "black"
        elif operation == "H":
            position = [int(v or "1") for v in (values or "1;1").split(";")]
            row, column = position[0] - 1, position[1] - 1
        elif operation == "J":
            start = 0 if values == "2" else row * width + column
            backgrounds[start:] = [background] * (len(backgrounds) - start)
            characters[start:] = [" "] * (len(characters) - start)
    elif token == "\r":
        column = 0
    elif token == "\n":
        row += 1
    else:
        index = row * width + column
        backgrounds[index] = background
        characters[index] = token
        column += 1
assert "".join(characters[:4]) == "menu", "Previous output was cleared"
assert all(b == "black" for b in backgrounds[:2 * width]), "Earlier rows changed"
assert "".join(characters[2 * width:2 * width + 7]) == "shell$ "
assert all(b == "default" for b in backgrounds[2 * width:]), "Black blank cells remain"
print("PASS exit: earlier rows preserved; prompt row and all following cells use default background")
