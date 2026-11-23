import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"

USE_COLOR = sys.stdout.isatty()


def _c(code, text):
    return f"{code}{text}{RESET}" if USE_COLOR else text


def title(num, text):
    line = "=" * 70
    print()
    print(_c(BOLD + CYAN, line))
    print(_c(BOLD + CYAN, f"  {num}. {text}"))
    print(_c(BOLD + CYAN, line))


def step(text):
    print()
    print(_c(BOLD, f"--- {text} ---"))


def show(label, value):
    print(f"  {label:<28} {value}")


def ok(text):
    print(f"  {_c(GREEN, '[OK]')} {text}")


def warn(text):
    print(f"  {_c(YELLOW, '[!]')} {text}")


def fail(text):
    print(f"  {_c(RED, '[FAIL]')} {text}")


def note(text):
    print(_c(DIM, f"  {text}"))


def hexs(data):
    return data.hex()


def short(data, n=24):
    h = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
    return h if len(h) <= n * 2 else f"{h[:n * 2]}...{h[-8:]}"


def human(nbytes):
    units = ["B", "KB", "MB", "GB"]
    size = float(nbytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{nbytes} B"


OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
os.makedirs(OUTPUT, exist_ok=True)


def outpath(name):
    return os.path.join(OUTPUT, name)
