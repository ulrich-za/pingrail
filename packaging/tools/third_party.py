#!/usr/bin/env python3
"""Write THIRD-PARTY-NOTICES.txt: every crate linked into pingrail on its
release targets, the licence pingrail uses it under, and that licence's text
with the crate's copyright lines. Run from the project root:

    python3 packaging/tools/third_party.py > THIRD-PARTY-NOTICES.txt
"""
import json, os, re, subprocess, sys

TARGETS = ["x86_64-pc-windows-gnu", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
# Preferred licence when a crate offers a choice.
PREFER = ["MIT", "BSD-2-Clause", "BSD-3-Clause", "Zlib", "BSL-1.0", "0BSD", "Unlicense", "ISC", "MPL-2.0", "Unicode-3.0", "Apache-2.0"]
FILES = {
    "MIT": ["LICENSE-MIT", "LICENSE-MIT.md", "LICENSE-MIT.txt", "license-mit", "LICENSE.MIT", "MIT-LICENSE", "LICENSE", "LICENSE.md", "LICENSE.txt"],
    "BSD-2-Clause": ["LICENSE-BSD", "LICENSE", "LICENSE.md", "LICENSE.txt"],
    "BSD-3-Clause": ["LICENSE-BSD", "LICENSE-BSD-3-Clause", "LICENSE", "LICENSE.md", "LICENSE.txt"],
    "Zlib": ["LICENSE-ZLIB", "LICENSE-ZLIB.md", "LICENSE-Zlib", "LICENSE", "LICENSE.md", "LICENSE.txt"],
    "BSL-1.0": ["LICENSE-BOOST", "LICENSE-BSL", "LICENSE"],
    "MPL-2.0": ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE-MPL"],
    "Unicode-3.0": ["LICENSE-UNICODE", "LICENSE", "LICENSE.txt"],
    "Unlicense": ["UNLICENSE", "LICENSE-UNLICENSE"],
    "0BSD": ["LICENSE-0BSD", "LICENSE-0BSD.md"],
    "ISC": ["LICENSE-ISC", "LICENSE", "LICENSE.md", "LICENSE.txt"],
    "Apache-2.0": ["LICENSE-APACHE", "LICENSE-Apache", "LICENSE-APACHE.md", "LICENSE", "LICENSE.md", "LICENSE.txt"],
}
GENERIC_MIT = """Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."""


def linked():
    names = set()
    for t in TARGETS:
        out = subprocess.run(["cargo", "tree", "-e", "normal", "--target", t, "--prefix", "none", "--format", "{p}"],
                             capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            m = re.match(r"(\S+) v(\S+)", line)
            if m:
                names.add((m.group(1), m.group(2)))
    return names


def choose(expr):
    """Licences to comply with for an SPDX expression (AND parts each need one)."""
    expr = expr.replace("/", " OR ")
    parts = [p.strip(" ()") for p in re.split(r"\bAND\b", expr)]
    chosen = []
    for p in parts:
        opts = [o.strip(" ()") for o in re.split(r"\bOR\b", p)]
        opts = [o.split(" WITH ")[0].strip() for o in opts]
        pick = next((x for x in PREFER if x in opts), opts[0])
        chosen.append(pick)
    return chosen


def find_text(pkg_dir, lic):
    for f in FILES.get(lic, ["LICENSE"]):
        p = os.path.join(pkg_dir, f)
        if os.path.isfile(p):
            text = open(p, encoding="utf-8", errors="replace").read()
            # A plain LICENSE file in a dual-licensed crate might be Apache:
            if lic != "Apache-2.0" and "Apache License" in text[:400] and "Version 2.0" in text[:600]:
                continue
            return text.strip()
    return None


def main():
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"],
                                     capture_output=True, text=True, check=True).stdout)
    want = linked()
    pkgs = [p for p in meta["packages"] if (p["name"], p["version"]) in want and p["name"] != "pingrail"]
    pkgs.sort(key=lambda p: (p["name"], p["version"]))
    groups = {}  # licence text -> list of (name, version, licence)
    index = []
    for p in pkgs:
        d = os.path.dirname(p["manifest_path"])
        expr = p.get("license") or "see crate"
        for lic in choose(expr):
            text = find_text(d, lic)
            if text is None and lic == "MIT":
                authors = ", ".join(p.get("authors") or [f"the {p['name']} authors"])
                text = f"Copyright (c) {authors}\n\n{GENERIC_MIT}"
            if text is None:
                text = f"(Licence text: {lic}. See https://spdx.org/licenses/{lic}.html)"
            groups.setdefault(text, []).append(f"{p['name']} {p['version']}")
        index.append(f"  {p['name']} {p['version']}  —  {expr}  (used under {' AND '.join(choose(expr))})"
                     + (f"\n      {p['repository']}" if p.get("repository") else ""))

    # OpenSSL itself, built from the source openssl-src carries.
    # (openssl-src is a build dependency, so it isn't in the linked list.)
    openssl = None
    for p in meta["packages"] if any(q["name"] == "openssl-sys" for q in pkgs) else []:
        if p["name"] == "openssl-src":
            d = os.path.join(os.path.dirname(p["manifest_path"]), "openssl")
            ver = p["version"].split("+")[-1]
            openssl = (ver, open(os.path.join(d, "LICENSE.txt"), encoding="utf-8").read().strip())
    w = sys.stdout.write
    w("pingrail — third-party notices\n")
    w("=" * 72 + "\n\n")
    w("pingrail is licensed under the Apache License, Version 2.0 (see LICENSE).\n"
      "It is built from the open-source components listed below, each used under\n"
      "its own licence; where a component offers a choice, the licence named in\n"
      "brackets is the one pingrail uses.\n\n")
    w("Also included\n-------------\n")
    w("  The Rust standard library — MIT OR Apache-2.0 (used under MIT).\n"
      "      https://github.com/rust-lang/rust\n")
    w("  Windows builds: the mingw-w64 runtime (CRT start-up code and winpthreads,\n"
      "      MIT/ZPL/public domain) and libgcc (GPL-3.0 with the GCC Runtime Library\n"
      "      Exception). https://www.mingw-w64.org/\n")
    w("  Linux builds link the system C library (glibc, LGPL-2.1) dynamically.\n")
    w("  SQLite (bundled through rusqlite) — public domain. https://sqlite.org/copyright.html\n")
    if openssl:
        w(f"  OpenSSL {openssl[0]}, compiled in through openssl-src for passkeys (WebAuthn):\n"
          "      Apache-2.0, text below. https://www.openssl.org/\n")
    w("  Mona Sans and Martian Mono, the web UI's fonts, are built into the program\n"
      "      (the Latin files exactly as Google Fonts publishes them, unmodified):\n"
      "      SIL Open Font License 1.1, texts below.\n"
      "      https://github.com/github/mona-sans  https://github.com/evilmartians/mono\n")
    w("  DejaVu fonts, used for reports, ship as separate files (fonts/), not part of\n"
      "      the program: Bitstream Vera / DejaVu licence, see fonts/LICENSE-DejaVu.txt.\n\n")
    w("Components\n----------\n")
    w("\n".join(index) + "\n\n")
    w("Licence texts\n-------------\n\n")
    for text, users in sorted(groups.items(), key=lambda kv: kv[1][0]):
        w("-" * 72 + "\n")
        w("Applies to: " + ", ".join(sorted(set(users))) + "\n\n")
        w(text + "\n\n")
    # Rust std
    w("-" * 72 + "\nApplies to: the Rust standard library\n\n"
      "Copyright (c) The Rust Project Contributors\n\n" + GENERIC_MIT + "\n")
    if openssl:
        w("\n" + "-" * 72 + f"\nApplies to: OpenSSL {openssl[0]}\n\n" + openssl[1] + "\n")
    # Web fonts built into the program
    for name, f in [("Mona Sans (web UI font)", "assets/fonts/web/LICENSE-MonaSans.txt"),
                    ("Martian Mono (web UI font)", "assets/fonts/web/LICENSE-MartianMono.txt")]:
        w("\n" + "-" * 72 + f"\nApplies to: {name}\n\n" + open(f, encoding="utf-8").read().strip() + "\n")


if __name__ == "__main__":
    main()
