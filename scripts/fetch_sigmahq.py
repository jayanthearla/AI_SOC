"""Download the public SigmaHQ rule set (Windows rules only) into baselines/sigmahq/rules for experiment E3.

    python scripts/fetch_sigmahq.py [--ref master]

Pin a commit/tag with --ref for reproducibility and record it in the paper (rule sets change daily).
"""
import argparse
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--ref", default="master", help="branch, tag or commit of SigmaHQ/sigma")
a = ap.parse_args()
url = f"https://codeload.github.com/SigmaHQ/sigma/zip/{a.ref}" if len(a.ref) >= 40 else f"https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/{a.ref}"
print("downloading", url)
data = urllib.request.urlopen(url, timeout=180).read()
dest = ROOT / "baselines" / "sigmahq" / "rules"
dest.mkdir(parents=True, exist_ok=True)
n = 0
with zipfile.ZipFile(io.BytesIO(data)) as z:
    for name in z.namelist():
        parts = name.split("/", 1)[1] if "/" in name else name
        if parts.startswith("rules/windows/") and name.endswith(".yml"):
            out = dest / parts[len("rules/windows/"):]
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(z.read(name))
            n += 1
(ROOT / "baselines" / "sigmahq" / "SOURCE.txt").write_text(f"SigmaHQ/sigma ref={a.ref}\nurl={url}\n")
print(f"extracted {n} Windows rules -> {dest}")
sys.exit(0 if n else 1)
