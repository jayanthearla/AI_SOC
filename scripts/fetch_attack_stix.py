"""Download the MITRE ATT&CK Enterprise STIX bundle and build the slim knowledge base used by Step 5.

    python scripts/fetch_attack_stix.py            # downloads ~54 MB, writes data/intel/attack_slim.json (~1-2 MB)

The full bundle is kept in data/intel/enterprise-attack.json (git-ignored).  Record the download date in the paper.
"""
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ai_soc.intel import mitre  # noqa: E402

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
dst = ROOT / "data" / "intel" / "enterprise-attack.json"
dst.parent.mkdir(parents=True, exist_ok=True)
if not dst.exists() or "--force" in sys.argv:
    print("downloading", URL)
    urllib.request.urlretrieve(URL, dst)
out = mitre.build_slim(dst, dst.with_name("attack_slim.json"))
print("wrote", out)
