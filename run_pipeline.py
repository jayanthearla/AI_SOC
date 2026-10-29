"""Thin wrapper kept for backwards compatibility:  python run_pipeline.py [--skip-extract] ...
Equivalent to:  python -m ai_soc.orchestration.pipeline ...
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from ai_soc.orchestration.pipeline import main  # noqa: E402

if __name__ == "__main__":
    main()
