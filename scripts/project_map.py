"""Run the shared project map engine for this repository."""

import os
import runpy
import sys
from pathlib import Path


def main():
    """Pass map arguments to the shared engine; stop if it is not installed."""
    root = Path(__file__).resolve().parents[1]
    override = os.environ.get("PROJECT_MAP_ENGINE")
    engine = (
        Path(override).expanduser()
        if override
        else Path.home() / ".claude/tools/project-map/project_map.py"
    )
    if not engine.is_file():
        raise SystemExit(
            f"Project map engine missing: {engine}. Install the shared engine or set PROJECT_MAP_ENGINE to its project_map.py file."
        )
    sys.argv = [str(engine), "--root", str(root), *sys.argv[1:]]
    sys.path.insert(0, str(engine.resolve().parent))
    runpy.run_path(str(engine), run_name="__main__")


if __name__ == "__main__":
    main()
