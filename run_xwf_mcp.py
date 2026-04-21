from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    project_root = Path(__file__).resolve().parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from xwf_mcp.server import main as server_main

    server_main()


if __name__ == "__main__":
    main()

