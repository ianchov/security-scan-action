#!/usr/bin/env python3
"""Run the pinned scanners on the git repository of the current directory. See README.md."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_scan.cli import main  # noqa: E402

sys.exit(main())
