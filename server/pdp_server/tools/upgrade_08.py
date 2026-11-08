"""Upgrade an endpoint's bundle to the 0.8 detection (detector-3 breadth evidence) without retraining detectors 1-2.

  python -m pdp_server.tools.upgrade_08 --endpoint <id> [--bundle <id>] [--deploy] [--device cuda|cpu]

The same tool as pdp_server.tools.upgrade_07 (which always upgrades to the current detection); see its docstring.
"""
from pdp_server.tools.upgrade_07 import main, train_config, upgrade  # noqa: F401

if __name__ == "__main__":
    main()
