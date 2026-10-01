import sys

from ironwall.ui.main_window import run, smoke_test
from ironwall.utils.logging import configure_logging

if __name__ == "__main__":
    if "--smoke-test" in sys.argv:
        raise SystemExit(smoke_test())
    configure_logging()
    raise SystemExit(run())
