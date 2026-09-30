from ironwall.ui.main_window import run
from ironwall.utils.logging import configure_logging

if __name__ == "__main__":
    configure_logging()
    raise SystemExit(run())
