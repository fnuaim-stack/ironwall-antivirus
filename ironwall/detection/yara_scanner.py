from __future__ import annotations

from pathlib import Path
from ironwall.utils.paths import rules_dir


class YaraScanner:
    name = "yara"
    def __init__(self, rule_directory: Path | None = None) -> None:
        self.rule_directory = rule_directory or rules_dir() / "yara"
        self.available = False
        try:
            import yara
            files = {p.stem: str(p) for p in self.rule_directory.glob("*.yar")}
            self.rules = yara.compile(filepaths=files) if files else None
            self.available = True
        except (ImportError, Exception):
            self.rules = None

    def scan(self, path: Path) -> list[dict]:
        if not self.rules:
            return []
        return [{"rule": match.rule, "tags": match.tags, "meta": dict(match.meta)} for match in self.rules.match(str(path))]
