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
        except ImportError:
            self.rules = None
            return
        try:
            files = {p.stem: str(p) for p in self.rule_directory.glob("*.yar")}
            self.rules = yara.compile(filepaths=files) if files else None
            self.available = True
        except (OSError, yara.Error):
            self.rules = None

    def scan(self, path: Path) -> list[dict]:
        if not self.rules:
            return []
        results = []
        for match in self.rules.match(str(path)):
            strings = []
            for item in match.strings:
                identifier = getattr(item, "identifier", None)
                if identifier is not None:
                    strings.append(identifier)
                elif isinstance(item, tuple) and len(item) >= 2:
                    strings.append(str(item[1]))
            results.append(
                {
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": strings,
                }
            )
        return results
