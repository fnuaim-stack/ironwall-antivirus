from __future__ import annotations

import threading
from pathlib import Path

from ironwall.utils.paths import rules_dir, user_rules_dir


class YaraScanner:
    name = "yara"

    def __init__(
        self,
        rule_directory: Path | None = None,
        user_rule_directory: Path | None = None,
    ) -> None:
        self.rule_directory = rule_directory or rules_dir() / "yara"
        self.user_rule_directory = user_rule_directory or user_rules_dir() / "yara"
        self.available = False
        self.errors: list[str] = []
        self._lock = threading.RLock()
        self._revision: tuple | None = None
        self.rules: dict[Path, object] = {}
        try:
            import yara

            self._yara = yara
            self.available = True
            self.refresh()
        except ImportError:
            self._yara = None

    def revision(self) -> tuple:
        files = sorted(
            (
                *self.rule_directory.rglob("*.yar"),
                *self.rule_directory.rglob("*.yara"),
                *self.user_rule_directory.rglob("*.yar"),
                *self.user_rule_directory.rglob("*.yara"),
            ),
            key=str,
        )
        result = []
        for path in files:
            try:
                stat = path.stat()
                result.append((str(path), stat.st_mtime_ns, stat.st_size))
            except OSError:
                result.append((str(path), -1, -1))
        return tuple(result)

    def refresh(self) -> None:
        if not self.available:
            return
        with self._lock:
            revision = self.revision()
            if revision == self._revision:
                return
            compiled = {}
            errors = []
            for filename, _, _ in revision:
                path = Path(filename)
                try:
                    compiled[path] = self._yara.compile(filepath=str(path))
                except (OSError, self._yara.Error) as exc:
                    errors.append(f"{path.name}: {exc}")
            self.rules, self.errors, self._revision = compiled, errors, revision

    def scan(self, path: Path) -> list[dict]:
        if not self.available:
            return []
        self.refresh()
        results = []
        with self._lock:
            rules = list(self.rules.items())
        for rule_path, compiled in rules:
            for match in compiled.match(str(path), timeout=10):
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
                        "rule_file": rule_path.name,
                        "tags": list(match.tags),
                        "meta": dict(match.meta),
                        "strings": strings,
                    }
                )
        return results
