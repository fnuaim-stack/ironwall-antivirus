from __future__ import annotations

from pathlib import Path


class HeuristicScanner:
    name = "heuristic"
    EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
    DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}

    def scan(self, path: Path) -> tuple[int, list[str]]:
        score, reasons = 0, []
        suffixes = [suffix.lower() for suffix in path.suffixes]
        if len(suffixes) >= 2 and suffixes[-1] in self.EXECUTABLE_EXTENSIONS and suffixes[-2] in self.DECOY_EXTENSIONS:
            score += 45; reasons.append(f"Executable has a misleading double extension: {path.name}")
        lower_path = str(path).lower()
        if path.suffix.lower() in self.EXECUTABLE_EXTENSIONS and any(token in lower_path for token in ("\\temp\\", "\\appdata\\local\\temp\\")):
            score += 25; reasons.append("Executable is located in a temporary directory")
        suspicious_names = ("invoice", "payment", "crack", "keygen", "password", "update")
        if path.suffix.lower() in self.EXECUTABLE_EXTENSIONS and any(token in path.stem.lower() for token in suspicious_names):
            score += 10; reasons.append("Executable name contains a commonly abused lure term")
        if path.suffix.lower() in {".ps1", ".vbs", ".js", ".bat", ".cmd"} and "startup" in lower_path:
            score += 35; reasons.append("Script is located in a startup-related directory")
        return score, reasons
