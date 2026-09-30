from __future__ import annotations

from pathlib import Path


class PEScanner:
    name = "pe"

    def scan(self, path: Path) -> tuple[int, list[str], dict]:
        if path.suffix.lower() not in {".exe", ".dll", ".sys", ".scr"}:
            return 0, [], {}
        try:
            import pefile  # optional runtime dependency

            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            score, reasons = 0, []
            sections = []
            for section in pe.sections:
                entropy = section.get_entropy()
                name = section.Name.rstrip(b"\0").decode(errors="replace")
                sections.append({"name": name, "entropy": round(entropy, 2)})
                if entropy >= 7.3:
                    score += 25
                    reasons.append(
                        f"PE section {name} has high entropy ({entropy:.2f})"
                    )
                if (
                    section.Characteristics & 0x20000000
                    and section.Characteristics & 0x80000000
                ):
                    score += 20
                    reasons.append(f"PE section {name} is writable and executable")
            imports = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                imports.append(entry.dll.decode(errors="replace"))
            details = {
                "architecture": "64-bit"
                if pe.FILE_HEADER.Machine == 0x8664
                else "32-bit",
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "sections": sections,
                "imports": imports[:100],
            }
            pe.close()
            return score, reasons, details
        except ImportError:
            return 0, [], {"provider": "unavailable"}
        except (OSError, ValueError, pefile.PEFormatError) as exc:
            return (
                0,
                [f"PE analysis could not parse file: {exc.__class__.__name__}"],
                {},
            )
