from __future__ import annotations

from pathlib import Path


class PEScanner:
    name = "pe"

    def scan(self, path: Path) -> tuple[int, list[str], dict]:
        if not self._looks_like_pe(path):
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
            imported_functions = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                imports.append(entry.dll.decode(errors="replace"))
                for symbol in entry.imports:
                    if symbol.name:
                        imported_functions.append(symbol.name.decode(errors="replace"))
            imported_names = {name.lower() for name in imported_functions}
            injection_apis = {
                "virtualallocex",
                "writeprocessmemory",
                "createremotethread",
                "ntwritevirtualmemory",
                "ntcreatethreadex",
            }
            injection_matches = imported_names & injection_apis
            if len(injection_matches) >= 2:
                score += 35
                reasons.append(
                    "PE imports multiple process-injection APIs: "
                    + ", ".join(sorted(injection_matches))
                )
            encryption_apis = {
                "cryptacquirecontexta",
                "cryptacquirecontextw",
                "cryptderivekey",
                "cryptencrypt",
                "bcryptencrypt",
            }
            encryption_matches = imported_names & encryption_apis
            if len(encryption_matches) >= 2:
                score += 20
                reasons.append(
                    "PE imports several file-encryption-related APIs: "
                    + ", ".join(sorted(encryption_matches))
                )
            anti_debug_apis = {
                "checkremotedebuggerpresent",
                "isdebuggerpresent",
                "ntqueryinformationprocess",
            }
            anti_debug_matches = imported_names & anti_debug_apis
            if anti_debug_matches:
                score += 10
                reasons.append(
                    "PE imports anti-debugging APIs: "
                    + ", ".join(sorted(anti_debug_matches))
                )
            details = {
                "architecture": {
                    0x14C: "x86",
                    0x8664: "x64",
                    0xAA64: "ARM64",
                }.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "sections": sections,
                "imports": imports[:100],
                "imported_functions": imported_functions[:200],
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

    @staticmethod
    def _looks_like_pe(path: Path) -> bool:
        if path.suffix.lower() in {".exe", ".dll", ".sys", ".scr", ".cpl"}:
            return True
        try:
            with path.open("rb") as handle:
                return handle.read(2) == b"MZ"
        except OSError:
            return False
