# Local detection rules

IronWall ships a small, reviewable local rule set:

- `hashes.json` contains the standard EICAR test hash and published SHA-256 indicators for well-known WannaCry samples.
- `yara/eicar.yar` detects the harmless EICAR marker.
- `yara/wannacry.yar` requires a PE header plus at least three WannaCry-associated strings to reduce false positives.

The source URL for every malware hash is stored with the entry. The WannaCry YARA metadata links to the public rules used to validate its indicators. Rules contain no malware bytes and scanning never executes a target.

Hash rules reload when `hashes.json` changes. YARA is an optional provider; packaged Windows builds include `yara-python`, while source installations continue to work without it.
