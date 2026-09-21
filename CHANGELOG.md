# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-20

First release.

### Added

- PE32 and PE32+ support: COFF and optional headers, recomputed checksum,
  section table with long names, data directories, imports (by name and
  ordinal), delay-load imports, exports with forwarders and `[NONAME]`
  entries, CodeView/PDB records, TLS callbacks, .NET header, Authenticode
  presence, and a mitigation summary (ASLR, DEP, CFG, CET, SafeSEH).
- ELF32 and ELF64 support in both byte orders: header with extended section
  numbering, program headers, section headers, dynamic section, notes and GNU
  build id, symbol tables with GNU symbol versions, an imports view grouped by
  needed library, an exports view, and a mitigation summary (PIE, NX stack,
  RELRO, stack canary, FORTIFY_SOURCE, CET/IBT, BTI/PAC).
- A bounds-checking layer that every read passes through, with an opaque image
  type, poisoned slices on failure, bounded string reads, counts clamped to
  what the file can hold, and a per-file work budget.
- `--flat` output (one tab-separated record per line) and `--batch` mode for
  sweeping directories.
- Unit tests with in-memory fixtures, hostile-header cases, and brute-force
  truncation and mutation sweeps.
- A libFuzzer target and a standalone mutation fuzzer.
- Differential tests against `dumpbin` and `llvm-readelf`.

[0.1.0]: https://github.com/ElatDev/loupe/releases/tag/v0.1.0
