# Native Analysis

Drake-X v1.0 supports native analysis in two main forms:

- deeper structured native analysis inside APK workflows via Ghidra
- first-class ELF analysis through `drake elf analyze`

## ELF Workflow

```bash
drake elf analyze ./sample.elf -w my-engagement
```

Current v1.0 ELF coverage:

- ELF header parsing
- section inventory
- imported symbol inventory
- protection profile:
  - NX
  - PIE
  - RELRO
  - stack canary
  - FORTIFY_SOURCE
- deterministic import-risk classification
- Evidence Graph output and persistence
- Markdown and JSON report output

Primary outputs:

- `elf_analysis.json`
- `elf_report.md`
- `elf_graph.json`

When a workspace is provided, the ELF session and graph are persisted to
SQLite and participate in graph query, case reporting, and correlation.

## APK Native Path

APK analysis can also use Ghidra headless to inspect native libraries
embedded in APK samples. Those results remain part of the APK evidence
surface rather than a standalone ELF session.

## Boundaries

ELF in v1.0 is intentionally narrower than PE:

- no exploit-indicator heuristics
- no shellcode carving
- no protection-interaction assessment

Drake-X does not claim PE parity for ELF in this release.
