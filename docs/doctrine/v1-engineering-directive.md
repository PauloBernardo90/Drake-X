# Drake-X v1.0 Engineering Directive

Evidence-Driven Malware Analysis with Bounded Exploit-Awareness

- Date: 2026-04-11
- Scope: Drake-X v0.7 -> v1.0 evolution
- Classification: Internal engineering doctrine

## 1. Core Mission

Drake-X is an evidence-driven malware analysis and threat investigation
platform.

Its purpose is to transform raw artifacts such as APK, PE, and ELF into
structured, traceable, and reproducible evidence so analysts can
understand:

- what the sample does
- how it executes, persists, injects, evades, or delivers payloads
- whether it contains embedded payloads or exploitation-related
  capability
- how it interacts with protections such as DEP, ASLR, CFG, SafeSEH, or
  platform-equivalent mitigations
- what requires dynamic validation

Drake-X is not an exploit-development platform.

## 2. Hard Doctrinal Boundary

The following rule is mandatory:

> Drake-X may detect, classify, contextualize, and correlate
> exploit-related evidence in malware samples.
>
> Drake-X does not generate exploit chains, optimize payloads, produce
> weaponized shellcode, or provide operational bypass instructions.
>
> Any deeper exploit validation remains analyst-driven and tool-external,
> with Drake-X limited to evidence ingestion, traceability, and
> analytical support.

Drake-X must not:

- generate exploit chains
- reconstruct operational ROP chains
- optimize payloads for execution
- produce weaponized shellcode
- provide actionable bypass instructions
- act as a debugger replacement
- execute, validate, or optimize exploit behavior autonomously

All exploit-related findings must be framed as:

- capability indicators
- behavioral signals
- analytical hypotheses

Never as operational procedures.

## 3. Product Positioning

Correct positioning:

- malware capability assessment platform
- evidence-centric analysis system
- exploit-aware, not exploit-operational

Incorrect positioning:

- exploit framework
- vulnerability research platform
- offensive tooling system

## 4. Terminology Normalization

Use the following language as the default vocabulary:

- exploit-awareness
- protection-interaction assessment
- potential ROP structure detection
- suspected shellcode extraction and behavioral triage
- exploit-related indicator detection
- dynamic evidence ingestion adapters
- bounded memory-relevant structural abstraction

Avoid terms that imply exploit construction, bypass execution, or
debugger replacement.

## 5. Evidence Model Policy

### 5.1 Canonical Graph

Only high-value analytical entities belong in the canonical graph:

- sample
- apk / pe_file / elf_file
- pe_section
- pe_import / pe_export
- pe_anomaly
- function
- protection_status
- suspicious_pattern
- exploit_indicator
- suspected_shellcode
- behavior
- capability
- technique
- report
- tool_output
- analyst_annotation

### 5.2 Non-Canonical Artifacts

The following must not be stored as first-class graph nodes by default:

- instruction
- basic_block
- call_graph
- memory_region
- stack_frame
- raw gadget listings

These belong in:

- structured JSON attachments
- bounded analysis artifacts
- on-demand inspection outputs

### 5.3 Boundedness Rule

The graph stores reasoning-relevant evidence.

Artifacts store deep inspection data.

Any instruction-level, gadget-level, shellcode-level, or decompiler-rich
detail must remain bounded, queryable on demand, and off the canonical
graph by default.

## 6. Architecture Principles

- modular pipeline with independent stages
- structured outputs from every integration
- subprocess-based external tooling with explicit timeouts
- no unsafe in-process execution of untrusted binaries
- bounded analysis at every stage
- fail-open stage behavior, not global failure cascades

## 7. Supported Analysis Domains

- Android APK
- Windows PE as a first-class native domain
- ELF with incremental native support

Each domain must:

- emit structured evidence
- follow the same evidence model
- integrate into the same reporting layer

## 8. Required Capabilities by Phase

### 8.1 v0.8 Native Foundations

Implement:

- PE parsing for headers, sections, imports, exports, and resources
- section entropy and anomaly detection
- bounded disassembly at function scope
- Windows API risk pattern detection
- PE report writer
- format detection and routing
- evidence-model extensions for native artifacts

Do not implement as foundational requirements:

- broad memory models
- debugger integration as a primary workflow
- ROP reconstruction

### 8.2 v0.9 Exploit-Awareness Layer

Implement:

- exploit-related indicator heuristics:
  - stack corruption patterns
  - suspicious control-flow constructs
  - injection API chains
- suspected shellcode carving
- bounded decoding for classification and evidence extraction, not for
  operational reuse
- protection status parsing:
  - DEP
  - ASLR
  - CFG
  - SafeSEH
- ATT&CK mapping for exploitation-related techniques
- AI-assisted exploit-aware assessment with strict evidence citation

All outputs at this layer must be labeled with conservative language
such as:

- suspected
- potential
- requires validation

### 8.3 v1.0 Evidence-Driven Malware Analysis at Scale

Implement:

- cross-sample correlation for exploit indicators, shellcode patterns,
  and API usage clusters
- persistent, queryable evidence storage
- distributed pipeline execution through queue and workers
- dynamic evidence ingestion adapters for analyst-produced outputs from
  debuggers, sandboxes, and external analysis tools
- structured validation-plan generation for analysts
- multi-domain reporting across mobile and native workflows

## 9. AI and LLM Usage Policy

AI is a reasoning layer, not a primary detection engine.

Deterministic detection precedes AI interpretation.

AI may:

- interpret evidence
- correlate findings
- generate bounded hypotheses
- suggest validation strategies

AI must never:

- fabricate instruction-level data
- invent gadget sequences
- claim exploitability without evidence
- provide operational exploitation steps

All exploit-aware AI outputs must include:

- evidence references
- confidence score
- explicit uncertainty language such as `pending dynamic validation`

## 10. Exploit-Aware Analysis Rules

When exploitation-related signals are identified, Drake-X must:

- reference concrete evidence such as APIs, sections, protections,
  strings, or suspicious patterns
- classify findings as indicators, not confirmed exploits
- relate findings back to malware behavior such as execution, injection,
  staging, or delivery
- map to ATT&CK where applicable

Drake-X must not:

- reconstruct full exploit chains
- simulate exploit execution
- produce step-by-step attack logic

## 11. Operator Workflows

Supported workflows include:

- `drake pe analyze sample.exe`
- `drake pe inspect --function <addr>` with bounded detail
- `drake graph query ...`

Unsupported workflows include:

- exploit simulation
- interactive live-debugging UX inside Drake-X
- payload crafting

Drake-X supports analysis and reasoning, not offensive execution.

## 12. Security and Isolation

- all binary handling is non-executing unless explicitly sandboxed
- external execution must be isolated from the core analysis worker
- shellcode handling must remain bounded and non-operational
- extracted payloads must never run automatically

## 13. Output Requirements

All outputs must be:

- evidence-backed
- reproducible
- structured
- traceable to source artifacts

Expected report sections include:

- Surface Analysis
- Behavioral Analysis
- Protection Analysis
- Exploit-Related Capability Assessment
- Indicators and Findings
- Validation Recommendations

## 14. Final Principle

Drake-X is an intelligence system.

It explains what malware appears capable of.

It does not enable how to weaponize or operationalize exploitation.
