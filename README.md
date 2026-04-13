# flux-coverage

FLUX coverage analyzer — comprehensive bytecode coverage analysis for FLUX VM programs.

## Features

- **Opcode coverage** — tracks which of 247 FLUX opcodes are exercised, with hit counts and first-hit PCs
- **Instruction coverage** — PC-level hit tracking showing what percentage of instructions were reached
- **Branch coverage** — per-branch-point tracking for conditional opcodes (BEQ, BNE, BLT, BGE) with taken/not-taken counts
- **Register coverage** — tracks which registers are read and written, with read vs. written distinction
- **Path coverage** — unique execution path identification via SHA-256 hashing
- **Multiple report formats** — Terminal, Markdown, JSON, and HTML with styled progress bars
- **Coverage diffing** — compare two coverage runs to see what improved/regressed
- **Overall score** — weighted composite score across all metrics
- **Pytest integration** — `FluxCoveragePlugin` for collecting and aggregating coverage across test sessions

## Usage

```python
from coverage import CoverageCollector, collect_coverage, diff_reports, ReportFormat

# Basic usage
c = CoverageCollector([0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00])
regs, report = c.run()
print(report.to_terminal())
print(report.to_html())   # Styled HTML report
print(report.to_json())   # Machine-readable JSON
print(report.to_markdown())  # Markdown table

# Convenience function
report = collect_coverage([0x18, 0, 42, 0x00], label="test1")

# Coverage diffing
r1 = collect_coverage([0x18, 0, 42, 0x00])
r2 = collect_coverage([0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00])
d = diff_reports(r1, r2)
print(d.to_terminal())
print(d.to_markdown())
```

## Report Metrics

| Metric | Description |
|--------|-------------|
| Instructions | PC-level hit ratio |
| Branches | Taken + not-taken for conditional jumps |
| Registers | How many of 64 registers are read/written |
| Opcodes | How many of 247 opcodes are exercised |
| Paths | Unique execution path count |
| Overall Score | Weighted composite (30% instruction, 30% branch, 30% opcode, 10% register) |

29 tests passing.
