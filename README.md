# flux-coverage

> Bytecode coverage analyzer measuring instruction, branch, path, and register coverage for FLUX programs.

## What This Is

`flux-coverage` is a Python module that **measures how much of a FLUX bytecode program was actually executed** — it tracks which instruction addresses were hit, which branches were taken/not-taken, how many unique execution paths occurred, and which registers were used.

## Role in the FLUX Ecosystem

Coverage ensures comprehensive testing of agent programs:

- **`flux-timeline`** shows execution order; coverage shows breadth
- **`flux-profiler`** measures frequency; coverage measures completeness
- **`flux-debugger`** helps find bugs; coverage finds untested code
- **`flux-signatures`** detects patterns; coverage verifies they're all exercised
- **`flux-decompiler`** shows all instructions; coverage shows which ran

## Key Features

| Feature | Description |
|---------|-------------|
| **Instruction Coverage** | Percentage of instructions that were executed |
| **Branch Coverage** | Both-way coverage (taken AND not-taken) for conditional branches |
| **Path Tracking** | Count of unique execution paths through the program |
| **Register Coverage** | Which registers were read/written during execution |
| **Markdown Reports** | Formatted coverage report table |
| **Multiple Run Support** | Create fresh collector per test input for differential coverage |
| **Factorial Validation** | Known-answer tests (e.g., 6! = 720) verify both correctness and coverage |

## Quick Start

```python
from flux_coverage import CoverageCollector

# Analyze coverage of a factorial program
bytecode = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, -6, 0, 0x00]
collector = CoverageCollector(bytecode)

regs, report = collector.run()

print(f"Instruction coverage: {report.instruction_pct:.1f}%")
print(f"Branch coverage: {report.branch_pct:.1f}%")
print(f"Register coverage: {report.register_pct:.1f}%")
print(f"Unique paths: {report.unique_paths}")

# Generate report
print(report.to_markdown())

# Test with different inputs for differential coverage
collector2 = CoverageCollector(bytecode)
_, report2 = collector2.run(initial_regs={0: 1})  # n=1 instead of n=6
```

## Running Tests

```bash
python -m pytest tests/ -v
# or
python coverage.py
```

## Related Fleet Repos

- [`flux-timeline`](https://github.com/SuperInstance/flux-timeline) — Execution tracing
- [`flux-profiler`](https://github.com/SuperInstance/flux-profiler) — Performance profiling
- [`flux-debugger`](https://github.com/SuperInstance/flux-debugger) — Step debugger
- [`flux-signatures`](https://github.com/SuperInstance/flux-signatures) — Pattern detection
- [`flux-decompiler`](https://github.com/SuperInstance/flux-decompiler) — Bytecode decompilation

## License

Part of the [SuperInstance](https://github.com/SuperInstance) FLUX fleet.
