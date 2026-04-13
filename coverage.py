"""
FLUX Coverage — comprehensive bytecode coverage analysis for FLUX VM programs.

Tracks:
- Opcode coverage (which of 247 opcodes are exercised)
- Branch coverage for conditional opcodes
- Register usage coverage (which registers are read/written)
- Path coverage (unique execution paths)
- Instruction coverage (PC-level hit tracking)

Report formats: terminal, JSON, HTML, Markdown, and coverage diffing.
Pytest integration via conftest plugin hooks.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Any
from enum import Enum
import json
import hashlib
import os
import time

# ═══════════════════════════════════════════════════════════════════
# FLUX Opcode Definitions (247 opcodes total)
# ═══════════════════════════════════════════════════════════════════

OPCODE_NAMES: Dict[int, str] = {
    0x00: "HALT",
    0x01: "NOP",
    # R-type (1-byte): 0x02..0x07
    0x02: "RET",
    0x03: "CALLR",
    0x04: "PUSHR",
    0x05: "POPR",
    0x06: "SWAPR",
    0x07: "XCHGR",
    # I-type (2-byte): 0x08..0x17
    0x08: "INCR", 0x09: "DECR", 0x0A: "SHL1", 0x0B: "SHR1",
    0x0C: "PUSH", 0x0D: "POP", 0x0E: "NOT", 0x0F: "NEG",
    0x10: "INC", 0x11: "DEC", 0x12: "DUP", 0x13: "OVER",
    0x14: "ROT", 0x15: "FLIP", 0x16: "TRAP", 0x17: "SYSCALL",
    # SI-type (3-byte): 0x18..0x1F
    0x18: "MOVI", 0x19: "MOVIs", 0x1A: "CMPI", 0x1B: "LOAD",
    0x1C: "STORE", 0x1D: "JMP", 0x1E: "CALL", 0x1F: "RETI",
    # RRR-type (4-byte): 0x20..0x3F
    0x20: "ADD", 0x21: "SUB", 0x22: "MUL", 0x23: "DIV",
    0x24: "MOD", 0x25: "AND", 0x26: "OR", 0x27: "XOR",
    0x28: "SHL", 0x29: "SHR", 0x2A: "SAR", 0x2B: "EQ",
    0x2C: "SEQ", 0x2D: "SLT", 0x2E: "SLE", 0x2F: "SGT",
    0x30: "SGE", 0x31: "SNE", 0x32: "MOV", 0x33: "LOADW",
    0x34: "STOREW", 0x35: "ADDC", 0x36: "SUBC", 0x37: "MULH",
    0x38: "UMULH", 0x39: "DIVU", 0x3A: "MOVr", 0x3B: "MOVR2",
    0x3C: "BEQ", 0x3D: "BNE", 0x3E: "BLT", 0x3F: "BGE",
}

# Conditional branch opcodes (for branch coverage)
CONDITIONAL_OPCODES = {0x3C, 0x3D, 0x3E, 0x3F}

# Total FLUX opcodes
TOTAL_OPCODES = 247

# Opcode category sizing
def _inst_size(op: int) -> int:
    """Return instruction size in bytes for an opcode."""
    if op <= 0x07: return 1  # R-type
    if op <= 0x17: return 2  # I-type
    if op <= 0x1F: return 3  # SI-type
    return 4  # RRR-type


def _count_instructions(bc) -> int:
    i, count = 0, 0
    while i < len(bc):
        i += _inst_size(bc[i])
        count += 1
    return count


def _signed_byte(b) -> int:
    return b - 256 if b > 127 else b


# ═══════════════════════════════════════════════════════════════════
# Coverage Report
# ═══════════════════════════════════════════════════════════════════

class ReportFormat(Enum):
    TERMINAL = "terminal"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


@dataclass
class OpcodeCoverageDetail:
    """Per-opcode coverage info."""
    opcode: int
    name: str
    hit_count: int
    first_hit_pc: Optional[int] = None


@dataclass
class BranchDetail:
    """Per-branch-point coverage info."""
    pc: int
    opcode: int
    name: str
    taken: bool = False
    not_taken: bool = False
    taken_count: int = 0
    not_taken_count: int = 0

    @property
    def fully_covered(self) -> bool:
        return self.taken and self.not_taken


@dataclass
class CoverageReport:
    """Comprehensive coverage report."""
    total_instructions: int
    hit_instructions: int
    total_branches: int
    branches_taken: int
    branches_not_taken: int
    unique_paths: int
    registers_used: int
    total_registers: int
    opcodes_seen: int = 0
    total_opcodes: int = TOTAL_OPCODES
    opcode_details: Dict[int, OpcodeCoverageDetail] = field(default_factory=dict)
    branch_details: List[BranchDetail] = field(default_factory=list)
    register_read: Set[int] = field(default_factory=set)
    register_written: Set[int] = field(default_factory=set)
    timestamp: float = field(default_factory=time.time)
    label: str = ""

    @property
    def instruction_pct(self) -> float:
        return (self.hit_instructions / self.total_instructions * 100) if self.total_instructions > 0 else 0

    @property
    def branch_pct(self) -> float:
        total = self.branches_taken + self.branches_not_taken
        if total == 0: return 100.0
        both = min(self.branches_taken, self.branches_not_taken)
        return (both * 2 / total * 100)

    @property
    def register_pct(self) -> float:
        return (self.registers_used / self.total_registers * 100) if self.total_registers > 0 else 0

    @property
    def opcode_pct(self) -> float:
        return (self.opcodes_seen / self.total_opcodes * 100) if self.total_opcodes > 0 else 0

    @property
    def branches_fully_covered(self) -> int:
        return sum(1 for b in self.branch_details if b.fully_covered)

    @property
    def overall_score(self) -> float:
        """Weighted overall coverage score."""
        weights = {"instruction": 0.3, "branch": 0.3, "register": 0.1, "opcode": 0.3}
        return (
            self.instruction_pct * weights["instruction"] +
            self.branch_pct * weights["branch"] +
            self.register_pct * weights["register"] +
            self.opcode_pct * weights["opcode"]
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "timestamp": self.timestamp,
            "overall_score": round(self.overall_score, 1),
            "instruction_coverage": {
                "hit": self.hit_instructions, "total": self.total_instructions,
                "percentage": round(self.instruction_pct, 1),
            },
            "branch_coverage": {
                "taken": self.branches_taken, "not_taken": self.branches_not_taken,
                "total_points": self.total_branches,
                "fully_covered": self.branches_fully_covered,
                "percentage": round(self.branch_pct, 1),
            },
            "register_coverage": {
                "used": self.registers_used, "total": self.total_registers,
                "percentage": round(self.register_pct, 1),
                "read": sorted(self.register_read),
                "written": sorted(self.register_written),
            },
            "opcode_coverage": {
                "seen": self.opcodes_seen, "total": self.total_opcodes,
                "percentage": round(self.opcode_pct, 1),
                "opcodes": {OPCODE_NAMES.get(op, f"UNK_{op:#04x}"): d.hit_count
                            for op, d in sorted(self.opcode_details.items())},
            },
            "path_coverage": {
                "unique_paths": self.unique_paths,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        lines = [f"# FLUX Coverage Report", ""]
        if self.label:
            lines.append(f"**Label:** {self.label}")
            lines.append(f"**Overall Score:** {self.overall_score:.1f}%")
            lines.append("")

        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Hit | Total | Coverage |")
        lines.append("|--------|-----|-------|----------|")
        lines.append(f"| Instructions | {self.hit_instructions} | {self.total_instructions} | {self.instruction_pct:.1f}% |")
        lines.append(f"| Branches (taken/not) | {self.branches_taken}/{self.branches_not_taken} | {self.total_branches} points | {self.branch_pct:.1f}% |")
        lines.append(f"| Registers | {self.registers_used} | {self.total_registers} | {self.register_pct:.1f}% |")
        lines.append(f"| Opcodes | {self.opcodes_seen} | {self.total_opcodes} | {self.opcode_pct:.1f}% |")
        lines.append(f"| Unique Paths | {self.unique_paths} | - | - |")
        lines.append("")

        if self.branch_details:
            lines.append("## Branch Details")
            lines.append("")
            lines.append("| PC | Opcode | Taken | Not Taken | Status |")
            lines.append("|----|--------|-------|-----------|--------|")
            for b in self.branch_details:
                status = "✅" if b.fully_covered else "⚠️"
                lines.append(f"| {b.pc} | {b.name} | {'✓' if b.taken else '✗'} ({b.taken_count}) | "
                             f"{'✓' if b.not_taken else '✗'} ({b.not_taken_count}) | {status} |")
            lines.append("")

        if self.opcode_details:
            lines.append("## Opcodes Hit")
            lines.append("")
            lines.append("| Opcode | Name | Hits | First PC |")
            lines.append("|--------|------|------|----------|")
            for op, d in sorted(self.opcode_details.items()):
                name = OPCODE_NAMES.get(op, f"UNK_{op:#04x}")
                first = str(d.first_hit_pc) if d.first_hit_pc is not None else "-"
                lines.append(f"| {op:#04x} | {name} | {d.hit_count} | {first} |")
            lines.append("")

        return "\n".join(lines)

    def to_html(self) -> str:
        score_color = "#2ecc71" if self.overall_score >= 80 else "#f39c12" if self.overall_score >= 50 else "#e74c3c"
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>FLUX Coverage Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; margin: 2em; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d2ff; border-bottom: 2px solid #00d2ff; padding-bottom: 0.5em; }}
h2 {{ color: #7f8c8d; margin-top: 1.5em; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th {{ background: #16213e; color: #00d2ff; padding: 0.6em 1em; text-align: left; border: 1px solid #2a2a4a; }}
td {{ padding: 0.5em 1em; border: 1px solid #2a2a4a; }}
.score {{ font-size: 2em; font-weight: bold; color: {score_color}; }}
.bar-bg {{ background: #2a2a4a; height: 20px; border-radius: 10px; overflow: hidden; }}
.bar-fill {{ height: 100%; border-radius: 10px; }}
.pass {{ color: #2ecc71; }} .warn {{ color: #f39c12; }} .fail {{ color: #e74c3c; }}
</style></head><body>
<h1>FLUX Coverage Report</h1>"""
        if self.label:
            html += f"<p><strong>Label:</strong> {self.label}</p>"
        html += f'<p class="score">Overall Score: {self.overall_score:.1f}%</p>'
        html += '<table><tr><th>Metric</th><th>Hit</th><th>Total</th><th>Coverage</th></tr>'
        for name, hit, total, pct in [
            ("Instructions", self.hit_instructions, self.total_instructions, self.instruction_pct),
            ("Branches", self.branches_taken + self.branches_not_taken, self.total_branches * 2, self.branch_pct),
            ("Registers", self.registers_used, self.total_registers, self.register_pct),
            ("Opcodes", self.opcodes_seen, self.total_opcodes, self.opcode_pct),
        ]:
            cls = "pass" if pct >= 80 else "warn" if pct >= 50 else "fail"
            color = "#2ecc71" if pct >= 80 else "#f39c12" if pct >= 50 else "#e74c3c"
            html += f'<tr><td>{name}</td><td>{hit}</td><td>{total}</td>'
            html += f'<td><span class="{cls}">{pct:.1f}%</span> '
            html += f'<div class="bar-bg"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div></td></tr>'
        html += '</table>'

        if self.opcode_details:
            html += '<h2>Opcodes Hit</h2><table><tr><th>Opcode</th><th>Name</th><th>Hits</th></tr>'
            for op, d in sorted(self.opcode_details.items()):
                name = OPCODE_NAMES.get(op, f"UNK_{op:#04x}")
                html += f'<tr><td>{op:#04x}</td><td>{name}</td><td>{d.hit_count}</td></tr>'
            html += '</table>'

        if self.branch_details:
            html += '<h2>Branch Details</h2><table><tr><th>PC</th><th>Opcode</th><th>Taken</th><th>Not Taken</th><th>Status</th></tr>'
            for b in self.branch_details:
                status = '<span class="pass">FULL</span>' if b.fully_covered else '<span class="warn">PARTIAL</span>'
                html += f'<tr><td>{b.pc}</td><td>{b.name}</td><td>{"✓" if b.taken else "✗"} ({b.taken_count})</td>'
                html += f'<td>{"✓" if b.not_taken else "✗"} ({b.not_taken_count})</td><td>{status}</td></tr>'
            html += '</table>'

        html += '<p style="color:#555;margin-top:2em;">Generated by flux-coverage</p></body></html>'
        return html

    def to_terminal(self) -> str:
        lines = []
        lines.append("═" * 60)
        lines.append("  FLUX COVERAGE REPORT")
        if self.label:
            lines.append(f"  Label: {self.label}")
        lines.append("═" * 60)
        lines.append(f"  Overall Score: {self.overall_score:.1f}%")
        lines.append("")
        lines.append(f"  Instructions: {self.hit_instructions}/{self.total_instructions}  ({self.instruction_pct:.1f}%)")
        lines.append(f"  Branches:     {self.branches_taken} taken, {self.branches_not_taken} not taken  ({self.branch_pct:.1f}%)")
        lines.append(f"  Registers:    {self.registers_used}/{self.total_registers}  ({self.register_pct:.1f}%)")
        lines.append(f"  Opcodes:      {self.opcodes_seen}/{self.total_opcodes}  ({self.opcode_pct:.1f}%)")
        lines.append(f"  Unique Paths: {self.unique_paths}")

        if self.opcode_details:
            lines.append("")
            lines.append("  Opcodes exercised:")
            for op, d in sorted(self.opcode_details.items()):
                name = OPCODE_NAMES.get(op, f"UNK_{op:#04x}")
                lines.append(f"    {op:#04x} {name:<10} hits={d.hit_count}")
            unseen = TOTAL_OPCODES - self.opcodes_seen
            lines.append(f"    ... and {unseen} opcodes not yet covered")

        if self.branch_details:
            lines.append("")
            lines.append("  Branch points:")
            for b in self.branch_details:
                status = "FULL" if b.fully_covered else "PARTIAL"
                lines.append(f"    PC={b.pc:4d} {b.name:<10} taken={b.taken_count} not_taken={b.not_taken_count}  [{status}]")

        lines.append("═" * 60)
        return "\n".join(lines)

    def format(self, fmt: ReportFormat = ReportFormat.TERMINAL) -> str:
        if fmt == ReportFormat.MARKDOWN:
            return self.to_markdown()
        if fmt == ReportFormat.JSON:
            return self.to_json()
        if fmt == ReportFormat.HTML:
            return self.to_html()
        return self.to_terminal()


# ═══════════════════════════════════════════════════════════════════
# Coverage Diff
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CoverageDiff:
    """Compare two coverage reports and show deltas."""
    before: CoverageReport
    after: CoverageReport

    @property
    def instruction_delta(self) -> float:
        return self.after.instruction_pct - self.before.instruction_pct

    @property
    def branch_delta(self) -> float:
        return self.after.branch_pct - self.before.branch_pct

    @property
    def opcode_delta(self) -> float:
        return self.after.opcode_pct - self.before.opcode_pct

    @property
    def register_delta(self) -> float:
        return self.after.register_pct - self.before.register_pct

    @property
    def new_opcodes(self) -> List[int]:
        return sorted(set(self.after.opcode_details) - set(self.before.opcode_details))

    @property
    def lost_opcodes(self) -> List[int]:
        return sorted(set(self.before.opcode_details) - set(self.after.opcode_details))

    @property
    def improved(self) -> bool:
        return self.after.overall_score > self.before.overall_score

    def to_markdown(self) -> str:
        def arrow(delta):
            if delta > 0: return f"+{delta:.1f}% ▲"
            if delta < 0: return f"{delta:.1f}% ▼"
            return "0.0% ─"

        lines = ["# FLUX Coverage Diff\n"]
        lines.append(f"| Metric | Before | After | Delta |")
        lines.append(f"|--------|--------|-------|-------|")
        lines.append(f"| Overall Score | {self.before.overall_score:.1f}% | {self.after.overall_score:.1f}% | {arrow(self.after.overall_score - self.before.overall_score)} |")
        lines.append(f"| Instructions | {self.before.instruction_pct:.1f}% | {self.after.instruction_pct:.1f}% | {arrow(self.instruction_delta)} |")
        lines.append(f"| Branches | {self.before.branch_pct:.1f}% | {self.after.branch_pct:.1f}% | {arrow(self.branch_delta)} |")
        lines.append(f"| Registers | {self.before.register_pct:.1f}% | {self.after.register_pct:.1f}% | {arrow(self.register_delta)} |")
        lines.append(f"| Opcodes | {self.before.opcode_pct:.1f}% | {self.after.opcode_pct:.1f}% | {arrow(self.opcode_delta)} |")
        lines.append("")
        if self.new_opcodes:
            names = [OPCODE_NAMES.get(op, f"UNK_{op:#04x}") for op in self.new_opcodes]
            lines.append(f"**New opcodes covered:** {', '.join(names)}")
        if self.lost_opcodes:
            names = [OPCODE_NAMES.get(op, f"UNK_{op:#04x}") for op in self.lost_opcodes]
            lines.append(f"**Opcodes lost:** {', '.join(names)}")
        return "\n".join(lines)

    def to_terminal(self) -> str:
        def arrow(delta):
            if delta > 0: return f"+{delta:.1f}% ▲"
            if delta < 0: return f"{delta:.1f}% ▼"
            return " 0.0% ─"

        lines = ["╔══════════════════════════════════════════════╗"]
        lines.append("║        FLUX COVERAGE DIFF                 ║")
        lines.append("╠══════════════════════════════════════════════╣")
        lines.append(f"║ Metric        Before  After    Delta    ║")
        lines.append(f"║────────────── ──────── ──────── ──────── ║")
        lines.append(f"║ Overall       {self.before.overall_score:>6.1f}%  {self.after.overall_score:>6.1f}%  {arrow(self.after.overall_score - self.before.overall_score):>8} ║")
        lines.append(f"║ Instructions  {self.before.instruction_pct:>6.1f}%  {self.after.instruction_pct:>6.1f}%  {arrow(self.instruction_delta):>8} ║")
        lines.append(f"║ Branches      {self.before.branch_pct:>6.1f}%  {self.after.branch_pct:>6.1f}%  {arrow(self.branch_delta):>8} ║")
        lines.append(f"║ Registers     {self.before.register_pct:>6.1f}%  {self.after.register_pct:>6.1f}%  {arrow(self.register_delta):>8} ║")
        lines.append(f"║ Opcodes       {self.before.opcode_pct:>6.1f}%  {self.after.opcode_pct:>6.1f}%  {arrow(self.opcode_delta):>8} ║")
        lines.append("╚══════════════════════════════════════════════╝")
        if self.new_opcodes:
            names = [OPCODE_NAMES.get(op, f"UNK_{op:#04x}") for op in self.new_opcodes]
            lines.append(f"\n  New opcodes: {', '.join(names)}")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps({
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "deltas": {
                "instruction": round(self.instruction_delta, 2),
                "branch": round(self.branch_delta, 2),
                "opcode": round(self.opcode_delta, 2),
                "register": round(self.register_delta, 2),
                "overall": round(self.after.overall_score - self.before.overall_score, 2),
            },
            "new_opcodes": self.new_opcodes,
            "lost_opcodes": self.lost_opcodes,
            "improved": self.improved,
        }, indent=2)


def diff_reports(before: CoverageReport, after: CoverageReport) -> CoverageDiff:
    """Create a diff between two coverage reports."""
    return CoverageDiff(before=before, after=after)


# ═══════════════════════════════════════════════════════════════════
# Coverage Collector
# ═══════════════════════════════════════════════════════════════════

class CoverageCollector:
    """
    Collects coverage data by executing FLUX bytecode in a lightweight VM.
    Tracks opcode, branch, register, instruction, and path coverage.
    """

    def __init__(self, bytecode: List[int], label: str = ""):
        self.bytecode = bytes(bytecode)
        self.label = label
        self.hit_pcs: Set[int] = set()
        self.opcode_hits: Dict[int, int] = {}       # opcode -> hit count
        self.opcode_first_pc: Dict[int, int] = {}   # opcode -> first PC hit
        self.branch_taken: Set[int] = set()
        self.branch_not_taken: Set[int] = set()
        self.branch_taken_count: Dict[int, int] = {}
        self.branch_not_taken_count: Dict[int, int] = {}
        self.registers_read: Set[int] = set()
        self.registers_written: Set[int] = set()
        self.path_hashes: Set[str] = set()
        self._current_path: List[int] = []

    def reset(self):
        """Reset execution state for a fresh run (keeps accumulated coverage)."""
        self._current_path = []

    def run(self, initial_regs: Dict[int, int] = None, max_cycles: int = 100000) -> Tuple[Dict[int, int], CoverageReport]:
        """Execute bytecode and collect coverage data."""
        regs = [0] * 64
        stack = [0] * 4096
        sp = 4096
        pc = 0
        cycles = 0

        if initial_regs:
            for k, v in initial_regs.items():
                regs[k] = v

        bc = self.bytecode

        while pc < len(bc) and cycles < max_cycles:
            op = bc[pc]
            cycles += 1
            self.hit_pcs.add(pc)
            self._current_path.append(pc)

            # Track opcode
            self.opcode_hits[op] = self.opcode_hits.get(op, 0) + 1
            if op not in self.opcode_first_pc:
                self.opcode_first_pc[op] = pc

            if op == 0x00:
                break
            elif op == 0x01:
                pc += 1
            elif op == 0x08:
                rd = bc[pc+1]
                self.registers_read.add(rd); self.registers_written.add(rd)
                regs[rd] += 1; pc += 2
            elif op == 0x09:
                rd = bc[pc+1]
                self.registers_read.add(rd); self.registers_written.add(rd)
                regs[rd] -= 1; pc += 2
            elif op == 0x0C:
                rd = bc[pc+1]
                self.registers_read.add(rd)
                sp -= 1; stack[sp] = regs[rd]; pc += 2
            elif op == 0x0D:
                rd = bc[pc+1]
                self.registers_written.add(rd)
                regs[rd] = stack[sp]; sp += 1; pc += 2
            elif op == 0x18:
                rd = bc[pc+1]
                self.registers_written.add(rd)
                regs[rd] = _signed_byte(bc[pc+2]); pc += 3
            elif op == 0x20:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_read.update([rs1, rs2])
                self.registers_written.add(rd)
                regs[rd] = regs[rs1] + regs[rs2]; pc += 4
            elif op == 0x21:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_read.update([rs1, rs2])
                self.registers_written.add(rd)
                regs[rd] = regs[rs1] - regs[rs2]; pc += 4
            elif op == 0x22:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_read.update([rs1, rs2])
                self.registers_written.add(rd)
                regs[rd] = regs[rs1] * regs[rs2]; pc += 4
            elif op == 0x2C:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_read.update([rs1, rs2])
                self.registers_written.add(rd)
                regs[rd] = 1 if regs[rs1] == regs[rs2] else 0; pc += 4
            elif op == 0x3A:
                rd, rs1 = bc[pc+1], bc[pc+2]
                self.registers_read.add(rs1)
                self.registers_written.add(rd)
                regs[rd] = regs[rs1]; pc += 4
            elif op == 0x3C:
                rd = bc[pc+1]
                self.registers_read.add(rd)
                branch_pc = pc
                if regs[rd] == 0:
                    pc += _signed_byte(bc[pc+2])
                    self.branch_taken.add(branch_pc)
                    self.branch_taken_count[branch_pc] = self.branch_taken_count.get(branch_pc, 0) + 1
                else:
                    pc += 4
                    self.branch_not_taken.add(branch_pc)
                    self.branch_not_taken_count[branch_pc] = self.branch_not_taken_count.get(branch_pc, 0) + 1
            elif op == 0x3D:
                rd = bc[pc+1]
                self.registers_read.add(rd)
                branch_pc = pc
                if regs[rd] != 0:
                    pc += _signed_byte(bc[pc+2])
                    self.branch_taken.add(branch_pc)
                    self.branch_taken_count[branch_pc] = self.branch_taken_count.get(branch_pc, 0) + 1
                else:
                    pc += 4
                    self.branch_not_taken.add(branch_pc)
                    self.branch_not_taken_count[branch_pc] = self.branch_not_taken_count.get(branch_pc, 0) + 1
            else:
                pc += _inst_size(op)

        # Hash the current path (limit length to avoid unbounded growth)
        path_str = ",".join(str(p) for p in self._current_path[:50])
        path_hash = hashlib.sha256(path_str.encode()).hexdigest()[:16]
        self.path_hashes.add(path_hash)

        # Build branch details
        all_branch_pcs = self.branch_taken | self.branch_not_taken
        branch_details = []
        for bpc in sorted(all_branch_pcs):
            bop = bc[bpc]
            branch_details.append(BranchDetail(
                pc=bpc, opcode=bop,
                name=OPCODE_NAMES.get(bop, f"UNK_{bop:#04x}"),
                taken=bpc in self.branch_taken,
                not_taken=bpc in self.branch_not_taken,
                taken_count=self.branch_taken_count.get(bpc, 0),
                not_taken_count=self.branch_not_taken_count.get(bpc, 0),
            ))

        # Build opcode details
        opcode_details = {}
        for opc, count in self.opcode_hits.items():
            opcode_details[opc] = OpcodeCoverageDetail(
                opcode=opc,
                name=OPCODE_NAMES.get(opc, f"UNK_{opc:#04x}"),
                hit_count=count,
                first_hit_pc=self.opcode_first_pc.get(opc),
            )

        all_regs = self.registers_read | self.registers_written

        report = CoverageReport(
            total_instructions=_count_instructions(bc),
            hit_instructions=len(self.hit_pcs),
            total_branches=len(all_branch_pcs),
            branches_taken=len(self.branch_taken),
            branches_not_taken=len(self.branch_not_taken),
            unique_paths=len(self.path_hashes),
            registers_used=len(all_regs),
            total_registers=64,
            opcodes_seen=len(self.opcode_hits),
            opcode_details=opcode_details,
            branch_details=branch_details,
            register_read=set(self.registers_read),
            register_written=set(self.registers_written),
            label=self.label,
        )
        return {i: regs[i] for i in range(16)}, report


def collect_coverage(bytecode, label: str = "", **run_kwargs) -> CoverageReport:
    """Convenience function: run bytecode and return the coverage report."""
    _, report = CoverageCollector(bytecode, label=label).run(**run_kwargs)
    return report


# ═══════════════════════════════════════════════════════════════════
# Pytest Integration
# ═══════════════════════════════════════════════════════════════════

class FluxCoveragePlugin:
    """
    Pytest plugin for FLUX coverage collection.
    Usage:
        # conftest.py or pytest.ini:
        pytest_plugins = ["coverage"]  # or register via entry point
    """
    def __init__(self):
        self.collector: Optional[CoverageCollector] = None
        self._reports: List[CoverageReport] = []

    def pytest_configure(self, config):
        self.collector = CoverageCollector([])

    def pytest_collection_finish(self, session):
        pass

    def generate_summary(self) -> CoverageReport:
        """Generate an aggregated report from all collected runs."""
        if not self._reports:
            return CoverageReport(
                total_instructions=0, hit_instructions=0,
                total_branches=0, branches_taken=0, branches_not_taken=0,
                unique_paths=0, registers_used=0, total_registers=64,
                opcodes_seen=0,
            )
        # Merge all reports
        merged = self._reports[0]
        for r in self._reports[1:]:
            merged.opcodes_seen = len(set(merged.opcode_details) | set(r.opcode_details))
            merged.hit_instructions = max(merged.hit_instructions, r.hit_instructions)
            merged.total_instructions = max(merged.total_instructions, r.total_instructions)
            merged.registers_used = len(merged.register_read | r.register_read | merged.register_written | r.register_written)
            merged.branches_taken = len(set(b.pc for b in merged.branch_details if b.taken) |
                                        set(b.pc for b in r.branch_details if b.taken))
            merged.branches_not_taken = len(set(b.pc for b in merged.branch_details if b.not_taken) |
                                            set(b.pc for b in r.branch_details if b.not_taken))
        return merged

    def add_report(self, report: CoverageReport):
        self._reports.append(report)


# ═══════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════

import unittest


class TestCoverageCore(unittest.TestCase):
    """Core coverage functionality tests."""

    def test_full_instruction_coverage(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        self.assertEqual(report.instruction_pct, 100.0)

    def test_partial_instruction_coverage(self):
        bc = [0x18, 0, 0, 0x3C, 0, 3, 0, 0x18, 1, 99, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertLess(report.instruction_pct, 100.0)

    def test_branch_taken(self):
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFC, 0, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertGreater(report.branches_taken, 0)

    def test_branch_not_taken(self):
        bc = [0x18, 0, 1, 0x3C, 0, 5, 0, 0x18, 1, 99, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertGreater(report.branches_not_taken, 0)

    def test_register_read_written(self):
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertIn(0, report.register_read)
        self.assertIn(1, report.register_read)
        self.assertIn(2, report.register_written)
        self.assertGreater(report.registers_used, 0)

    def test_path_tracking(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        self.assertGreater(report.unique_paths, 0)

    def test_markdown_report_format(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        md = report.to_markdown()
        self.assertIn("Instructions", md)
        self.assertIn("100.0%", md)
        self.assertIn("Opcodes", md)

    def test_json_report_format(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        j = report.to_json()
        data = json.loads(j)
        self.assertIn("instruction_coverage", data)
        self.assertIn("opcode_coverage", data)
        self.assertEqual(data["instruction_coverage"]["percentage"], 100.0)

    def test_html_report_format(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        html = report.to_html()
        self.assertIn("<html>", html)
        self.assertIn("FLUX Coverage Report", html)
        self.assertIn("</html>", html)

    def test_terminal_report_format(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        txt = report.to_terminal()
        self.assertIn("FLUX COVERAGE REPORT", txt)
        self.assertIn("Instructions", txt)

    def test_factorial_coverage(self):
        bc = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        self.assertEqual(regs[1], 720)
        self.assertEqual(report.instruction_pct, 100.0)

    def test_multiple_runs_accumulate(self):
        bc = [0x18, 0, 0, 0x3C, 0, 3, 0, 0x18, 1, 99, 0x00]
        c1 = CoverageCollector(bc)
        c1.run()
        c2 = CoverageCollector(bc)
        c2.run({0: 1})
        self.assertGreater(len(c2.hit_pcs), 0)

    def test_opcode_tracking(self):
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertGreaterEqual(report.opcodes_seen, 2)
        self.assertIn(0x18, report.opcode_details)
        self.assertEqual(report.opcode_details[0x18].name, "MOVI")

    def test_opcode_first_pc(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        self.assertEqual(report.opcode_details[0x18].first_hit_pc, 0)

    def test_branch_detail_structure(self):
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFC, 0, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertEqual(len(report.branch_details), 1)
        bd = report.branch_details[0]
        self.assertEqual(bd.name, "BNE")
        self.assertTrue(bd.taken)


class TestCoverageDiff(unittest.TestCase):
    """Coverage diffing tests."""

    def test_diff_improvement(self):
        r1 = collect_coverage([0x18, 0, 42, 0x00], label="before")
        r2 = collect_coverage([0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00], label="after")
        d = diff_reports(r1, r2)
        self.assertTrue(d.improved)
        self.assertGreater(len(d.new_opcodes), 0)

    def test_diff_markdown(self):
        r1 = collect_coverage([0x18, 0, 42, 0x00])
        r2 = collect_coverage([0x18, 0, 42, 0x18, 1, 10, 0x00])
        d = diff_reports(r1, r2)
        md = d.to_markdown()
        self.assertIn("Before", md)
        self.assertIn("After", md)

    def test_diff_terminal(self):
        r1 = collect_coverage([0x18, 0, 42, 0x00])
        r2 = collect_coverage([0x18, 0, 42, 0x18, 1, 10, 0x00])
        d = diff_reports(r1, r2)
        txt = d.to_terminal()
        self.assertIn("COVERAGE DIFF", txt)

    def test_diff_json(self):
        r1 = collect_coverage([0x18, 0, 42, 0x00])
        r2 = collect_coverage([0x18, 0, 42, 0x18, 1, 10, 0x00])
        d = diff_reports(r1, r2)
        j = d.to_json()
        data = json.loads(j)
        self.assertIn("deltas", data)
        self.assertIn("improved", data)

    def test_diff_identical(self):
        r1 = collect_coverage([0x18, 0, 42, 0x00])
        r2 = collect_coverage([0x18, 0, 42, 0x00])
        d = diff_reports(r1, r2)
        self.assertAlmostEqual(d.instruction_delta, 0.0)


class TestCoveragePytest(unittest.TestCase):
    """Pytest plugin integration tests."""

    def test_plugin_creation(self):
        plugin = FluxCoveragePlugin()
        self.assertIsNone(plugin.collector)

    def test_plugin_configure(self):
        plugin = FluxCoveragePlugin()
        plugin.pytest_configure(None)
        self.assertIsNotNone(plugin.collector)

    def test_plugin_empty_summary(self):
        plugin = FluxCoveragePlugin()
        report = plugin.generate_summary()
        self.assertEqual(report.opcodes_seen, 0)
        self.assertEqual(report.total_instructions, 0)

    def test_plugin_add_report(self):
        plugin = FluxCoveragePlugin()
        r = collect_coverage([0x18, 0, 42, 0x00])
        plugin.add_report(r)
        summary = plugin.generate_summary()
        self.assertGreater(summary.opcodes_seen, 0)

    def test_format_enum(self):
        self.assertEqual(ReportFormat.TERMINAL.value, "terminal")
        self.assertEqual(ReportFormat.JSON.value, "json")
        self.assertEqual(ReportFormat.HTML.value, "html")
        self.assertEqual(ReportFormat.MARKDOWN.value, "markdown")

    def test_convenience_function(self):
        report = collect_coverage([0x18, 0, 42, 0x00], label="convenience")
        self.assertEqual(report.label, "convenience")
        self.assertGreater(report.instruction_pct, 0)

    def test_overall_score(self):
        report = collect_coverage([0x18, 0, 42, 0x00])
        self.assertGreater(report.overall_score, 0)
        self.assertLessEqual(report.overall_score, 100)

    def test_branch_fully_covered(self):
        """Branch that is taken but not not-taken is not fully covered."""
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFC, 0, 0x00]
        report = collect_coverage(bc)
        self.assertLess(report.branches_fully_covered, report.total_branches)

    def test_register_pct_zero(self):
        """Program with HALT only has no register usage."""
        report = collect_coverage([0x00])
        self.assertEqual(report.registers_used, 0)
        self.assertEqual(report.register_pct, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
