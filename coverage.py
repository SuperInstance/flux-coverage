"""
FLUX Coverage — measure how much of a bytecode program was actually executed.

Tracks instruction coverage, branch coverage, path coverage, register coverage.
"""
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple


@dataclass
class CoverageReport:
    total_instructions: int
    hit_instructions: int
    total_branches: int
    branches_taken: int
    branches_not_taken: int
    unique_paths: int
    registers_used: int
    total_registers: int
    
    @property
    def instruction_pct(self) -> float:
        return (self.hit_instructions / self.total_instructions * 100) if self.total_instructions > 0 else 0
    
    @property
    def branch_pct(self) -> float:
        total = self.branches_taken + self.branches_not_taken
        both = min(self.branches_taken, self.branches_not_taken)
        return (both * 2 / total * 100) if total > 0 else 0
    
    @property
    def register_pct(self) -> float:
        return (self.registers_used / self.total_registers * 100) if self.total_registers > 0 else 0
    
    def to_markdown(self) -> str:
        lines = ["# FLUX Coverage Report\n"]
        lines.append("| Metric | Hit | Total | Coverage |")
        lines.append("|--------|-----|-------|----------|")
        lines.append("| Instructions | {} | {} | {:.1f}% |".format(
            self.hit_instructions, self.total_instructions, self.instruction_pct))
        lines.append("| Branches taken | {} | {} | - |".format(
            self.branches_taken, self.total_branches))
        lines.append("| Branch both ways | - | - | {:.1f}% |".format(self.branch_pct))
        lines.append("| Registers | {} | {} | {:.1f}% |".format(
            self.registers_used, self.total_registers, self.register_pct))
        lines.append("| Unique paths | {} | - | - |".format(self.unique_paths))
        return "\n".join(lines)


def _inst_size(op):
    if op <= 0x07: return 1
    if op <= 0x17: return 2
    if op <= 0x1F: return 3
    return 4


def _count_instructions(bc):
    i = 0
    count = 0
    while i < len(bc):
        i += _inst_size(bc[i])
        count += 1
    return count


class CoverageCollector:
    def __init__(self, bytecode: List[int]):
        self.bytecode = bytes(bytecode)
        self.hit_pcs: Set[int] = set()
        self.branch_taken: Set[int] = set()
        self.branch_not_taken: Set[int] = set()
        self.registers_used: Set[int] = set()
        self.path_hashes: Set[str] = set()
        self._current_path: List[int] = []
    
    def run(self, initial_regs: Dict[int, int] = None, max_cycles: int = 100000) -> Tuple[Dict[int, int], CoverageReport]:
        regs = [0] * 64
        stack = [0] * 4096
        sp = 4096
        pc = 0
        cycles = 0
        
        if initial_regs:
            for k, v in initial_regs.items():
                regs[k] = v
        
        def sb(b): return b - 256 if b > 127 else b
        bc = self.bytecode
        
        while pc < len(bc) and cycles < max_cycles:
            op = bc[pc]
            cycles += 1
            self.hit_pcs.add(pc)
            self._current_path.append(pc)
            
            if op == 0x00: break
            elif op == 0x08:
                rd = bc[pc+1]; self.registers_used.add(rd); regs[rd] += 1; pc += 2
            elif op == 0x09:
                rd = bc[pc+1]; self.registers_used.add(rd); regs[rd] -= 1; pc += 2
            elif op == 0x0C:
                rd = bc[pc+1]; self.registers_used.add(rd); sp -= 1; stack[sp] = regs[rd]; pc += 2
            elif op == 0x0D:
                rd = bc[pc+1]; self.registers_used.add(rd); regs[rd] = stack[sp]; sp += 1; pc += 2
            elif op == 0x18:
                rd = bc[pc+1]; self.registers_used.add(rd); regs[rd] = sb(bc[pc+2]); pc += 3
            elif op == 0x20:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_used.update([rd, rs1, rs2])
                regs[rd] = regs[rs1] + regs[rs2]; pc += 4
            elif op == 0x21:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_used.update([rd, rs1, rs2])
                regs[rd] = regs[rs1] - regs[rs2]; pc += 4
            elif op == 0x22:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_used.update([rd, rs1, rs2])
                regs[rd] = regs[rs1] * regs[rs2]; pc += 4
            elif op == 0x2C:
                rd, rs1, rs2 = bc[pc+1], bc[pc+2], bc[pc+3]
                self.registers_used.update([rd, rs1, rs2])
                regs[rd] = 1 if regs[rs1] == regs[rs2] else 0; pc += 4
            elif op == 0x3A:
                rd, rs1 = bc[pc+1], bc[pc+2]
                self.registers_used.update([rd, rs1])
                regs[rd] = regs[rs1]; pc += 4
            elif op == 0x3C:
                rd = bc[pc+1]; self.registers_used.add(rd)
                branch_pc = pc
                if regs[rd] == 0:
                    pc += sb(bc[pc+2])
                    self.branch_taken.add(branch_pc)
                else:
                    pc += 4
                    self.branch_not_taken.add(branch_pc)
            elif op == 0x3D:
                rd = bc[pc+1]; self.registers_used.add(rd)
                branch_pc = pc
                if regs[rd] != 0:
                    pc += sb(bc[pc+2])
                    self.branch_taken.add(branch_pc)
                else:
                    pc += 4
                    self.branch_not_taken.add(branch_pc)
            else:
                pc += 1
        
        self.path_hashes.add(",".join(str(p) for p in self._current_path[:50]))
        
        all_branches = self.branch_taken | self.branch_not_taken
        
        report = CoverageReport(
            total_instructions=_count_instructions(bc),
            hit_instructions=len(self.hit_pcs),
            total_branches=len(all_branches),
            branches_taken=len(self.branch_taken),
            branches_not_taken=len(self.branch_not_taken),
            unique_paths=len(self.path_hashes),
            registers_used=len(self.registers_used),
            total_registers=64,
        )
        return {i: regs[i] for i in range(16)}, report


import unittest


class TestCoverage(unittest.TestCase):
    def test_full_coverage(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        self.assertEqual(report.instruction_pct, 100.0)
    
    def test_partial_coverage(self):
        bc = [0x18, 0, 0, 0x3C, 0, 3, 0, 0x18, 1, 99, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertLess(report.instruction_pct, 100.0)
    
    def test_branch_coverage(self):
        bc = [0x18, 0, 5, 0x09, 0, 0x3D, 0, 0xFC, 0, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertGreater(report.branches_taken, 0)
    
    def test_register_coverage(self):
        bc = [0x18, 0, 10, 0x18, 1, 20, 0x20, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertGreater(report.registers_used, 0)
        self.assertGreater(report.register_pct, 0)
    
    def test_path_tracking(self):
        bc = [0x18, 0, 42, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        self.assertGreater(report.unique_paths, 0)
    
    def test_markdown_report(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        md = report.to_markdown()
        self.assertIn("Instructions", md)
        self.assertIn("100.0%", md)
    
    def test_factorial_coverage(self):
        bc = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        self.assertEqual(regs[1], 720)
        self.assertEqual(report.instruction_pct, 100.0)
        self.assertGreater(report.branches_taken, 0)
    
    def test_multiple_runs(self):
        bc = [0x18, 0, 0, 0x3C, 0, 3, 0, 0x18, 1, 99, 0x00]
        c1 = CoverageCollector(bc)
        c1.run()
        c2 = CoverageCollector(bc)
        c2.run({0: 1})
        self.assertGreater(len(c2.hit_pcs), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
