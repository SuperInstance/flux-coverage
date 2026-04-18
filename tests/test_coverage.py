"""Comprehensive pytest tests for flux-coverage."""

import pytest
from coverage import (
    CoverageReport,
    CoverageCollector,
    _inst_size,
    _count_instructions,
)


# ── CoverageReport tests ──────────────────────────────────────

class TestCoverageReport:
    """Tests for the CoverageReport dataclass."""

    def test_instruction_pct_full(self):
        r = CoverageReport(10, 10, 2, 2, 0, 1, 5, 64)
        assert r.instruction_pct == 100.0

    def test_instruction_pct_partial(self):
        r = CoverageReport(10, 5, 0, 0, 0, 1, 3, 64)
        assert r.instruction_pct == 50.0

    def test_instruction_pct_zero_denominator(self):
        r = CoverageReport(0, 0, 0, 0, 0, 1, 0, 64)
        assert r.instruction_pct == 0.0

    def test_branch_pct_full(self):
        """Both taken and not-taken for all branches => 100%."""
        r = CoverageReport(4, 4, 2, 2, 2, 1, 3, 64)
        assert r.branch_pct == 100.0

    def test_branch_pct_none_both(self):
        """If one side is 0 for all branches, branch_pct = 0."""
        r = CoverageReport(4, 4, 2, 2, 0, 1, 3, 64)
        assert r.branch_pct == 0.0

    def test_branch_pct_mixed(self):
        """min(taken, not_taken) * 2 / total. With taken=1, not_taken=1: min=1*2/2=100%."""
        r = CoverageReport(4, 4, 2, 2, 0, 1, 3, 64)
        assert r.branch_pct == 0.0
        r2 = CoverageReport(4, 4, 2, 1, 1, 1, 3, 64)
        assert r2.branch_pct == 100.0

    def test_branch_pct_zero_denominator(self):
        r = CoverageReport(0, 0, 0, 0, 0, 1, 0, 64)
        assert r.branch_pct == 0.0

    def test_register_pct_full(self):
        r = CoverageReport(4, 4, 0, 0, 0, 1, 64, 64)
        assert r.register_pct == 100.0

    def test_register_pct_partial(self):
        r = CoverageReport(4, 4, 0, 0, 0, 1, 16, 64)
        assert r.register_pct == 25.0

    def test_register_pct_zero_denominator(self):
        r = CoverageReport(4, 4, 0, 0, 0, 1, 0, 0)
        assert r.register_pct == 0.0

    def test_to_markdown_contains_metrics(self):
        r = CoverageReport(10, 8, 2, 1, 1, 3, 5, 64)
        md = r.to_markdown()
        assert "# FLUX Coverage Report" in md
        assert "Instructions" in md
        assert "Branches taken" in md
        assert "Registers" in md
        assert "Unique paths" in md
        assert "80.0%" in md

    def test_to_markdown_empty_program(self):
        r = CoverageReport(0, 0, 0, 0, 0, 0, 0, 0)
        md = r.to_markdown()
        assert "# FLUX Coverage Report" in md
        assert "0.0%" in md


# ── _inst_size tests ──────────────────────────────────────────

class TestInstSize:
    """Tests for the _inst_size helper function."""

    @pytest.mark.parametrize("op, expected", [
        (0x00, 1),  # HALT
        (0x01, 1),  # NOP
        (0x07, 1),  # boundary: 0x07 -> size 1
        (0x08, 2),  # INC
        (0x09, 2),  # DEC
        (0x0C, 2),  # PUSH
        (0x0D, 2),  # POP
        (0x17, 2),  # boundary: 0x17 -> size 2
        (0x18, 3),  # MOVI
        (0x19, 3),  # ADDI
        (0x1F, 3),  # boundary: 0x1F -> size 3
        (0x20, 4),  # ADD
        (0x21, 4),  # SUB
        (0x22, 4),  # MUL
        (0x2C, 4),  # CMP_EQ
        (0x3A, 4),  # MOV
        (0x3C, 4),  # JZ
        (0x3D, 4),  # JNZ
        (0xFF, 4),  # unknown -> size 4
    ])
    def test_inst_size(self, op, expected):
        assert _inst_size(op) == expected


# ── _count_instructions tests ─────────────────────────────────

class TestCountInstructions:
    """Tests for the _count_instructions helper function."""

    def test_empty_bytecode(self):
        assert _count_instructions([]) == 0

    def test_single_halt(self):
        assert _count_instructions([0x00]) == 1

    def test_mixed_instructions(self):
        # MOVI r0, 42 (3 bytes) + HALT (1 byte) = 2 instructions
        assert _count_instructions([0x18, 0, 42, 0x00]) == 2

    def test_all_size_categories(self):
        # 1-byte: HALT
        # 2-byte: INC
        # 3-byte: MOVI
        # 4-byte: ADD
        bc = [0x08, 0, 0x18, 0, 0, 0x20, 0, 0, 0, 0x00]
        assert _count_instructions(bc) == 4

    def test_long_program(self):
        bc = [0x08, 0, 0x09, 1] * 10 + [0x00]
        assert _count_instructions(bc) == 21


# ── CoverageCollector tests ───────────────────────────────────

class TestCoverageCollector:
    """Tests for the CoverageCollector class."""

    def test_empty_bytecode(self):
        c = CoverageCollector([])
        regs, report = c.run()
        assert report.total_instructions == 0
        assert report.hit_instructions == 0

    def test_single_halt(self):
        c = CoverageCollector([0x00])
        regs, report = c.run()
        assert report.total_instructions == 1
        assert report.hit_instructions == 1
        assert report.instruction_pct == 100.0

    def test_movi_and_halt(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        regs, report = c.run()
        assert report.instruction_pct == 100.0
        assert regs[0] == 42

    def test_inc_instruction(self):
        bc = [0x18, 0, 10, 0x08, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[0] == 11
        assert report.instruction_pct == 100.0

    def test_dec_instruction(self):
        bc = [0x18, 0, 10, 0x09, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[0] == 9

    def test_add_instruction(self):
        bc = [0x18, 0, 5, 0x18, 1, 7, 0x20, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[2] == 12

    def test_sub_instruction(self):
        bc = [0x18, 0, 10, 0x18, 1, 3, 0x21, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[2] == 7

    def test_mul_instruction(self):
        bc = [0x18, 0, 6, 0x18, 1, 7, 0x22, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[2] == 42

    def test_cmp_eq_equal(self):
        bc = [0x18, 0, 5, 0x18, 1, 5, 0x2C, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[2] == 1

    def test_cmp_eq_not_equal(self):
        bc = [0x18, 0, 5, 0x18, 1, 3, 0x2C, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[2] == 0

    def test_mov_instruction(self):
        bc = [0x18, 0, 99, 0x3A, 5, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[5] == 99

    def test_push_pop(self):
        bc = [0x18, 0, 42, 0x0C, 0, 0x18, 1, 0, 0x0D, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[1] == 42

    def test_initial_regs(self):
        bc = [0x20, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run(initial_regs={0: 10, 1: 20})
        assert regs[2] == 30

    def test_max_cycles(self):
        """Program with a loop that exceeds max_cycles."""
        # JZ r0 with large negative offset -> infinite loop (r0 stays 0, JZ always taken)
        # But offset -6 lands at a valid instruction that loops back.
        # MOVI r0,0; JZ r0, -6 (back to MOVI); this creates a true infinite loop.
        bc = [0x18, 0, 0, 0x3C, 0, 0xFA, 0x00, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run(max_cycles=10)
        # Should stop due to max_cycles (loop between MOVI and JZ)
        # The loop: pc=0 MOVI, pc=3 JZ taken → pc=3+(-6)=-3, then -3 < len(bc) is True
        # bc[-3] = bc[5] = 0xFA, which is a 4-byte instruction size, so pc=-3+4=1
        # pc=1: op=0x00 HALT → break. Actually this stops early.
        # Let's just verify max_cycles is respected by using a simple loop:
        bc2 = [0x08, 0, 0x09, 0] * 1000 + [0x00]  # INC/DEC loop, no branch
        c2 = CoverageCollector(bc2)
        regs2, report2 = c2.run(max_cycles=5)
        assert report2.hit_instructions <= 5

    def test_jz_branch_taken(self):
        """JZ jumps when register is zero."""
        # MOVI r0, 0; JZ r0, +3 (skip past INC to HALT)
        bc = [0x18, 0, 0, 0x3C, 0, 3, 0x08, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert 3 in c.branch_taken  # JZ is at pc=3

    def test_jz_branch_not_taken(self):
        """JZ doesn't jump when register is non-zero."""
        # MOVI r0, 5; JZ r0, +3; INC r0; HALT
        # When not taken, pc advances by 4 (skip operand bytes), landing on pc=7=HALT.
        # INC at pc=6 is skipped.
        bc = [0x18, 0, 5, 0x3C, 0, 3, 0x08, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert 3 in c.branch_not_taken
        assert regs[0] == 5  # INC skipped (not-taken falls through past operands)

    def test_jnz_branch_taken(self):
        """JNZ jumps when register is non-zero."""
        # MOVI r0, 1; JNZ r0, +3 (skip to HALT)
        bc = [0x18, 0, 1, 0x3D, 0, 3, 0x08, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert 3 in c.branch_taken

    def test_jnz_branch_not_taken(self):
        """JNZ doesn't jump when register is zero."""
        # MOVI r0, 0; JNZ r0, +3; INC r0; HALT
        # When not taken, pc advances by 4 (skip operand bytes), landing on pc=7=HALT.
        # INC at pc=6 is skipped.
        bc = [0x18, 0, 0, 0x3D, 0, 3, 0x08, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert 3 in c.branch_not_taken
        assert regs[0] == 0  # INC skipped (not-taken falls through past operands)

    def test_branch_coverage_both_ways(self):
        """Run same program with different inputs to cover both branch directions."""
        # Use ADD to set r0 from initial regs, then JZ
        # r0+r1: if r1=0 → r0 stays as-is (0), JZ taken
        # if r1=1 → r0=1, JZ not taken
        bc = [0x20, 0, 0, 1, 0x3C, 0, 3, 0x08, 0, 0x00]

        c1 = CoverageCollector(bc)
        c1.run(initial_regs={0: 0, 1: 0})  # r0=0, JZ taken

        c2 = CoverageCollector(bc)
        c2.run(initial_regs={0: 0, 1: 1})  # r0=1, JZ not taken

        # Merge branches for full coverage
        all_taken = c1.branch_taken | c2.branch_taken
        all_not_taken = c1.branch_not_taken | c2.branch_not_taken
        assert len(all_taken) > 0
        assert len(all_not_taken) > 0

    def test_register_tracking(self):
        bc = [0x18, 0, 1, 0x18, 5, 2, 0x20, 10, 0, 5, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        assert 0 in c.registers_used
        assert 5 in c.registers_used
        assert 10 in c.registers_used
        assert report.registers_used == 3

    def test_path_tracking(self):
        bc = [0x18, 0, 42, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        assert report.unique_paths == 1

    def test_path_accumulation_across_runs(self):
        """Running the same collector multiple times appends to _current_path.

        Since _current_path is not reset between runs, the path hash grows.
        """
        bc = [0x18, 0, 42, 0x00]
        c = CoverageCollector(bc)
        c.run()
        # After 1 run: path = "0,3"
        assert len(c.path_hashes) == 1
        c.run()
        # After 2 runs: path = "0,3,0,3" (accumulated), a new unique hash
        assert len(c.path_hashes) == 2

    def test_return_regs_slice(self):
        """run() returns only first 16 registers."""
        bc = [0x18, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs, _ = c.run()
        assert len(regs) == 16

    def test_factorial(self):
        """Compute 6! = 720."""
        # r0=6, r1=1, loop: r1*=r0, r0--, JNZ r0, loop
        bc = [0x18, 0, 6, 0x18, 1, 1, 0x22, 1, 1, 0, 0x09, 0, 0x3D, 0, 0xFA, 0, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run()
        assert regs[1] == 720
        assert report.instruction_pct == 100.0

    def test_markdown_report_integration(self):
        c = CoverageCollector([0x18, 0, 42, 0x00])
        _, report = c.run()
        md = report.to_markdown()
        assert "FLUX Coverage Report" in md
        assert "100.0%" in md
        assert "Branches taken" in md

    def test_negative_immediate(self):
        """MOVI with negative immediate value."""
        # sb(0xFF) = -1
        bc = [0x18, 0, 0xFF, 0x00]
        c = CoverageCollector(bc)
        regs, _ = c.run()
        assert regs[0] == -1

    def test_unknown_opcode_discrepancy(self):
        """Unknown opcodes: VM advances 1 byte but _inst_size returns 4.

        This is a known discrepancy: _count_instructions treats unknown opcodes
        as 4-byte instructions (since op > 0x1F), but the VM's else clause only
        advances by 1 byte. This causes instruction_pct > 100% for programs with
        unknown opcodes.
        """
        bc = [0xFE, 0x18, 0, 42, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        # _count_instructions counts FE as 4-byte (1 inst) + MOVI (1 inst) = 2 total
        # But VM hits 3 PCs (0, 1, 4)
        assert report.total_instructions == 2
        assert report.hit_instructions == 3
        assert report.instruction_pct == 150.0

    def test_partial_coverage_unreachable_code(self):
        """Code after a branch that jumps to end is unreachable."""
        # MOVI r0, 0; JZ r0, +6; <unreachable>; <unreachable>; HALT
        bc = [0x18, 0, 0, 0x3C, 0, 6, 0x18, 5, 99, 0x18, 6, 88, 0x00]
        c = CoverageCollector(bc)
        _, report = c.run()
        assert report.instruction_pct < 100.0

    def test_zero_max_cycles(self):
        """max_cycles=0 means no instructions executed."""
        bc = [0x18, 0, 42, 0x00]
        c = CoverageCollector(bc)
        regs, report = c.run(max_cycles=0)
        assert report.hit_instructions == 0
        assert regs[0] == 0

    def test_reusable_collector(self):
        """CoverageCollector can be run with different initial_regs."""
        bc = [0x20, 2, 0, 1, 0x00]
        c = CoverageCollector(bc)
        regs1, _ = c.run(initial_regs={0: 1, 1: 2})
        regs2, _ = c.run(initial_regs={0: 10, 1: 20})
        assert regs1[2] == 3
        assert regs2[2] == 30
