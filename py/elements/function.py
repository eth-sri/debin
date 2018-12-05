import multiprocessing.dummy
import time

from common.idgen import IDGEN
from common.timer import TIMER
from common import utils
from common.utils import decode_sleb128, encode_address
from common.constants import UNKNOWN_LABEL, LOC_VAR, FUN_ARG, VOID
from common.constants import ENUM_DW_FORM_exprloc, ENUM_ABBREV_CODE
from common.constants import X64_FUN_ARG_REGS, ARM_FUN_ARG_REGS, TTYPES
from bap.stmts import DefStmt, JmpStmt, DirectLabel, CallKind
from bap.vars import MemVar, RegVar, VirtualVar
from bap.exps import IntExp, StoreExp, BinOpExp
from elements.givs import Node
from elements.ttype import Ttype
from elements.regs import GivReg, Reg
from elements.offsets import IndirectOffset
from elements.elmfactory import EXP_TRANSFORMER
from elements.conventions import infer_functions, syscalls
from elfs.framebase import FrameBase
from elftools.dwarf.locationlists import LocationEntry
from c.variables import make_variables
from common.constants import SYMTAB


class Functions:
    def __init__(self, *args, **kwargs):
        self.binary = kwargs['binary']
        if 'functions' in kwargs:
            self.functions = kwargs['functions']
        elif 'bap' in kwargs:
            self.bap = kwargs['bap']
            self.functions = [Function(bap=sub_bap, binary=self.binary) for sub_bap in self.bap]

        self.functions_by_lowpc = dict([(f.low_pc, f) for f in self.functions])
        self.functions_by_tid = dict([(f.tid, f) for f in self.functions])

        self.low_pc = min(map(lambda f: f.low_pc, self.functions))
        self.high_pc = max(map(lambda f: f.high_pc, self.functions))

    def initialize(self):
        self.binary.sections.init_dynsym_functions()

        if not self.binary.sections.has_sec(SYMTAB):
            syscalls(self)
            if self.binary.binary_type == 'ET_EXEC':
                infer_functions(self)

        regs = []
        offs = []

        for f in self.functions:
            if f.is_run_init:
                f.initialize()

            if self.binary.config.TWO_PASS:
                regs += list(f.regs.values())
                for off in f.indirect_offsets.values():
                    for indirect_offset in off.values():
                        offs.append(indirect_offset)

        utils.write_progress('Recovering Variables...', self.binary)
        if self.binary.config.TWO_PASS:
            TIMER.start_scope('1VAR')
            for i in regs + offs:
                predict(i, self.binary)
            TIMER.end_scope()
        utils.write_progress('Extracting Features...', self.binary)

        for f in self.functions:
            f.callees.clear()
            f.callers.clear()
            for callee in f.bap.callees:
                if callee in self.functions_by_tid:
                    f.add_callee(self.functions_by_tid[callee])
            for caller in f.bap.callers:
                if caller in self.functions_by_tid:
                    f.add_caller(self.functions_by_tid[caller])

    def get_function_by_tid(self, tid):
        return self.functions_by_tid[tid] if tid in self.functions_by_tid else None

    def get_function_by_lowpc(self, low_pc):
        return self.functions_by_lowpc[low_pc] if low_pc in self.functions_by_lowpc else None

    def is_lowpc_function(self, low_pc):
        return low_pc in self.functions_by_lowpc

    def get_function_by_pc(self, pc):
        for f in self.functions:
            if pc >= f.low_pc and pc <= f.high_pc:
                return f
        else:
            return None


def predict(loc, binary):
    if isinstance(loc, Reg):
        reg = loc
        feature = binary.config.REG_DICT.transform(dict(map(lambda f: (f, 1), reg.features)))
        if binary.config.REG_MODEL.predict(feature)[0] == 1:
            reg.n2p_type = binary.config.INF
        else:
            reg.n2p_type = binary.config.GIV
    elif isinstance(loc, IndirectOffset):
        off = loc
        feature = binary.config.OFF_DICT.transform(dict(map(lambda f: (f, 1), off.features)))
        if binary.config.OFF_MODEL.predict(feature)[0] == 1:
            off.n2p_type = binary.config.INF
        else:
            off.n2p_type = binary.config.GIV


class Function(Node):
    total = 0
    known = 0
    unknown = 0
    inf = 0
    giv = 0
    correct = 0

    ttype_total = 0
    ttype_known = 0
    ttype_unknown = 0
    ttype_inf = 0
    ttype_tp_1p = 0
    ttype_fp_1p = 0
    ttype_tn_1p = 0
    ttype_fn_1p = 0
    ttype_correct = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bap = kwargs['bap']
        self.binary = kwargs['binary']
        self.low_pc = self.bap.low_pc
        self.high_pc = self.bap.high_pc
        self.name = self.bap.name

        if self.low_pc == self.binary.entry_point:
            self.name = '_start'

        self.train_name = UNKNOWN_LABEL
        self.is_name_given = False
        self.is_run_init = True

        if self.name in ('_start', '_init', '_fini', '__libc_csu_init', '__libc_csu_fini', '__libc_start_main'):
            self.is_run_init = False
            self.is_name_given = True
            self.train_name = self.name
        else:
            if self.binary.sections.is_in_text_sec(self.low_pc):
                if not self.name.startswith('sub_'):
                    self.train_name = self.name
                    if self.binary.config.MODE == self.binary.config.TEST:
                        self.is_name_given = True
            else:
                if not self.name.startswith('sub_'):
                    self.is_name_given = True
                    self.train_name = self.name
                self.is_run_init = False

        self.tid = self.bap.tid
        self.ttype = None
        self.test_name = UNKNOWN_LABEL
        if self.is_name_given:
            self.test_name = self.train_name

        self.insns = set()
        self.flags = set()
        self.giv_regs = set()
        self.giv_offsets = set()
        self.int_consts = set()
        self.string_consts = set()
        self.code_offsets = set()
        self.virtual_elms = set()
        self.direct_offsets = set()
        self.switch_tables = set()
        self.syscalls = set()

        self.virtual_exps = dict()
        self.reg_pcs = dict()
        self.flag_pcs = dict()

        self.flag_defs = dict()
        self.reg_defs = dict()

        self.indirect_offsets = dict()
        self.regs = dict()

        self.blks = dict()

        self.callers = set()
        self.callees = set()
        self.factors = []
        self.not_equals = set()

        self.nodes = []
        self.edges = []

        if self.binary.config.MACHINE_ARCH == 'x86':
            self.fun_arg_offset = None

        if self.binary.config.MODE == self.binary.config.TRAIN:
            self.die_children = []
            self.frame_bases = []
            self.frame_bases_added = False
            self.init_run = False

    def __repr__(self):
        return '(Function {} {} {} {})'.format(format(self.low_pc, '02x'), format(self.high_pc, '02x'), self.tid, self.name)

    def __str__(self):
        if self.test_name is None or \
                self.test_name == UNKNOWN_LABEL or \
                self.test_name == self.train_name:
            return '(Function {} {})'.format(self.train_name, str(self.ttype))
        else:
            if self.train_name == UNKNOWN_LABEL:
                return '(Function (WRONGU {} {}) {})'.format(self.train_name, self.test_name, str(self.ttype))
            else:
                return '(Function (WRONGK {} {}) {})'.format(self.train_name, self.test_name, str(self.ttype))

    def initialize(self):
        from elements.blk import Blk

        self.ttype = Ttype(owner=self)

        for blk_bap in self.bap.blks:
            blk = Blk(function=self, bap=blk_bap)
            self.blks[blk.tid] = blk

        for virtual_exp in self.virtual_exps.values():
            if isinstance(virtual_exp.exp, list):
                virtual_exp.exp = [EXP_TRANSFORMER.visit(e, blk=virtual_exp.blk, pc=virtual_exp.pc) for e in virtual_exp.exp]
            else:
                virtual_exp.exp = EXP_TRANSFORMER.visit(virtual_exp.exp, blk=virtual_exp.blk, pc=virtual_exp.pc)

        for blk in self.blks.values():
            blk.initialize()

        for blk in self.blks.values():
            blk.init_features()

        for l in self.bap.cfg:
            src = l[0]
            dst = l[1]
            if src in self.blks and dst in self.blks:
                self.blks[src].add_callee(self.blks[dst])
                self.blks[dst].add_caller(self.blks[src])

        if self.binary.config.INDIRECT_OFFSET_WITH_INDEX:
            for base_pointer, offset in self.indirect_offsets:
                key = (base_pointer, offset)
                for index in self.indirect_offsets[key]:
                    reg_key = (base_pointer, index)
                    if reg_key in self.regs:
                        reg = self.regs[reg_key]
                        indirect_offset = self.indirect_offsets[key][index]
                        for pc in reg.pcs:
                            indirect_offset.add_pc(pc)

        if self.binary.config.MACHINE_ARCH == 'x86':
            self.find_fun_args()

    def find_fun_args(self):
        reg_to_offset = {
            frozenset(['EBX', 'ESI', 'EDI', 'EBP']): 20,
            frozenset(['ESI', 'EDI', 'EBP']): 16,
            frozenset(['EBX', 'ESI', 'EDI']): 16,
            frozenset(['ESI', 'EDI']): 12,
            frozenset(['EBX', 'EDI']): 12,
            frozenset(['EBX', 'ESI']): 12,
            frozenset(['EBX']): 8,
            frozenset([]): 4,
        }

        pushed_regs = set()

        if self.fun_arg_offset is None:
            # print(self.name)
            for blk in self.bap.blks:
                for i, stmt in enumerate(blk.stmts):
                    if isinstance(stmt, DefStmt) and stmt.insn is not None and stmt.insn.startswith('SUB') \
                            and isinstance(stmt.lhs, RegVar) and stmt.lhs.name == 'ESP' \
                            and isinstance(stmt.rhs, BinOpExp) and stmt.rhs.op == 'MINUS' \
                            and isinstance(stmt.rhs.e1, RegVar) and stmt.rhs.e1.name == 'ESP' \
                            and isinstance(stmt.rhs.e2, IntExp):
                        self.fun_arg_offset = stmt.rhs.e2.value
                        pushed_virtual_vars = set()
                        for j in range(i - 1, -1, -1):
                            stmt = blk.stmts[j]
                            if isinstance(stmt, DefStmt) and stmt.insn is not None and stmt.insn.startswith('PUSH'):
                                if isinstance(stmt.rhs, StoreExp):
                                    if isinstance(stmt.rhs.exp, RegVar):
                                        pushed_regs.add(stmt.rhs.exp.name)
                                    elif isinstance(stmt.rhs.exp, VirtualVar):
                                        pushed_virtual_vars.add((stmt.rhs.exp.name, stmt.rhs.exp.index))
                                elif isinstance(stmt.lhs, VirtualVar) \
                                        and isinstance(stmt.rhs, RegVar) \
                                        and (stmt.lhs.name, stmt.lhs.index) in pushed_virtual_vars:
                                    pushed_regs.add(stmt.rhs.name)

                        pushed_regs = frozenset(pushed_regs)
                        if pushed_regs in reg_to_offset:
                            self.fun_arg_offset += reg_to_offset[pushed_regs]
                        else:
                            pass

                    if self.fun_arg_offset is not None:
                        break
                if self.fun_arg_offset is not None:
                    break

            if self.fun_arg_offset is None and len(self.bap.blks) > 0:
                blk = self.bap.blks[0]
                pushed_regs = set()
                pushed_virtual_vars = set()
                for stmt in reversed(blk.stmts):
                    if isinstance(stmt, DefStmt) and stmt.insn is not None and stmt.insn.startswith('PUSH'):
                        if isinstance(stmt.rhs, StoreExp):
                            if isinstance(stmt.rhs.exp, RegVar):
                                pushed_regs.add(stmt.rhs.exp.name)
                            elif isinstance(stmt.rhs.exp, VirtualVar):
                                pushed_virtual_vars.add((stmt.rhs.exp.name, stmt.rhs.exp.index))
                        elif isinstance(stmt.lhs, VirtualVar) \
                                and isinstance(stmt.rhs, RegVar) \
                                and (stmt.lhs.name, stmt.lhs.index) in pushed_virtual_vars:
                            pushed_regs.add(stmt.rhs.name)

                pushed_regs = frozenset(pushed_regs)
                if pushed_regs in reg_to_offset:
                    self.fun_arg_offset = reg_to_offset[pushed_regs]
                else:
                    pass

        pushed_regs = frozenset(pushed_regs)
        if pushed_regs in reg_to_offset:
            if self.fun_arg_offset is None:
                self.fun_arg_offset = reg_to_offset[pushed_regs]
            else:
                self.fun_arg_offset += reg_to_offset[pushed_regs]
        else:
            pass

        if self.fun_arg_offset is not None:
            for offset in self.indirect_offsets.values():
                for indirect_offset in offset.values():
                    if indirect_offset.base_pointer == 'ESP' and indirect_offset.offset >= self.fun_arg_offset:
                        indirect_offset.var_type = FUN_ARG

            # for reg in self.regs.values():
            #     if reg.name not in pushed_regs and reg.index == 0:
            #         reg.var_type = FUN_ARG
            #         reg.low_pc = self.low_pc

    def add_callee(self, callee):
        self.callees.add(callee)

    def add_caller(self, caller):
        self.callers.add(caller)

    def dump_debug(self):
        print('function {}'.format(repr(self)))
        print('function {}'.format(str(self)))
        for blk_tid in sorted(self.blks.keys()):
            blk = self.blks[blk_tid]
            print('blk {}'.format(blk_tid))
            for stmt in blk.stmts:
                pc = format(stmt.pc, '02x') if stmt.pc is not None else None
                print('{} {} raw: {}'.format(pc, stmt.insn, repr(stmt)))
                print('{} {} debug: {}'.format(pc, stmt.insn, str(stmt)))
            print()
        print()

    def stat(self):
        Function.total += 1
        if self.is_name_given:
            Function.giv += 1
        else:
            Function.inf += 1
            if self.train_name != UNKNOWN_LABEL:
                Function.known += 1
            else:
                Function.unknown += 1

    def add_frame_bases(self, frame_base_attr, cu_low_pc):
        if not self.frame_bases_added:
            self.frame_bases_added = True
            self.frame_bases = []
            if frame_base_attr is None:
                self.frame_bases = []
            else:
                form = frame_base_attr.form
                loc = frame_base_attr.value
                if (form == 'DW_FORM_exprloc' or form == 'DW_FORM_block1') and loc[0] >= ENUM_DW_FORM_exprloc['DW_OP_breg0'] and loc[0] <= ENUM_DW_FORM_exprloc['DW_OP_breg31'] and (loc[0] - ENUM_DW_FORM_exprloc['DW_OP_breg0']) in self.binary.config.REG_MAPPING:
                    loc_reg = self.binary.config.REG_MAPPING[loc[0] - ENUM_DW_FORM_exprloc['DW_OP_breg0']]
                    loc_offset = decode_sleb128(loc[1:])
                    self.frame_bases = [FrameBase(base_register=loc_reg, offset=loc_offset, low_pc=0, high_pc=self.binary.config.HIGH_PC)]
                elif (form == 'DW_FORM_exprloc' or form == 'DW_FORM_block1') and loc[0] >= ENUM_DW_FORM_exprloc['DW_OP_reg0'] and loc[0] <= ENUM_DW_FORM_exprloc['DW_OP_reg31'] and (loc[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']) in self.binary.config.REG_MAPPING:
                    loc_reg = self.binary.config.REG_MAPPING[loc[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']]
                    self.frame_bases = [FrameBase(base_register=loc_reg, offset=0, low_pc=0, high_pc=self.binary.config.HIGH_PC)]
                elif form == 'DW_FORM_exprloc' and len(loc) == 1 and loc[0] == ENUM_DW_FORM_exprloc['DW_OP_call_frame_cfa']:
                    for frame_base in self.binary.debug_info.call_frames:
                        if not (frame_base.low_pc > self.high_pc + self.low_pc or self.low_pc > frame_base.high_pc):
                            self.frame_bases.append(frame_base)
                elif form == 'DW_FORM_sec_offset' or form == 'DW_FORM_data4':
                    loc_list = self.binary.debug_info.location_lists.get_location_list_at_offset(loc)
                    for loc_entry in loc_list:
                        if isinstance(loc_entry, LocationEntry):
                            entry_low_pc = loc_entry.begin_offset + cu_low_pc
                            entry_high_pc = loc_entry.end_offset + cu_low_pc
                            entry_loc_expr = loc_entry.loc_expr
                            if entry_loc_expr[0] >= ENUM_DW_FORM_exprloc['DW_OP_breg0'] and entry_loc_expr[0] <= ENUM_DW_FORM_exprloc['DW_OP_breg31'] and (entry_loc_expr[0] - ENUM_DW_FORM_exprloc['DW_OP_breg0']) in self.binary.config.REG_MAPPING:
                                loc_reg = self.binary.config.REG_MAPPING[entry_loc_expr[0] - ENUM_DW_FORM_exprloc['DW_OP_breg0']]
                                loc_offset = decode_sleb128(entry_loc_expr[1:])
                                self.frame_bases.append(FrameBase(base_register=loc_reg, offset=loc_offset, low_pc=entry_low_pc, high_pc=entry_high_pc))
                            elif entry_loc_expr[0] >= ENUM_DW_FORM_exprloc['DW_OP_reg0'] and entry_loc_expr[0] <= ENUM_DW_FORM_exprloc['DW_OP_reg31'] and (entry_loc_expr[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']) in self.binary.config.REG_MAPPING:
                                loc_reg = self.binary.config.REG_MAPPING[entry_loc_expr[0] - ENUM_DW_FORM_exprloc['DW_OP_reg0']]
                                loc_offset = decode_sleb128(entry_loc_expr[1:])
                                self.frame_bases.append(FrameBase(base_register=loc_reg, offset=loc_offset, low_pc=entry_low_pc, high_pc=entry_high_pc))
                            else:
                                pass
                else:
                    pass
            self.frame_bases = sorted(self.frame_bases, key=lambda f: f.low_pc)

    def debug_info(self):
        bs = bytearray()

        if self.ttype.test_name is None \
                or self.ttype.test_name in (UNKNOWN_LABEL, VOID) \
                or self.ttype.test_name not in TTYPES:
            bs.append(ENUM_ABBREV_CODE['SUBPROGRAM_VOID'])
        else:
            bs.append(ENUM_ABBREV_CODE['SUBPROGRAM'])

        bs.extend(map(ord, self.test_name))
        bs.append(0x00)

        if self.test_name not in TTYPES \
                and self.test_name != UNKNOWN_LABEL \
                and self.test_name not in self.binary.sections.symbol_names:
            self.binary.predicted.add(self.test_name)

        if self.ttype.test_name is not None \
                and self.ttype.test_name not in (UNKNOWN_LABEL, VOID) \
                and self.ttype.test_name in TTYPES:
            bs += utils.encode_kbytes(self.binary.types.get_offset(self.ttype.test_name), 4)

        bs += encode_address(self.low_pc, self.binary)

        bs += encode_address(self.high_pc - self.low_pc, self.binary)

        locs = []

        for off in self.indirect_offsets.values():
            for indirect_offset in off.values():
                if indirect_offset.n2p_type == self.binary.config.INF \
                        and indirect_offset.test_name is not None \
                        and indirect_offset.test_name != UNKNOWN_LABEL \
                        and len(indirect_offset.pcs) > 0:
                    locs.append(indirect_offset)

        for reg in self.regs.values():
            if reg.n2p_type == self.binary.config.INF \
                    and reg.test_name is not None \
                    and reg.test_name != UNKNOWN_LABEL \
                    and len(reg.pcs) > 0:
                locs.append(reg)

        variables = make_variables(locs, self.binary)
        fun_args = list(filter(lambda v: v.var_type == FUN_ARG, variables))
        loc_vars = list(filter(lambda v: v.var_type == LOC_VAR, variables))

        if self.binary.config.MACHINE_ARCH == 'x86':
            fun_args = sorted(fun_args, key=lambda v: v.fun_arg_loc)
            for fun_arg in fun_args:
                bs += fun_arg.debug_info()
        elif self.binary.config.MACHINE_ARCH == 'x64':
            for reg in X64_FUN_ARG_REGS:
                args = list(filter(lambda v: v.fun_arg_loc == reg, fun_args))
                for arg in args:
                    bs += arg.debug_info()
        elif self.binary.config.MACHINE_ARCH == 'ARM':
            for reg in ARM_FUN_ARG_REGS:
                args = list(filter(lambda v: v.fun_arg_loc == reg, fun_args))
                for arg in args:
                    bs += arg.debug_info()

        loc_vars = sorted(loc_vars, key=lambda v: v.low_pc)

        for var in loc_vars:
            bs += var.debug_info()

        bs.append(0x00)

        return bs
