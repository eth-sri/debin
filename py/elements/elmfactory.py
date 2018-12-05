import sys
import traceback

from common.constants import GIV_REGS, TEXT
from common.visitors import StmtVisitor, ExpVisitor

from elements.regs import GivReg, Reg, RegBase
from elements.offsets import DirectOffset, IndirectOffset, GivOffset, StringArrayOffset, TempOffset
from elements.givs import IntConst, StringConst, Flag, Insn, CodeOffset
from elements.givs import VirtualElm, VirtualExp, SwitchTable, NodeType
from elements.givs import OpNode, OtherVarNode, SizeNode, UnknownNode

from bap.vars import VirtualVar, RegVar, FlagVar, MemVar, OtherVar
from bap.exps import LoadExp, StoreExp, BinOpExp, UnOpExp, CastExp
from bap.exps import IntExp, LetExp, UnknownExp, IteExp, ExtractExp, ConcatExp
from bap.stmts import DefStmt, JmpStmt, PhiStmt
from bap.stmts import DirectLabel, IndirectLabel, CallKind, GotoKind, RetKind, IntentKind


class ExpInitializer(ExpVisitor):
    def visit_load_exp(self, exp, *args, **kwargs):
        self.visit(exp.addr, *args, **kwargs)

    def visit_store_exp(self, exp, *args, **kwargs):
        self.visit(exp.addr, *args, **kwargs)
        self.visit(exp.exp, *args, **kwargs)

    def visit_binop_exp(self, exp, *args, **kwargs):
        self.visit(exp.e1, *args, **kwargs)
        self.visit(exp.e2, *args, **kwargs)

    def visit_unop_exp(self, exp, *args, **kwargs):
        self.visit(exp.e, *args, **kwargs)

    def visit_cast_exp(self, exp, *args, **kwargs):
        self.visit(exp.e, *args, **kwargs)

    def visit_int_exp(self, exp, *args, **kwargs):
        pass

    def visit_let_exp(self, exp, *args, **kwargs):
        self.visit(exp.v, *args, **kwargs)
        self.visit(exp.head, *args, **kwargs)
        self.visit(exp.body, *args, **kwargs)

    def visit_unknown_exp(self, exp, *args, **kwargs):
        pass

    def visit_ite_exp(self, exp, *args, **kwargs):
        self.visit(exp.cond, *args, **kwargs)
        self.visit(exp.yes, *args, **kwargs)
        self.visit(exp.no, *args, **kwargs)

    def visit_extract_exp(self, exp, *args, **kwargs):
        self.visit(exp.e, *args, **kwargs)

    def visit_concat_exp(self, exp, *args, **kwargs):
        self.visit(exp.e1, *args, **kwargs)
        self.visit(exp.e2, *args, **kwargs)

    def visit_virtual_var(self, exp, *args, **kwargs):
        pass

    def visit_reg_var(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        function = blk.function
        key = (exp.name, exp.index)

        if pc is not None:
            if not kwargs['is_lhs']:
                if key not in function.reg_pcs:
                    function.reg_pcs[key] = set()
                function.reg_pcs[key].add(pc)
        # if pc is not None:
        #     if kwargs['is_lhs']:
        #         function.reg_def_pc[key] = pc
        #     elif key in function.reg_def_pc \
        #             and pc != function.reg_def_pc[key]:
        #         if key not in function.reg_pcs:
        #             function.reg_pcs[key] = set()
        #         function.reg_pcs[key].add(pc)

    def visit_flag_var(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        function = blk.function
        key = (exp.name, exp.index)

        if pc is not None:
            if not kwargs['is_lhs']:
                if key not in function.flag_pcs:
                    function.flag_pcs[key] = set()
                function.flag_pcs[key].add(pc)

    def visit_mem_var(self, exp, *args, **kwargs):
        pass

    def visit_other_var(self, exp, *args, **kwargs):
        pass


EXP_INITIALIZER = ExpInitializer()


class StmtInitializer(StmtVisitor):

    def visit_def(self, stmt, *args, **kwargs):
        EXP_INITIALIZER.visit(stmt.lhs, is_lhs=True, *args, **kwargs)
        EXP_INITIALIZER.visit(stmt.rhs, is_lhs=False, *args, **kwargs)
        if isinstance(stmt.lhs, VirtualVar):
            make_virtual(stmt, blk=kwargs['blk'], pc=kwargs['pc'])

    def visit_phi(self, stmt, *args, **kwargs):
        EXP_INITIALIZER.visit(stmt.lhs, is_lhs=True, *args, **kwargs)
        for rhs in stmt.rhs:
            EXP_INITIALIZER.visit(rhs, is_lhs=False, *args, **kwargs)

    def visit_jmp(self, stmt, *args, **kwargs):
        cond = stmt.cond
        kind = stmt.kind
        EXP_INITIALIZER.visit(cond, is_lhs=False, *args, **kwargs)
        if isinstance(kind, CallKind):
            target = kind.target
            if isinstance(target, IndirectLabel):
                EXP_INITIALIZER.visit(target.exp, is_lhs=False, *args, **kwargs)
            rtn = kind.rtn
            if isinstance(rtn, IndirectLabel):
                EXP_INITIALIZER.visit(rtn.exp, is_lhs=False, *args, **kwargs)
        elif isinstance(kind, GotoKind) or isinstance(kind, RetKind):
            label = kind.label
            if isinstance(label, IndirectLabel):
                EXP_INITIALIZER.visit(label.exp, is_lhs=False, *args, **kwargs)


STMT_INITIALIZER = StmtInitializer()


class ExpTransformer(ExpVisitor):
    def visit_load_exp(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        self.visit(exp.addr, *args, **kwargs)
        base_pointer, offset, access = mem_addr(exp.addr, blk, pc)
        return make_mem(exp.addr, base_pointer, offset, blk, pc, access)

    def visit_store_exp(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        self.visit(exp.addr, *args, **kwargs)
        base_pointer, offset, access = mem_addr(exp.addr, blk, pc)
        lhs = make_mem(exp.addr, base_pointer, offset, blk, pc, access)
        rhs = self.visit(exp.exp, *args, **kwargs)
        return lhs, rhs

    def visit_binop_exp(self, exp, *args, **kwargs):
        e1 = self.visit(exp.e1, *args, **kwargs)
        e2 = self.visit(exp.e2, *args, **kwargs)
        return BinOpExp(op=exp.op, e1=e1, e2=e2, t=exp.t)

    def visit_unop_exp(self, exp, *args, **kwargs):
        e = self.visit(exp.e, *args, **kwargs)
        return UnOpExp(op=exp.op, e=e, t=exp.t)

    def visit_cast_exp(self, exp, *args, **kwargs):
        e = self.visit(exp.e, *args, **kwargs)
        return CastExp(kind=exp.kind, size=exp.size, e=e, t=exp.t)

    def visit_int_exp(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        binary = blk.binary
        value = exp.value
        if 'allint' in kwargs and kwargs['allint']:
            return make_int_const(value, exp.width, blk, pc)
        elif binary.sections.is_in_bss_sec(value) \
                or binary.sections.is_in_data_sec(value) \
                or binary.sections.is_in_rodata_sec(value) \
                or binary.sections.is_in_text_sec(value) \
                or binary.sections.is_in_plt_sec(value):
            return make_mem(exp, None, value, blk, pc, None)
        else:
            return make_int_const(value, exp.width, blk, pc)

    def visit_let_exp(self, exp, *args, **kwargs):
        v = self.visit(exp.v, *args, **kwargs)
        head = self.visit(exp.head, *args, **kwargs)
        body = self.visit(exp.body, *args, **kwargs)
        return LetExp(v=v, head=head, body=body, t=exp.t)

    def visit_unknown_exp(self, exp, *args, **kwargs):
        return make_unknown_node(kwargs['blk'].binary)

    def visit_ite_exp(self, exp, *args, **kwargs):
        cond = self.visit(exp.cond, *args, **kwargs)
        yes = self.visit(exp.yes, *args, **kwargs)
        no = self.visit(exp.no, *args, **kwargs)
        return IteExp(cond=cond, yes=yes, no=no, t=exp.t)

    def visit_extract_exp(self, exp, *args, **kwargs):
        e = self.visit(exp.e, *args, **kwargs)
        return ExtractExp(hi=exp.hi, lo=exp.lo, e=e, t=exp.t)

    def visit_concat_exp(self, exp, *args, **kwargs):
        e1 = self.visit(exp.e1, *args, **kwargs)
        e2 = self.visit(exp.e2, *args, **kwargs)
        return ConcatExp(e1=e1, e2=e2, t=exp.t)

    def visit_virtual_var(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        return get_virtual_exp(exp, blk)

    def visit_reg_var(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        return make_reg(exp.name, exp.index, blk, pc, False)

    def visit_flag_var(self, exp, *args, **kwargs):
        blk = kwargs['blk']
        return make_flag(exp.name, exp.index, blk)

    def visit_mem_var(self, exp, *args, **kwargs):
        return exp

    def visit_other_var(self, exp, *args, **kwargs):
        return make_othervar_node(exp.name, kwargs['blk'])


EXP_TRANSFORMER = ExpTransformer()


class StmtTransformer(StmtVisitor):
    def visit_def(self, stmt, *args, **kwargs):
        blk = kwargs['blk']
        pc = kwargs['pc']
        if stmt.insn is not None:
            make_insn(stmt.insn, blk)

        if type(stmt.lhs) in (VirtualVar, OtherVar):
            lhs = stmt.lhs
            rhs = EXP_TRANSFORMER.visit(stmt.rhs, *args, **kwargs)
            return None
        else:
            if isinstance(stmt.lhs, RegVar):
                lhs = make_reg(stmt.lhs.name, stmt.lhs.index, blk, pc, True)
                rhs = EXP_TRANSFORMER.visit(stmt.rhs, *args, **kwargs) 
                key = (lhs.base_register, lhs.index)
                blk.function.reg_defs[key] = rhs
            elif isinstance(stmt.lhs, FlagVar):
                key = (stmt.lhs.name, stmt.lhs.index)
                rhs = EXP_TRANSFORMER.visit(stmt.rhs, *args, **kwargs)
                if key in blk.function.flag_pcs:
                    blk.function.flag_defs[key] = rhs
                    lhs = make_flag(stmt.lhs.name, stmt.lhs.index, blk)
                else:
                    return None
            elif isinstance(stmt.lhs, MemVar):
                lhs, rhs = EXP_TRANSFORMER.visit(stmt.rhs, *args, **kwargs)
            # elif isinstance(stmt.lhs, OtherVar):
            #     lhs = stmt.lhs
            #     rhs = EXP_TRANSFORMER.visit(stmt.rhs, blk=blk, pc=pc)
            return DefStmt(lhs=lhs, rhs=rhs, t=stmt.t, tid=stmt.tid, insn=stmt.insn, pc=stmt.pc)

    def visit_phi(self, stmt, *args, **kwargs):
        blk = kwargs['blk']
        if stmt.insn is not None:
            make_insn(stmt.insn, blk)

        if type(stmt.lhs) in (MemVar, OtherVar):
            return None
        elif isinstance(stmt.lhs, VirtualVar):
            lhs = stmt.lhs
            rhs = stmt.rhs
            return None
        else:
            if isinstance(stmt.lhs, RegVar):
                lhs = EXP_TRANSFORMER.visit(stmt.lhs, *args, **kwargs)
                rhs = [EXP_TRANSFORMER.visit(r, *args, **kwargs) for r in stmt.rhs]
                key = (lhs.base_register, lhs.index)
                blk.function.reg_defs[key] = rhs
            elif isinstance(stmt.lhs, FlagVar):
                key = (stmt.lhs.name, stmt.lhs.index)
                if key in blk.function.flag_pcs:
                    lhs = make_flag(stmt.lhs.name, stmt.lhs.index, blk)
                    rhs = [EXP_TRANSFORMER.visit(r, *args, **kwargs) for r in stmt.rhs]
                    blk.function.flag_defs[key] = rhs
                else:
                    return None
            # elif isinstance(stmt.lhs, OtherVar):
            #     lhs = stmt.lhs
            #     rhs = stmt.rhs
            return PhiStmt(lhs=lhs, rhs=rhs, t=stmt.t, tid=stmt.tid, insn=stmt.insn, pc=stmt.pc)

    def visit_jmp(self, stmt, *args, **kwargs):
        blk = kwargs['blk']
        if stmt.insn is not None:
            make_insn(stmt.insn, blk)

        cond = EXP_TRANSFORMER.visit(stmt.cond, *args, **kwargs)
        kind = stmt.kind
        if isinstance(kind, CallKind):
            target = kind.target
            if isinstance(target, IndirectLabel):
                exp = EXP_TRANSFORMER.visit(target.exp, *args, **kwargs)
                target = IndirectLabel(exp=exp, t=target.t)
            elif isinstance(target, DirectLabel):
                target = blk.binary.functions.get_function_by_tid(target.target_tid)
            rtn = kind.rtn
            if isinstance(rtn, IndirectLabel):
                exp = EXP_TRANSFORMER.visit(rtn.exp, *args, **kwargs)
                rtn = IndirectLabel(exp=exp, t=rtn.t)
            args = dict()
            for key, value in kind.args.items():
                args[key] = EXP_TRANSFORMER.visit(value[0], blk=blk, pc=value[1])
            kind = CallKind(target=target, rtn=rtn, args=args, t=kind.t)
        elif isinstance(kind, GotoKind):
            label = kind.label
            if isinstance(label, IndirectLabel):
                exp = EXP_TRANSFORMER.visit(label.exp, *args, **kwargs)
                label = IndirectLabel(exp=exp, t=label.t)
            kind = GotoKind(label=label, t=kind.t)
        elif isinstance(kind, RetKind):
            label = kind.label
            if isinstance(label, IndirectLabel):
                exp = EXP_TRANSFORMER.visit(label.exp, *args, **kwargs)
                label = IndirectLabel(exp=exp, t=label.t)
            kind = RetKind(label=label, t=kind.t)
        elif isinstance(kind, IntentKind):
            kind = kind

        return JmpStmt(cond=cond, kind=kind, t=stmt.t, tid=stmt.tid, insn=stmt.insn, pc=stmt.pc)


STMT_TRANSFORMER = StmtTransformer()


def mem_addr(addr, blk, pc):
    binary = blk.binary
    if isinstance(addr, BinOpExp) \
            and isinstance(addr.e2, IntExp) \
            and addr.op in ('PLUS', 'MINUS'):
        if isinstance(addr.e1, RegVar):
            base_pointer = make_reg(addr.e1.name, addr.e1.index, blk, pc, False)
            if addr.op == 'PLUS':
                offset = addr.e2.value
                return base_pointer, offset, None
            elif addr.op == 'MINUS':
                offset = -addr.e2.value
                return base_pointer, offset, None
            else:
                return None, None, None
        elif isinstance(addr.e1, CastExp):
            reg = addr.e1
            while hasattr(reg, 'e'):
                reg = reg.e
            if isinstance(reg, RegVar):
                base_pointer = make_reg(reg.name, reg.index, blk, pc, False)
                if addr.op == 'PLUS':
                    offset = addr.e2.value
                    return base_pointer, offset, None
                elif addr.op == 'MINUS':
                    offset = -addr.e2.value
                    return base_pointer, offset, None
                else:
                    return None, None, None
        elif isinstance(addr.e1, VirtualVar):
            name = addr.e1.name
            index = addr.e1.index
            key = (name, index)
            function = blk.function
            if key in function.virtual_exps:
                virtual_exp = function.virtual_exps[key]
                if isinstance(virtual_exp.exp, RegBase):
                    base_pointer = virtual_exp.exp
                    if addr.op == 'PLUS':
                        offset = addr.e2.value
                        return base_pointer, offset, None
                    elif addr.op == 'MINUS':
                        offset = -addr.e2.value
                        return base_pointer, offset, None
                    else:
                        return None, None, None
                elif isinstance(virtual_exp.exp, BinOpExp) \
                        and isinstance(virtual_exp.exp.e1, RegBase) \
                        and isinstance(virtual_exp.exp.e2, IntConst):
                    base_pointer = virtual_exp.exp.e1
                    if addr.op == 'PLUS':
                        offset = addr.e2.value
                    elif addr.op == 'MINUS':
                        offset = -addr.e2.value
                    else:
                        return None, None, None
                    if virtual_exp.exp.op == 'PLUS':
                        offset += virtual_exp.exp.e2.value
                        return base_pointer, offset, None
                    elif virtual_exp.exp.op == 'MINUS':
                        offset -= virtual_exp.exp.e2.value
                        return base_pointer, offset, None
                    else:
                        return None, None, None
                else:
                    return None, None, None
            else:
                return None, None, None
        elif isinstance(addr.e1, BinOpExp):
            binary = blk.binary
            offset = addr.e2.value
            if isinstance(addr.e1.e1, IntExp) \
                    and isinstance(addr.e1.e2, IntExp):
                if addr.e1.op == 'PLUS':
                    offset = addr.e1.e1.value + addr.e1.e2.value
                elif addr.e1.op == 'MINUS':
                    offset = addr.e1.e1.value - addr.e1.e2.value

                if addr.op == 'PLUS':
                    offset += addr.e2.value
                elif addr.op == 'MINUS':
                    offset -= addr.e2.value

                return None, offset, None
            else:
                access = EXP_TRANSFORMER.visit(addr.e1, blk=blk, pc=pc)
                if binary.config.MACHINE_ARCH == 'ARM':
                    offset = binary.sections.sections[TEXT].get_data_offset(offset)
                return None, offset, access
        elif isinstance(addr.e1, IntExp):
            offset = None
            if addr.op == 'PLUS':
                offset = addr.e1.value + addr.e2.value
            elif addr.op == 'MINUS':
                offset = addr.e1.value - addr.e2.value
            return None, offset, None
        else:
            return None, addr.e2.value, None
    elif isinstance(addr, RegVar):
        base_pointer = make_reg(addr.name, addr.index, blk, pc, False)
        offset = 0
        return base_pointer, offset, None
    elif isinstance(addr, CastExp):
        reg = addr
        while hasattr(reg, 'e'):
            reg = reg.e
        if isinstance(reg, RegVar):
            base_pointer = make_reg(reg.name, reg.index, blk, pc, False)
            offset = 0
            return base_pointer, offset, None
        else:
            return None, None, None
    elif isinstance(addr, VirtualVar):
        name = addr.name
        index = addr.index
        key = (name, index)
        function = blk.function
        if key in function.virtual_exps:
            virtual_exp = function.virtual_exps[key]
            if isinstance(virtual_exp.exp, RegBase):
                offset = 0
                base_pointer = virtual_exp.exp
                return base_pointer, offset, None
            elif isinstance(virtual_exp.exp, BinOpExp) \
                    and isinstance(virtual_exp.exp.e1, RegBase) \
                    and isinstance(virtual_exp.exp.e2, IntConst):
                if virtual_exp.exp.op == 'PLUS':
                    offset = virtual_exp.exp.e2.value
                    base_pointer = virtual_exp.exp.e1
                    return base_pointer, offset, None
                elif virtual_exp.exp.op == 'MINUS':
                    offset = -virtual_exp.exp.e2.value
                    base_pointer = virtual_exp.exp.e1
                    return base_pointer, offset, None
                else:
                    return None, None, None
            else:
                return None, None, None
        else:
            return None, None, None
    elif isinstance(addr, IntExp):
        binary = blk.binary
        offset = addr.value
        if binary.config.MACHINE_ARCH == 'ARM':
            offset = binary.sections.sections[TEXT].get_data_offset(offset)
        return None, offset, None
    else:
        return None, None, None


def make_mem(addr, base_pointer, offset, blk, pc, access=None):
    binary = blk.binary
    if base_pointer is not None and offset is not None:
        return make_indirect_offset(addr, base_pointer, offset, blk, pc)
    elif base_pointer is not None and offset is None:
        return make_indirect_offset(addr, base_pointer, 0, blk, pc)
    elif base_pointer is None and offset is not None:
        binary = blk.binary
        if binary.sections.is_in_gotplt_sec(offset):
            offset = binary.sections.get_gotplt_offset(offset)
        if binary.sections.is_in_bss_sec(offset) \
                or binary.sections.is_in_data_sec(offset):
            return make_direct_offset(offset, blk, pc, access)
        elif binary.sections.is_in_rodata_sec(offset):
            rodata_addrs = binary.sections.get_rodata_addrs(offset)
            text_addrs = binary.sections.get_text_addrs(offset)
            if len(rodata_addrs) > 0:
                rodata_strs = list(map(binary.sections.get_rodata_string, rodata_addrs))
                if all([s is None for s in rodata_strs]):
                    return make_direct_offset(offset, blk, pc, access)
                else:
                    return make_string_array(offset, blk, pc, access)
            elif len(text_addrs) > 0:
                return make_switch_table(offset, blk, pc, access)
            else:
                str_value = binary.sections.get_rodata_string(offset)
                if str_value is None:
                    return make_direct_offset(offset, blk, pc, access)
                else:
                    return make_string_const(offset, blk, pc, access)
        elif binary.sections.is_in_text_sec(offset) \
                or binary.sections.is_in_plt_sec(offset):
            return make_code_offset(offset, blk, access)
        elif access is not None:
            return make_giv_offset(addr, blk, pc, access)
        else:
            if binary.config.MACHINE_ARCH == 'ARM':
                return make_int_const(offset, 32, blk, pc)
            elif binary.config.MACHINE_ARCH == 'x86':
                return make_int_const(offset, 32, blk, pc)
            elif binary.config.MACHINE_ARCH == 'x64':
                return make_int_const(offset, 64, blk, pc)
    elif base_pointer is None and offset is None:
        return make_giv_offset(addr, blk, pc, access)


def get_virtual_exp(var_bap, blk):
    function = blk.function
    key = (var_bap.name, var_bap.index)
    if key in function.virtual_exps:
        return function.virtual_exps[key]
    else:
        return var_bap


def make_virtual(stmt_bap, blk, pc):
    function = blk.function
    binary = blk.binary
    lhs = stmt_bap.lhs
    name = lhs.name
    index = lhs.index

    if name in binary.virtual_elms:
        virtual_elm = binary.virtual_elms[name]
    else:
        virtual_elm = VirtualElm(binary=binary, name=name)
        binary.virtual_elms[name] = virtual_elm

    function.virtual_elms.add(name)

    key = (name, index)
    if key not in function.virtual_exps:
        rhs = stmt_bap.rhs
        virtual_exp = VirtualExp(name=name, index=index, exp=rhs, elm=virtual_elm, blk=blk, pc=pc)
        function.virtual_exps[key] = virtual_exp


def make_reg(base_register, index, blk, pc, is_lhs):
    function = blk.function
    binary = function.binary

    key = (base_register, index)
    if base_register in GIV_REGS \
            or base_register not in binary.config.REG_MAPPING \
            or key not in function.reg_pcs:
        reg = make_giv_reg(base_register, index, blk, pc)
    elif key in binary.giv_regs \
            and pc in binary.giv_regs[key].pcs:
        reg = binary.giv_regs[key]
    else:
        if key in function.regs:
            reg = function.regs[key]
        else:
            reg = Reg(base_register=base_register, index=index, function=function)
            function.regs[key] = reg

        if pc is not None and not is_lhs:
            reg.add_pc(pc)

        reg.blks.add(blk.tid)

    return reg


def make_giv_reg(base_register, index, blk, pc):
    function = blk.function
    binary = function.binary

    key = (base_register, index)
    if key in binary.giv_regs:
        reg = binary.giv_regs[key]
    else:
        reg = GivReg(base_register=base_register, index=index, binary=binary)
        binary.giv_regs[key] = reg

    function.giv_regs.add(key)

    if pc is not None:
        reg.add_pc(pc)

    return reg


def make_temp_offset(base_pointer, offset, blk, pc):
    binary = blk.binary
    key = (base_pointer, offset)

    if key in binary.temp_offsets:
        temp_offset = binary.temp_offsets[key]
    else:
        temp_offset = TempOffset(base_pointer=base_pointer, offset=offset, binary=binary)
        binary.temp_offsets[key] = temp_offset

    if pc is not None:
        temp_offset.add_pc(pc)

    return temp_offset


def make_giv_offset(addr_bap, blk, pc, access=None):
    function = blk.function
    binary = blk.binary
    exp = EXP_TRANSFORMER.visit(addr_bap, blk=blk, pc=pc, allint=True)

    key = exp.str_noindex()
    if key in binary.giv_offsets:
        giv_offset = binary.giv_offsets[key]
    else:
        giv_offset = GivOffset(offset=key, exp=exp, binary=binary, access=access)
        binary.giv_offsets[key] = giv_offset

    function.giv_offsets.add(key)

    return giv_offset


def make_direct_offset(offset, blk, pc, access=None):
    # if offset < 100000:
    #     print(offset)
    #     traceback.print_stack(file=sys.stdout)
    function = blk.function
    binary = function.binary

    if offset in binary.direct_offsets:
        direct_offset = binary.direct_offsets[offset]
    else:
        direct_offset = DirectOffset(binary=binary, offset=offset, access=access)
        binary.direct_offsets[offset] = direct_offset

    function.direct_offsets.add(offset)

    return direct_offset


def make_indirect_offset(addr_bap, base_pointer, offset, blk, pc):
    function = blk.function
    binary = function.binary
    base_register = base_pointer.base_register
    if binary.config.INDIRECT_OFFSET_WITH_INDEX:
        index = base_pointer.index
    else:
        index = 0
    key = (base_register, offset)

    if binary.config.MACHINE_ARCH == 'ARM':
        new_offset = binary.sections.sections[TEXT].get_data_offset(offset)
    else:
        new_offset = offset

    if binary.sections.is_in_rodata_sec(new_offset):
        rodata_addrs = binary.sections.get_rodata_addrs(new_offset)
        text_addrs = binary.sections.get_text_addrs(new_offset)
        if len(rodata_addrs) > 0:
            rodata_strs = list(map(binary.sections.get_rodata_string, rodata_addrs))
            if all([s is None for s in rodata_strs]):
                return make_direct_offset(offset, blk, pc)
            else:
                return make_string_array(offset, blk, pc)
        elif len(text_addrs) > 0:
            return make_switch_table(new_offset, blk, pc, base_pointer)
        else:
            str_value = binary.sections.get_rodata_string(new_offset)
            if str_value is None:
                return make_direct_offset(new_offset, blk, pc, base_pointer)
            else:
                return make_string_const(new_offset, blk, pc, base_pointer)
    elif binary.sections.is_in_data_sec(new_offset) \
            or binary.sections.is_in_bss_sec(new_offset):
        return make_direct_offset(new_offset, blk, pc, base_pointer)
    elif key in binary.temp_offsets \
            and pc is not None \
            and pc in binary.temp_offsets[key].pcs:
        return binary.temp_offsets[key]
    elif base_register not in binary.config.REG_MAPPING:
        return make_giv_offset(addr_bap, blk, pc)
    else:
        if key in function.indirect_offsets:
            offsets = function.indirect_offsets[key]
            if index in offsets:
                indirect_offset = offsets[index]
            else:
                indirect_offset = IndirectOffset(function=function, base_pointer=base_register, offset=offset, index=index)
                offsets[index] = indirect_offset
        else:
            indirect_offset = IndirectOffset(function=function, base_pointer=base_register, offset=offset, index=index)
            function.indirect_offsets[key] = dict()
            function.indirect_offsets[key][index] = indirect_offset

        if pc is not None:
            indirect_offset.add_pc(pc)

        indirect_offset.blks.add(blk.tid)

    return indirect_offset


def make_int_const(value, width, blk, pc):
    function = blk.function
    binary = blk.binary

    key = (value, width)
    if key in binary.int_consts:
        int_const = binary.int_consts[key]
    else:
        int_const = IntConst(value=value, width=width, binary=binary)
        binary.int_consts[key] = int_const

    function.int_consts.add(key)

    return int_const


def make_switch_table(offset, blk, pc, access=None):
    function = blk.function
    binary = function.binary

    if offset in binary.switch_tables:
        switch_table = binary.switch_tables[offset]
    else:
        addrs = binary.sections.get_rodata_addrs(offset)
        locs = []
        for addr in addrs:
            if addr in binary.code_offsets:
                locs.append(binary.code_offsets[addr])
            else:
                target = binary.functions.get_function_by_pc(addr)
                loc = CodeOffset(binary=binary, target=target, offset=offset)
                binary.code_offsets[addr] = loc
                locs.append(loc)

        switch_table = SwitchTable(offset=offset, binary=binary, locs=locs, access=access)
        binary.switch_tables[offset] = switch_table

    function.switch_tables.add(offset)

    return switch_table


def make_string_array(offset, blk, pc, access=None):
    function = blk.function
    binary = function.binary

    if offset in binary.direct_offsets:
        string_array = binary.direct_offsets[offset]
    else:
        addrs = binary.sections.get_rodata_addrs(offset)
        strings = []
        for addr in addrs:
            if addr in binary.string_consts:
                strings.append(binary.string_consts[addr])
            else:
                value = binary.sections.get_rodata_string(addr)
                if value is not None:
                    string_const = StringConst(binary=binary, value=value, access=None, offset=addr)
                    binary.string_consts[addr] = string_const
                    strings.append(string_const)

        string_array = StringArrayOffset(binary=binary, offset=offset, access=access, strings=strings)
        binary.direct_offsets[offset] = string_array

    function.direct_offsets.add(offset)

    return string_array


def make_string_const(offset, blk, pc, access=None):
    function = blk.function
    binary = blk.binary

    if offset in binary.string_consts:
        string_const = binary.string_consts[offset]
    else:
        value = binary.sections.get_rodata_string(offset)
        string_const = StringConst(offset=offset, binary=binary, value=value, access=access)
        binary.string_consts[offset] = string_const

    function.string_consts.add(offset)

    return string_const


def make_flag(base_flag, index, blk):
    function = blk.function
    binary = blk.binary

    key = (base_flag, index)
    if key in binary.flags:
        flag = binary.flags[key]
    else:
        flag = Flag(base_flag=base_flag, index=index, binary=binary)
        binary.flags[key] = flag

    function.flags.add(key)

    return flag


def make_insn(insn_name, blk):
    function = blk.function
    binary = blk.binary

    if insn_name in binary.insns:
        insn = binary.insns[insn_name]
    else:
        insn = Insn(name=insn_name, binary=binary)
        binary.insns[insn_name] = insn

    function.insns.add(insn_name)

    return insn


def make_code_offset(offset, blk, access=None):
    function = blk.function
    binary = blk.binary
    target = binary.functions.get_function_by_pc(offset)

    key = offset
    if key in binary.code_offsets:
        code_offset = binary.code_offsets[key]
    else:
        code_offset = CodeOffset(binary=binary, target=target, offset=offset, access=access)
        binary.code_offsets[key] = code_offset

    function.code_offsets.add(key)

    return code_offset


def make_node_type(name, binary):
    if name in binary.node_types:
        node_type = binary.node_types[name]
    else:
        node_type = NodeType(binary=binary, name=name)
        binary.node_types[name] = node_type
    return node_type


def make_op_node(name, function):
    binary = function.binary
    if name in binary.op_nodes:
        op_node = binary.op_nodes[name]
    else:
        op_node = OpNode(binary=binary, name=name)
        binary.op_nodes[name] = op_node
    return op_node


def make_othervar_node(name, blk):
    binary = blk.binary
    if name in binary.othervar_nodes:
        othervar_node = binary.othervar_nodes[name]
    else:
        othervar_node = OtherVarNode(binary=binary, name=name)
        binary.othervar_nodes[name] = othervar_node
    return othervar_node


def make_size_node(size, binary):
    if size in binary.size_nodes:
        size_node = binary.size_nodes[size]
    else:
        size_node = SizeNode(binary=binary, size=size)
        binary.size_nodes[size] = size_node
    return size_node


def make_unknown_node(binary):
    if binary.unknown_node is None:
        binary.unknown_node = UnknownNode(binary=binary)
    return binary.unknown_node
