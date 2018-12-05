import abc

from bap.vars import VirtualVar, RegVar, FlagVar, MemVar, OtherVar
from bap.exps import LoadExp, StoreExp, BinOpExp, UnOpExp, CastExp
from bap.exps import IntExp, LetExp, UnknownExp, IteExp, ExtractExp, ConcatExp
from bap.stmts import DefStmt, JmpStmt, PhiStmt
from bap.stmts import DirectLabel, IndirectLabel, CallKind, GotoKind, RetKind, IntentKind

from elements.givs import IntConst, StringConst, SwitchTable, Flag, Insn
from elements.givs import CodeOffset, VirtualElm, VirtualExp, OtherVarNode
from elements.givs import UnknownNode
from elements.offsets import GivOffset, TempOffset, StringArrayOffset
from elements.offsets import DirectOffset, IndirectOffset
from elements.regs import GivReg, Reg
from elements.ttype import Ttype


class StmtVisitor:
    def visit(self, stmt, *args, **kwargs):
        if isinstance(stmt, DefStmt):
            return self.visit_def(stmt, *args, **kwargs)
        elif isinstance(stmt, PhiStmt):
            return self.visit_phi(stmt, *args, **kwargs)
        elif isinstance(stmt, JmpStmt):
            return self.visit_jmp(stmt, *args, **kwargs)

    @abc.abstractmethod
    def visit_def(self, stmt, *args, **kwargs):
        raise NotImplementedError('visit_def')

    @abc.abstractmethod
    def visit_phi(self, stmt, *args, **kwargs):
        raise NotImplementedError('visit_phi')

    @abc.abstractmethod
    def visit_jmp(self, stmt, *args, **kwargs):
        raise NotImplementedError('visit_jmp')


class ExpVisitor:
    def visit(self, exp, *args, **kwargs):
        if isinstance(exp, LoadExp):
            return self.visit_load_exp(exp, *args, **kwargs)
        elif isinstance(exp, StoreExp):
            return self.visit_store_exp(exp, *args, **kwargs)
        elif isinstance(exp, BinOpExp):
            return self.visit_binop_exp(exp, *args, **kwargs)
        elif isinstance(exp, UnOpExp):
            return self.visit_unop_exp(exp, *args, **kwargs)
        elif isinstance(exp, CastExp):
            return self.visit_cast_exp(exp, *args, **kwargs)
        elif isinstance(exp, IntExp):
            return self.visit_int_exp(exp, *args, **kwargs)
        elif isinstance(exp, LetExp):
            return self.visit_let_exp(exp, *args, **kwargs)
        elif isinstance(exp, UnknownExp):
            return self.visit_unknown_exp(exp, *args, **kwargs)
        elif isinstance(exp, IteExp):
            return self.visit_ite_exp(exp, *args, **kwargs)
        elif isinstance(exp, ExtractExp):
            return self.visit_extract_exp(exp, *args, **kwargs)
        elif isinstance(exp, ConcatExp):
            return self.visit_concat_exp(exp, *args, **kwargs)
        elif isinstance(exp, VirtualVar):
            return self.visit_virtual_var(exp, *args, **kwargs)
        elif isinstance(exp, RegVar):
            return self.visit_reg_var(exp, *args, **kwargs)
        elif isinstance(exp, FlagVar):
            return self.visit_flag_var(exp, *args, **kwargs)
        elif isinstance(exp, MemVar):
            return self.visit_mem_var(exp, *args, **kwargs)
        elif isinstance(exp, OtherVar):
            return self.visit_other_var(exp, *args, **kwargs)
        elif isinstance(exp, IntConst):
            return self.visit_int_const(exp, *args, **kwargs)
        elif isinstance(exp, StringConst):
            return self.visit_string_const(exp, *args, **kwargs)
        elif isinstance(exp, SwitchTable):
            return self.visit_switch_table(exp, *args, **kwargs)
        elif isinstance(exp, Flag):
            return self.visit_flag(exp, *args, **kwargs)
        elif isinstance(exp, Insn):
            return self.visit_insn(exp, *args, **kwargs)
        elif isinstance(exp, CodeOffset):
            return self.visit_code_offset(exp, *args, **kwargs)
        elif isinstance(exp, VirtualElm):
            return self.visit_virtual_elm(exp, *args, **kwargs)
        elif isinstance(exp, VirtualExp):
            return self.visit_virtual_exp(exp, *args, **kwargs)
        elif isinstance(exp, OtherVarNode):
            return self.visit_othervar_node(exp, *args, **kwargs)
        elif isinstance(exp, UnknownNode):
            return self.visit_unknown_node(exp, *args, **kwargs)
        elif isinstance(exp, GivOffset):
            return self.visit_giv_offset(exp, *args, **kwargs)
        elif isinstance(exp, TempOffset):
            return self.visit_temp_offst(exp, *args, **kwargs)
        elif isinstance(exp, StringArrayOffset):
            return self.visit_string_array(exp, *args, **kwargs)
        elif isinstance(exp, DirectOffset):
            return self.visit_direct_offset(exp, *args, **kwargs)
        elif isinstance(exp, IndirectOffset):
            return self.visit_indirect_offset(exp, *args, **kwargs)
        elif isinstance(exp, GivReg):
            return self.visit_giv_reg(exp, *args, **kwargs)
        elif isinstance(exp, Reg):
            return self.visit_reg(exp, *args, **kwargs)
        elif isinstance(exp, Ttype):
            return self.visit_ttype(exp, *args, **kwargs)

    @abc.abstractmethod
    def visit_load_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_load_exp')

    @abc.abstractmethod
    def visit_store_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_store_exp')

    @abc.abstractmethod
    def visit_binop_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_binop_exp')

    @abc.abstractmethod
    def visit_unop_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_unop_exp')

    @abc.abstractmethod
    def visit_cast_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_cast_exp')

    @abc.abstractmethod
    def visit_int_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_int_exp')

    @abc.abstractmethod
    def visit_let_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_let_exp')

    @abc.abstractmethod
    def visit_unknown_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_unknown_exp')

    @abc.abstractmethod
    def visit_ite_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_ite_exp')

    @abc.abstractmethod
    def visit_extract_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_extract_exp')

    @abc.abstractmethod
    def visit_concat_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_concat_exp')

    @abc.abstractmethod
    def visit_virtual_var(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_virtual_var')

    @abc.abstractmethod
    def visit_reg_var(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_reg_var')

    @abc.abstractmethod
    def visit_flag_var(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_flag_var')

    @abc.abstractmethod
    def visit_mem_var(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_mem_var')

    @abc.abstractmethod
    def visit_other_var(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_other_var')

    @abc.abstractmethod
    def visit_int_const(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_int_const')

    @abc.abstractmethod
    def visit_string_const(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_string_const')

    @abc.abstractmethod
    def visit_switch_table(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_switch_table')

    @abc.abstractmethod
    def visit_flag(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_flag')

    @abc.abstractmethod
    def visit_insn(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_insn')

    @abc.abstractmethod
    def visit_code_offset(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_code_offset')

    @abc.abstractmethod
    def visit_virtual_elm(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_virtual_elm')

    @abc.abstractmethod
    def visit_virtual_exp(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_virtual_exp')

    @abc.abstractmethod
    def visit_othervar_node(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_othervar_node')

    @abc.abstractmethod
    def visit_unknown_node(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_unknown_node')

    @abc.abstractmethod
    def visit_giv_offset(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_giv_offset')

    @abc.abstractmethod
    def visit_temp_offst(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_temp_offst')

    @abc.abstractmethod
    def visit_string_array(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_string_array')

    @abc.abstractmethod
    def visit_direct_offset(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_direct_offset')

    @abc.abstractmethod
    def visit_indirect_offset(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_indirect_offset')

    @abc.abstractmethod
    def visit_giv_reg(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_giv_reg')

    @abc.abstractmethod
    def visit_reg(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_reg')

    @abc.abstractmethod
    def visit_ttype(self, exp, *args, **kwargs):
        raise NotImplementedError('visit_ttype')
