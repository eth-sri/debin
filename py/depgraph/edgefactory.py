from common.constants import GIV_REGS, TEXT
from common.visitors import StmtVisitor, ExpVisitor

from elements.regs import GivReg, Reg, RegBase
from elements.offsets import DirectOffset, IndirectOffset, GivOffset, StringArrayOffset, TempOffset
from elements.givs import IntConst, StringConst, Flag, Insn, CodeOffset
from elements.givs import Node, VirtualElm, VirtualExp, SwitchTable
from elements.function import Function
from elements.elmfactory import make_op_node

from bap.stmts import DefStmt, JmpStmt, PhiStmt
from bap.vars import VirtualVar, RegVar, FlagVar, MemVar, OtherVar
from bap.exps import LoadExp, StoreExp, BinOpExp, UnOpExp, CastExp
from bap.exps import IntExp, LetExp, UnknownExp, IteExp, ExtractExp, ConcatExp
from bap.stmts import DirectLabel, IndirectLabel, CallKind, GotoKind, RetKind, IntentKind

from depgraph.nodes import GIV_NODES, INF_NODES, NODES, FINE_NODES
from depgraph.infos import coarse, fine


class ExpElmsExtractor(ExpVisitor):
    def visit_binop_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.e1)
        yield from self.visit(exp.e2)

    def visit_unop_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.e)

    def visit_cast_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.e)

    def visit_unknown_node(self, exp, *args, **kwargs):
        yield exp

    def visit_let_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.head)
        yield from self.visit(exp.body)

    def visit_ite_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.cond)
        yield from self.visit(exp.yes)
        yield from self.visit(exp.no)

    def visit_extract_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.e)

    def visit_concat_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.e1)
        yield from self.visit(exp.e2)

    def visit_virtual_var(self, exp, *args, **kwargs):
        yield from []

    def visit_othervar_node(self, exp, *args, **kwargs):
        yield exp

    def visit_int_const(self, exp, *args, **kwargs):
        yield exp

    def visit_string_const(self, exp, *args, **kwargs):
        yield exp

    def visit_switch_table(self, exp, *args, **kwargs):
        yield exp

    def visit_flag(self, exp, *args, **kwargs):
        yield exp

    def visit_code_offset(self, exp, *args, **kwargs):
        yield exp

    def visit_virtual_exp(self, exp, *args, **kwargs):
        yield from self.visit(exp.exp)

    def visit_giv_offset(self, exp, *args, **kwargs):
        yield exp

    def visit_temp_offst(self, exp, *args, **kwargs):
        yield exp

    def visit_string_array(self, exp, *args, **kwargs):
        yield exp

    def visit_direct_offset(self, exp, *args, **kwargs):
        yield exp

    def visit_indirect_offset(self, exp, *args, **kwargs):
        yield exp

    def visit_giv_reg(self, exp, *args, **kwargs):
        yield exp

    def visit_reg(self, exp, *args, **kwargs):
        yield exp


EXP_ELMS_EXTRACTOR = ExpElmsExtractor()


class ExpEdgeExtractor(ExpVisitor):
    def visit_binop_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        binary = function.binary

        a, a_op = get_inner_node(exp.e1)
        b, b_op = get_inner_node(exp.e2)

        if type(a) in NODES \
                and type(b) in NODES \
                and (type(a) in INF_NODES or type(b) in INF_NODES):
            binary.edges.add_edge_name_ttype(
                a,
                b,
                '[{}]'.format(exp.op) + '[{}]' + '[{}]'
            )
            binary.edges.add_edge_name_ttype(
                a,
                b,
                '[{}]'.format(exp.op) + a_op + '[{}]' + b_op + '[{}]'
            )
            add_unop_edge(a_op, a, function)
            add_unop_edge(b_op, b, function)
            self.visit(a, function=function)
            self.visit(b, function=function)
        else:
            self.visit(exp.e1, function=function)
            self.visit(exp.e2, function=function)

    def visit_unop_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        operand, op_name = get_inner_node(exp)

        if type(operand) in INF_NODES:
            add_unop_edge(op_name, operand, function)
            self.visit(operand, function=function)
        else:
            self.visit(exp.e, function=function)

    def visit_cast_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        operand, op_name = get_inner_node(exp)

        if type(operand) in INF_NODES:
            add_unop_edge(op_name, operand, function)
            self.visit(operand, function=function)
        else:
            self.visit(exp.e, function=function)

    def visit_let_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        self.visit(exp.v, function=function)
        self.visit(exp.head, function=function)
        self.visit(exp.body, function=function)

    def visit_ite_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        self.visit(exp.cond, function=function)
        self.visit(exp.yes, function=function)
        self.visit(exp.no, function=function)

    def visit_extract_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        binary = function.binary

        op_node = make_op_node('EXTRACT[{}][{}]'.format(exp.hi, exp.lo), function)
        operand, op_name = get_inner_node(exp.e)
        if type(operand) in INF_NODES:
            binary.edges.add_edge_name_ttype(
                operand,
                op_node,
                'EXTRACT[{}]'
            )
            self.visit(operand, function=function)
        else:
            self.visit(exp.e, function=function)

    def visit_concat_exp(self, exp, *args, **kwargs):
        function = kwargs['function']
        self.visit(exp.e1, function=function)
        self.visit(exp.e2, function=function)

    def visit_virtual_var(self, exp, *args, **kwargs):
        pass

    def visit_reg_var(self, exp, *args, **kwargs):
        pass

    def visit_flag_var(self, exp, *args, **kwargs):
        pass

    def visit_mem_var(self, exp, *args, **kwargs):
        pass

    def visit_other_var(self, exp, *args, **kwargs):
        pass

    def visit_unknown_node(self, exp, *args, **kwargs):
        pass

    def visit_int_const(self, exp, *args, **kwargs):
        pass

    def visit_string_const(self, exp, *args, **kwargs):
        pass

    def visit_switch_table(self, exp, *args, **kwargs):
        pass

    def visit_flag(self, exp, *args, **kwargs):
        pass

    def visit_insn(self, exp, *args, **kwargs):
        pass

    def visit_code_offset(self, exp, *args, **kwargs):
        pass

    def visit_virtual_elm(self, exp, *args, **kwargs):
        pass

    def visit_virtual_exp(self, exp, *args, **kwargs):
        self.visit(exp.exp, function=kwargs['function'])

    def visit_othervar_node(self, exp, *args, **kwargs):
        pass

    def visit_giv_offset(self, exp, *args, **kwargs):
        self.visit(exp.exp, function=kwargs['function'])

    def visit_temp_offst(self, exp, *args, **kwargs):
        pass

    def visit_string_array(self, exp, *args, **kwargs):
        pass

    def visit_direct_offset(self, exp, *args, **kwargs):
        pass

    def visit_indirect_offset(self, exp, *args, **kwargs):
        pass

    def visit_giv_reg(self, exp, *args, **kwargs):
        pass

    def visit_reg(self, exp, *args, **kwargs):
        pass

    def visit_ttype(self, exp, *args, **kwargs):
        pass


EXP_EDGE_EXTRACTOR = ExpEdgeExtractor()


class StmtEdgeExtractor(StmtVisitor):
    def visit_def(self, stmt, *args, **kwargs):
        function = kwargs['function']
        binary = function.binary
        lhs = stmt.lhs
        rhs = stmt.rhs
        EXP_EDGE_EXTRACTOR.visit(rhs, function=function)

        if stmt.insn is not None \
                and (type(lhs) in INF_NODES or
                     isinstance(lhs, Flag)):
            if stmt.insn in binary.insns:
                binary.edges.add_edge(
                    lhs,
                    binary.insns[stmt.insn],
                    'INSN_lhs[{}]',
                    fine if type(lhs) in FINE_NODES else coarse
                )

            rhs_elms = list(EXP_ELMS_EXTRACTOR.visit(rhs))
            for i, elm in enumerate(rhs_elms):
                binary.edges.add_edge(
                    lhs,
                    elm,
                    '{}_{}'.format(stmt.insn, i) + '[{}]' + '[{}]',
                    fine if type(lhs) in FINE_NODES else coarse,
                    fine if type(elm) in FINE_NODES else coarse,
                )

                if stmt.insn in binary.insns \
                        and type(elm) in INF_NODES:
                    binary.edges.add_edge(
                        elm,
                        binary.insns[stmt.insn],
                        'INSN_rhs_{}'.format(i) + '[{}]',
                        fine if type(elm) in FINE_NODES else coarse
                    )

            rhs_elms.append(lhs)
            if stmt.insn in binary.insns:
                rhs_elms.append(binary.insns[stmt.insn])
            binary.factors.add_stmt_factor(rhs_elms)

    def visit_phi(self, stmt, *args, **kwargs):
        function = kwargs['function']
        binary = function.binary
        lhs = stmt.lhs
        rhs = list(filter(lambda r: type(r) in INF_NODES, stmt.rhs))
        rhs_ttypes = filter(lambda r: hasattr(r, 'ttype'), rhs)
        rhs_ttypes = list(map(lambda r: r.ttype, rhs_ttypes))

        if type(lhs) in INF_NODES:
            for r in rhs:
                binary.edges.add_edge_name_ttype(
                    lhs,
                    r,
                    'Phi[{}]'
                )
            rhs.append(lhs)
            binary.factors.add_phi_factor(rhs)
            if hasattr(lhs, 'ttype'):
                rhs_ttypes.append(lhs.ttype)
                binary.factors.add_phi_factor(rhs_ttypes)
        else:
            binary.factors.add_phi_factor(rhs)

    def visit_jmp(self, stmt, *args, **kwargs):
        function = kwargs['function']
        binary = function.binary

        if stmt.cond is not None:
            EXP_EDGE_EXTRACTOR.visit(stmt.cond, function=function)

            cond, cond_op = get_inner_node(stmt.cond)
            if type(cond) in INF_NODES:
                add_unop_edge(cond_op, cond, function)
                add_unop_edge('COND[{}]'.format(cond_op), cond, function)
            elif isinstance(cond, Flag):
                key = (cond.base_flag, cond.index)
                if key in function.flag_defs:
                    flag_def, flag_op = get_inner_node(function.flag_defs[key])
                    if type(flag_def) in INF_NODES:
                        binary.edges.add_edge_name_ttype(
                            flag_def,
                            cond,
                            'COND[{}{}{}]'.format(cond_op, flag_op, cond.base_flag) + '[{}]'
                        )
                    elif isinstance(flag_def, BinOpExp):
                        e1, e1_op = get_inner_node(flag_def.e1)
                        e2, e2_op = get_inner_node(flag_def.e2)
                        if type(e1) in NODES \
                                and type(e2) in NODES \
                                and (type(e1) in INF_NODES or type(e2) in INF_NODES):
                            binary.edges.add_edge_name_ttype(
                                e1,
                                e2,
                                'COND_{}[{}{}{}]'.format(flag_def.op, cond_op, flag_op, cond.base_flag) + e1_op + '[{}]' + e2_op + '[{}]'
                            )
                        elif isinstance(e1, BinOpExp) \
                                and isinstance(e2, IntConst):
                            if e2.value == 0:
                                a, a_op = get_inner_node(e1.e1)
                                b, b_op = get_inner_node(e1.e2)
                                if type(a) in NODES \
                                        and type(b) in NODES\
                                        and (type(a) in INF_NODES or type(b) in INF_NODES):
                                    binary.edges.add_edge_name_ttype(
                                        a,
                                        b,
                                        'COND_{}[{}{}{}]'.format(e1.op, cond_op, flag_op, cond.base_flag) + a_op + '[{}]' + b_op + '[{}]'
                                    )
                            else:
                                pass
                        else:
                            # print('{} {}'.format(stmt.cond, flag_def))
                            pass
                    elif isinstance(flag_def, IntConst):
                        pass
                    else:
                        # print('{} {}'.format(stmt.cond, flag_def))
                        pass
            elif isinstance(cond, BinOpExp):
                e1, e1_op = get_inner_node(cond.e1)
                e2, e2_op = get_inner_node(cond.e2)
                if type(e1) in NODES \
                        and type(e2) in NODES \
                        and (type(e1) in INF_NODES or type(e2) in INF_NODES):
                    binary.edges.add_edge_name_ttype(
                        e1,
                        e2,
                        'COND_{}'.format(cond.op) + e1_op + '[{}]' + e2_op + '[{}]'
                    )
                elif isinstance(e1, BinOpExp) \
                        and isinstance(e2, IntConst):
                    a, a_op = get_inner_node(e1.e1)
                    b, b_op = get_inner_node(e1.e2)
                    if e2.value == 0:
                        if type(a) in NODES \
                                and type(b) in NODES \
                                and (type(a) in INF_NODES or type(b) in INF_NODES):
                            binary.edges.add_edge_name_ttype(
                                a,
                                b,
                                'COND_{}[{}{}]'.format(e1.op, cond_op, e1_op) + a_op + '[{}]' + b_op + '[{}]'
                            )
                    elif type(a) in INF_NODES \
                            and isinstance(b, IntConst):
                        binary.edges.add_edge_name_ttype(
                            a,
                            e2,
                            'COND_{}[{}{}][{}_{}]'.format(e1.op, cond_op, e1_op, e2.width, e2.value) + a_op + '[{}]' + b_op + '[{}]'
                        )
                    else:
                        pass
                else:
                    # print(stmt.cond)
                    pass
            else:
                # print(stmt.cond)
                pass

        if isinstance(stmt.kind, CallKind) \
                and stmt.kind.target is not None \
                and isinstance(stmt.kind.target, Function):
            args = []
            for key in stmt.kind.args:
                arg = stmt.kind.args[key]
                if isinstance(arg, Node):
                    f2 = key
                    if binary.config.MACHINE_ARCH == 'x86':
                        f2 = '{}+{}'.format(key[0], key[1])
                    elif binary.config.MACHINE_ARCH == 'x64':
                        f2 = key
                    elif binary.config.MACHINE_ARCH == 'ARM':
                        f2 = key
                    binary.edges.add_edge_name_ttype(
                        stmt.kind.target,
                        arg,
                        'NAME[{}]FUNARG'.format(f2)
                    )

            arg_ttypes = filter(lambda a: hasattr(a, 'ttype'), args)
            arg_ttypes = list(map(lambda a: a.ttype, arg_ttypes))
            binary.factors.add_funarg_factor(arg_ttypes, True)

            args.append(stmt.kind.target)
            binary.factors.add_funarg_factor(args, False)


STMT_EDGE_EXTRACTOR = StmtEdgeExtractor()


def get_inner_node(exp):
    exp = exp.exp if type(exp) is VirtualExp else exp
    if type(exp) is CastExp:
        node, op = get_inner_node(exp.e)
        return node, '({}{})'.format(exp.kind, exp.size) + op
    elif type(exp) is UnOpExp:
        node, op = get_inner_node(exp.e)
        return node, '({})'.format(exp.op) + op
    elif type(exp) in NODES:
        return exp, ''
    else:
        return exp, ''


def add_unop_edge(op_name, node, function):
    op_node = make_op_node(op_name, function)
    function.binary.edges.add_edge_name_ttype(
        node,
        op_node,
        'UNOP[{}]'
    )
