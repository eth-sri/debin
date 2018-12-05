from elements.regs import GivReg, Reg
from elements.givs import Flag, IntConst
from elements.offsets import IndirectOffset
from elements.function import Function
from common.visitors import StmtVisitor, ExpVisitor
from bap.exps import BinOpExp
from bap.stmts import CallKind
from depgraph.edgefactory import get_inner_node
from depgraph.infos import fine, coarse
from depgraph.nodes import GIV_NODES, INF_NODES, NODES, FINE_NODES


class ExpFeatureExtractor(ExpVisitor):
    def visit_binop_exp(self, exp, *args, **kwargs):
        a, a_op = get_inner_node(exp.e1)
        b, b_op = get_inner_node(exp.e2)

        if type(a) in (Reg, IndirectOffset) \
                or type(b) in (Reg, IndirectOffset):
            feature = 'UNOP[{}][{}]'.format(a_op, '{}')
            add_unary_feature(feature, a)

            feature = 'UNOP[{}][{}]'.format(b_op, '{}')
            add_unary_feature(feature, b)

            feature = '{}[{}][{}]'.format(exp.op, '{}', '{}')
            add_binary_feature(feature, a, b)

            self.visit(a)
            self.visit(b)
        else:
            self.visit(exp.e1)
            self.visit(exp.e2)

    def visit_unop_exp(self, exp, *args, **kwargs):
        operand, op_name = get_inner_node(exp)

        if type(operand) in (Reg, IndirectOffset):
            feature = 'UNOP[{}][{}]'.format(op_name, '{}')
            add_unary_feature(feature, operand)

            self.visit(operand)
        else:
            self.visit(exp.e)

    def visit_cast_exp(self, exp, *args, **kwargs):
        operand, op_name = get_inner_node(exp)

        if type(operand) in (Reg, IndirectOffset):
            feature = 'UNOP[{}][{}]'.format(op_name, '{}')
            add_unary_feature(feature, operand)

            self.visit(operand)
        else:
            self.visit(exp.e)

    def visit_let_exp(self, exp, *args, **kwargs):
        self.visit(exp.v)
        self.visit(exp.head)
        self.visit(exp.body)

    def visit_ite_exp(self, exp, *args, **kwargs):
        self.visit(exp.cond)
        self.visit(exp.yes)
        self.visit(exp.no)

    def visit_extract_exp(self, exp, *args, **kwargs):
        operand, op_name = get_inner_node(exp.e)

        if type(operand) in (Reg, IndirectOffset):
            feature = 'UNOP[{}][{}]'.format(op_name, '{}')
            add_unary_feature(feature, operand)

            feature = 'EXTRACT[{}][{}][{}]'.format(exp.hi, exp.lo, '{}')
            add_unary_feature(feature, operand)

            self.visit(operand)
        else:
            self.visit(exp.e)

    def visit_concat_exp(self, exp, *args, **kwargs):
        self.visit(exp.e1)
        self.visit(exp.e2)

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
        self.visit(exp.exp)

    def visit_othervar_node(self, exp, *args, **kwargs):
        pass

    def visit_giv_offset(self, exp, *args, **kwargs):
        pass

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


EXP_FEATURE_EXTRACTOR = ExpFeatureExtractor()


class StmtFeatureExtractor(StmtVisitor):
    def visit_def(self, stmt, *args, **kwargs):
        from depgraph.edgefactory import EXP_ELMS_EXTRACTOR

        EXP_FEATURE_EXTRACTOR.visit(stmt.rhs)

    def visit_phi(self, stmt, *args, **kwargs):
        lhs = stmt.lhs
        rhs = stmt.rhs
        if isinstance(lhs, Reg):
            lhs.features.add('PHILHS[{}]'.format(coarse(lhs)))

        for elm in rhs:
            if isinstance(elm, Reg):
                elm.features.add('PHIRHS[{}]'.format(coarse(elm)))

    def visit_jmp(self, stmt, *args, **kwargs):
        function = kwargs['function']
        binary = function.binary

        if stmt.cond is not None:
            cond, cond_op = get_inner_node(stmt.cond)
            if type(cond) in (Reg, IndirectOffset):
                feature = 'UNOP[{}][{}]'.format(cond_op, '{}')
                add_unary_feature(feature, cond)
            elif isinstance(cond, Flag):
                key = (cond.base_flag, cond.index)
                if key in function.flag_defs:
                    flag_def, flag_op = get_inner_node(function.flag_defs[key])
                    if type(flag_def) in (Reg, IndirectOffset):
                        feature = 'COND[{}{}{}][{}]'.format(cond_op, flag_op, cond.base_flag, '{}')
                        add_unary_feature(feature, flag_def)
                    elif isinstance(flag_def, BinOpExp):
                        e1, e1_op = get_inner_node(flag_def.e1)
                        e2, e2_op = get_inner_node(flag_def.e2)

                        if type(e1) in NODES \
                                and type(e2) in NODES \
                                and (type(e1) in (Reg, IndirectOffset) or
                                     type(e2) in (Reg, IndirectOffset)):
                            feature = 'COND_{}[{}{}{}][{}{}][{}{}]'.format(
                                      flag_def.op,
                                      cond_op,
                                      flag_op,
                                      cond.base_flag,
                                      e1_op,
                                      '{}',
                                      e2_op,
                                      '{}'
                            )
                            add_binary_feature(feature, e1, e2)
                        elif isinstance(e1, BinOpExp) and isinstance(e2, IntConst):
                            if e2.value == 0:
                                a, a_op = get_inner_node(e1.e1)
                                b, b_op = get_inner_node(e1.e2)
                                if type(a) in NODES \
                                        and type(b) in NODES \
                                        and (type(a) in (Reg, IndirectOffset) or
                                             type(b) in (Reg, IndirectOffset)):
                                    feature = 'COND_{}[{}{}{}][{}{}][{}{}]'.format(
                                              e1.op,
                                              cond_op,
                                              flag_op,
                                              cond.base_flag,
                                              a_op,
                                              '{}',
                                              b_op,
                                              '{}'
                                    )
                                    add_binary_feature(feature, e1, e2)
                            else:
                                pass
                        else:
                            pass
                    elif isinstance(flag_def, IntConst):
                        pass
                    else:
                        pass
            elif isinstance(cond, BinOpExp):
                e1, e1_op = get_inner_node(cond.e1)
                e2, e2_op = get_inner_node(cond.e2)
                if type(e1) in NODES \
                        and type(e2) in NODES \
                        and (type(e1) in (Reg, IndirectOffset) or
                             type(e2) in (Reg, IndirectOffset)):
                    feature = 'COND_{}[{}{}][{}{}]'.format(
                        cond.op,
                        e1_op,
                        '{}',
                        e2_op,
                        '{}'
                    )
                    add_binary_feature(feature, e1, e2)
                elif isinstance(e1, BinOpExp) \
                        and isinstance(e2, IntConst):
                    a, a_op = get_inner_node(e1.e1)
                    b, b_op = get_inner_node(e1.e2)
                    if e2.value == 0:
                        if type(a) in NODES \
                                and type(b) in NODES \
                                and (type(a) in (Reg, IndirectOffset) or
                                     type(b) in (Reg, IndirectOffset)):
                            feature = 'COND_{}[{}{}][{}{}][{}{}]'.format(
                                e1.op,
                                cond.op,
                                e1_op,
                                a_op,
                                '{}',
                                b_op,
                                '{}'
                            )
                            add_binary_feature(feature, a, b)
                    elif type(a) in (Reg, IndirectOffset) \
                            and isinstance(b, IntConst):
                        feature = 'COND_{}[{}{}][{}_{}][{}{}][{}{}]'.format(
                            e1.op,
                            cond_op,
                            e1_op,
                            e2.width,
                            e2.value,
                            a_op,
                            '{}',
                            b_op,
                            '{}'
                        )
                        add_binary_feature(feature, a, b)
                    else:
                        pass
                else:
                    pass
            else:
                pass

        if isinstance(stmt.kind, CallKind) \
                and stmt.kind.target is not None \
                and isinstance(stmt.kind.target, Function):
            function = stmt.kind.target
            for key in stmt.kind.args:
                arg = stmt.kind.args[key]
                func_name = function.name if function.is_name_given else 'FUNC'
                f2 = key
                if binary.config.MACHINE_ARCH == 'x86':
                    f2 = '{}+{}'.format(key[0], key[1])
                elif binary.config.MACHINE_ARCH == 'x64':
                    f2 = key
                elif binary.config.MACHINE_ARCH == 'ARM':
                    f2 = key
                feature = 'ARG[{}][{}][{}]'.format(func_name, f2, '{}')
                add_unary_feature(feature, arg)


STMT_FEATURE_EXTRACTOR = StmtFeatureExtractor()


def add_unary_feature(feature, node):
    if isinstance(node, Reg):
        node.features.add(feature.format(coarse(node)))
    elif isinstance(node, IndirectOffset):
        node.features.add(feature.format(coarse(node)))
        node.features.add(feature.format(fine(node)))


def add_binary_feature(feature, n1, n2):
    if type(n1) in (GivReg, Reg, Flag):
        n1_info = coarse(n1)
    else:
        n1_info = fine(n1)

    if type(n2) in (GivReg, Reg, Flag):
        n2_info = coarse(n2)
    else:
        n2_info = fine(n2)

    if isinstance(n1, Reg):
        n1.features.add('L' + feature.format(coarse(n1), n2_info))
        if isinstance(n2, IndirectOffset):
            n1.features.add('L' + feature.format(coarse(n1), coarse(n2_info)))
    elif isinstance(n1, IndirectOffset):
        n1.features.add('L' + feature.format(coarse(n1), n2_info))
        n1.features.add('L' + feature.format(fine(n1), n2_info))
        if isinstance(n2, IndirectOffset):
            n1.features.add('L' + feature.format(coarse(n1), coarse(n2_info)))
            n1.features.add('L' + feature.format(fine(n1), coarse(n2_info)))

    if isinstance(n2, Reg):
        n2.features.add('R' + feature.format(n1_info, coarse(n2)))
        if isinstance(n1, IndirectOffset):
            n2.features.add('R' + feature.format(coarse(n1), coarse(n2)))
    elif isinstance(n2, IndirectOffset):
        n2.features.add('R' + feature.format(n1_info, coarse(n2)))
        n2.features.add('R' + feature.format(n1_info, fine(n2)))
        if isinstance(n1, IndirectOffset):
            n2.features.add('R' + feature.format(coarse(n1), coarse(n2)))
            n2.features.add('R' + feature.format(coarse(n1), coarse(n2)))
