open Bap.Std
open Core_kernel.Std
open Yojson.Basic

let vars_of_exp = Exp.fold ~init:Var.Set.empty (object
    inherit [Var.Set.t] Exp.visitor
    method! enter_var var vars = Set.add vars var
  end)


let vars_of_label = function
  | Indirect exp -> vars_of_exp exp
  | Direct _ -> Var.Set.empty


let collect_vars sub =
  let (++) = Set.union in
  Term.enum blk_t sub |>
  Seq.fold ~init:(Var.Set.empty,Var.Set.empty) ~f:(fun sets blk ->
    Blk.elts blk |> Seq.fold ~init:sets ~f:(fun (defs,uses) ->
      function
      | `Phi phi ->
        Set.add defs (Phi.lhs phi),
        Seq.fold (Phi.values phi) ~init:uses ~f:(fun uses (_,exp) ->
            uses ++ vars_of_exp exp)
      | `Def def ->
        Set.add defs (Def.lhs def),
        uses ++ vars_of_exp (Def.rhs def)
      | `Jmp jmp ->
        defs,
        uses ++ vars_of_exp (Jmp.cond jmp) ++
        match Jmp.kind jmp with
        | Ret dst | Goto dst -> vars_of_label dst
        | Int (_,_) -> Var.Set.empty
        | Call call ->
          uses ++ vars_of_label (Call.target call) ++
          match Call.return call with
          | None -> Var.Set.empty
          | Some dst -> vars_of_label dst))


let clean_sub arch sub =
  let module Target = (val target_of_arch arch) in
  let no_side_effects var =
    let open Target.CPU in
    Var.is_virtual var || is_flag var in
  let filter dead t lhs blk =
    Term.filter t blk ~f:(fun p -> not(Set.mem dead (lhs p))) in
  let rec clean sub =
    let defs,uses = collect_vars sub in
    let dead = Set.diff defs uses |> Set.filter ~f:no_side_effects in
    if Set.is_empty dead then sub
    else Term.map blk_t sub ~f:(fun blk ->
      blk |>
      filter dead phi_t Phi.lhs |>
      filter dead def_t Def.lhs) |> clean  in
  clean sub


let deadcode proj =
  Project.program proj |>
  Term.map sub_t ~f:(clean_sub (Project.arch proj)) |>
  Project.with_program proj


let startswith str substr =
  let len_str = String.length str in
  let len_substr = String.length substr in
  if len_str >= len_substr then
    String.equal (String.sub str 0 len_substr) substr
  else false


let top_function init_proj =
  let proj = deadcode init_proj
  in


  let module Target = (val target_of_arch (Project.arch proj))
  in


  let prog = Project.program proj
  in


  let unsigned_int_of_word w =
    let unsigned_w = Bitvector.unsigned w in
    Bitvector.to_int_exn unsigned_w
  in


  let signed_int_of_word w =
    let signed_w = Bitvector.signed w in
    Bitvector.to_int_exn signed_w
  in


  let nosigned_int_of_word w = Bitvector.to_int_exn w
  in


  let int_of_word = nosigned_int_of_word
  in

  let string_of_word = Bitvector.string_of_value ~hex:false
  in


  let cast_json = function
    | Bil.UNSIGNED -> `String "UNSIGNED"
    | Bil.SIGNED -> `String "SIGNED"
    | Bil.HIGH -> `String "HIGH"
    | Bil.LOW -> `String "LOW"
  in


  let binop_json = function
    |	Bil.PLUS -> `String "PLUS"
    |	Bil.MINUS -> `String "MINUS"
    |	Bil.TIMES -> `String "TIMES"
    |	Bil.DIVIDE -> `String "DIVIDE"
    |	Bil.SDIVIDE -> `String "SDIVIDE"
    |	Bil.MOD -> `String "MOD"
    |	Bil.SMOD -> `String "SMOD"
    |	Bil.LSHIFT -> `String "LSHIFT"
    |	Bil.RSHIFT -> `String "RSHIFT"
    |	Bil.ARSHIFT -> `String "ARSHIFT"
    |	Bil.AND -> `String "AND"
    |	Bil.OR -> `String "OR"
    |	Bil.XOR -> `String "XOR"
    |	Bil.EQ -> `String "EQ"
    |	Bil.NEQ -> `String "NEQ"
    |	Bil.LT -> `String "LT"
    |	Bil.LE -> `String "LE"
    |	Bil.SLT -> `String "SLT"
    |	Bil.SLE -> `String "SLE"
  in


  let unop_json = function
    | Bil.NEG -> `String "NEG"
    | Bil.NOT -> `String "NOT"
  in


  let endian_json = function
    | Bitvector.LittleEndian -> `String "LittleEndian"
    | Bitvector.BigEndian -> `String "BigEndian"
  in


  let var_json v =
    if Var.is_virtual v then
      `Assoc [("t", `String "Var"); ("kind", `String "Virtual"); ("name", `String (Var.name v)); ("index", `Int (Var.index v))]
    else if Target.CPU.is_reg v then
      `Assoc [("t", `String "Var"); ("kind", `String "Reg"); ("name", `String (Var.name v)); ("index", `Int (Var.index v))]
    else if Target.CPU.is_flag v then
      `Assoc [("t", `String "Var"); ("kind", `String "Flag"); ("name", `String (Var.name v)); ("index", `Int (Var.index v))]
    else if Target.CPU.is_mem v then
      `Assoc [("t", `String "Var"); ("kind", `String "Mem"); ("name", `String (Var.name v)); ("index", `Int (Var.index v))]
    else
      `Assoc [("t", `String "Var"); ("kind", `String "Other"); ("name", `String (Var.name v)); ("index", `Int (Var.index v))]
  in


  let rec exp_json = function
    | Bil.Load (e1, e2, endian, size) ->
      `Assoc [("t", `String "Load"); ("addr", (exp_json e2)); ("endian", (endian_json endian)); ("size", `Int (Size.in_bytes size))]
    | Bil.Store (e1, e2, e3, endian, size) ->
      `Assoc [("t", `String "Store"); ("addr", (exp_json e2)); ("exp", (exp_json e3)); ("endian", (endian_json endian)); ("size", `Int (Size.in_bytes size))]
    | Bil.BinOp (op, e1, e2) ->
      `Assoc [("t", `String "BinOp"); ("op", (binop_json op)); ("e1", (exp_json e1)); ("e2", (exp_json e2))]
    | Bil.UnOp (op, e) ->
      `Assoc [("t", `String "UnOp"); ("op", (unop_json op)); ("e", (exp_json e))]
    | Bil.Int (w) ->
      `Assoc [("t", `String "Int"); ("value", `String (string_of_word w)); ("width", `Int (Bitvector.bitwidth w))]
    | Bil.Cast (cast, i, e) ->
      `Assoc [("t", `String "Cast"); ("kind", (cast_json cast)); ("size", `Int i); ("e", (exp_json e))]
    | Bil.Let (var, e1, e2) ->
      `Assoc [("t", `String "Let"); ("v", (var_json var)); ("head", (exp_json e1)); ("body", (exp_json e2))]
    | Bil.Unknown (s, t) ->
      `Assoc [("t", `String "Unknown"); ("msg", `String s)]
    | Bil.Ite (e1, e2, e3) ->
      `Assoc [("t", `String "Ite"); ("cond", (exp_json e1)); ("yes", (exp_json e2)); ("no", (exp_json e3))]
    | Bil.Extract (i1, i2, e) ->
      `Assoc [("t", `String "Extract"); ("hi", `Int i1); ("lo", `Int i2); ("e", (exp_json e))]
    | Bil.Concat (e1, e2) ->
      `Assoc [("t", `String "Concat"); ("e1", (exp_json e1)); ("e2", (exp_json e2))]
    | Bil.Var (var) ->
      (var_json var)
  in


  let def_json def =
    let base_attrs =
      [("t", `String "Def"); ("lhs", (var_json @@ Def.lhs def)); ("rhs", (exp_json @@ Def.rhs def)); ("tid", `String (Tid.to_string @@ Term.tid @@ def))] in
    let insn_option = Term.get_attr def Disasm.insn in
    let pc_option = Term.get_attr def address in
    let complete_attrs =
      match (insn_option, pc_option) with
        | (Some insn, Some pc_word) ->
          ("pc", `Int (int_of_word pc_word)) :: (("insn", `String (Insn.name insn)) :: base_attrs)
        | (Some insn, None) ->
          (("insn", `String (Insn.name insn)) :: base_attrs)
        | (None, Some pc_word) ->
          (("pc", `Int (int_of_word pc_word)) :: base_attrs)
        | (None, None) ->
          base_attrs
    in
    `Assoc complete_attrs
  in


  let phi_json phi =
    let rhs_json = `List (Seq.to_list @@ Seq.map (Phi.values phi) (fun (tid, exp) -> (exp_json exp))) in
    let base_attrs =
      [("t", `String "Phi"); ("lhs", (var_json @@ Phi.lhs phi)); ("rhs", rhs_json); ("tid", `String (Tid.to_string @@ Term.tid @@ phi))] in
    let insn_option = Term.get_attr phi Disasm.insn in
    let pc_option = Term.get_attr phi address in
    let complete_attrs =
      match (insn_option, pc_option) with
        | (Some insn, Some pc_word) ->
          ("pc", `Int (int_of_word pc_word)) :: (("insn", `String (Insn.name insn)) :: base_attrs)
        | (Some insn, None) ->
          (("insn", `String (Insn.name insn)) :: base_attrs)
        | (None, Some pc_word) ->
          (("pc", `Int (int_of_word pc_word)) :: base_attrs)
        | (None, None) ->
          base_attrs
    in
    `Assoc complete_attrs
  in


  let jmp_json jmp =
    let label_json = function
      | Direct tid ->
        `Assoc [("t", `String "Direct"); ("target_tid", `String (Tid.to_string @@ tid))]
      | Indirect exp ->
        `Assoc [("t", `String "Indirect"); ("exp", (exp_json exp))]
    in
    let call_json call =
      let return_json =
        match (Call.return call) with
          | Some label -> (label_json label)
          | None -> `String "None"
      in
      `Assoc [("t", `String "call"); ("target", (label_json @@ Call.target call)); ("rtn", return_json)]
    in
    let jmpkind_json = function
      | Call call ->
        `Assoc [("t", `String "Call"); ("call", (call_json call))]
      | Goto label ->
        `Assoc [("t", `String "Goto"); ("label", (label_json label))]
      | Ret label ->
        `Assoc [("t", `String "Ret"); ("label", (label_json label))]
      | Int (i, tid) ->
        `Assoc [("t", `String "Intent")]
    in
    let base_attrs =
      [("t", `String "Jmp"); ("kind", (jmpkind_json @@ Jmp.kind jmp)); ("cond", (exp_json @@ Jmp.cond jmp)); ("tid", `String (Tid.to_string @@ Term.tid @@ jmp))] in
    let insn_option = Term.get_attr jmp Disasm.insn in
    let pc_option = Term.get_attr jmp address in
    let complete_attrs =
      match (insn_option, pc_option) with
        | (Some insn, Some pc_word) ->
          ("pc", `Int (int_of_word pc_word)) :: (("insn", `String (Insn.name insn)) :: base_attrs)
        | (Some insn, None) ->
          (("insn", `String (Insn.name insn)) :: base_attrs)
        | (None, Some pc_word) ->
          (("pc", `Int (int_of_word pc_word)) :: base_attrs)
        | (None, None) ->
          base_attrs
    in
    `Assoc complete_attrs
  in


  let blk_json blk =
    let rev_stmts =
      Blk.elts blk |> Seq.fold ~init:[] ~f:(fun stmts ->
        function
        | `Def def -> (def_json def) :: stmts
        | `Phi phi -> (phi_json phi) :: stmts
        | `Jmp jmp -> (jmp_json jmp) :: stmts)
    in
    `Assoc [("stmts", `List (List.rev rev_stmts)); ("tid", `String (Tid.to_string @@ Term.tid @@ blk))]
  in


  let blks_json ssa =
    `List (Seq.to_list @@ Seq.map ~f:blk_json @@ Term.enum blk_t ssa)
  in


  let cfg_json ssa =
    let open Graphs.Ir in
    let string_of_src e = (Tid.to_string @@ Term.tid @@ Node.label @@ Edge.src @@ e) in
    let string_of_dst e = (Tid.to_string @@ Term.tid @@ Node.label @@ Edge.dst @@ e) in
    `List(
      Sub.to_cfg ssa |>
      edges |>
      Seq.fold ~init:[] ~f:(fun es e ->
        `Assoc([("src", `String (string_of_src e)); ("dst", `String (string_of_dst e))]) :: es))
  in


  let ssa_low_pc ssa =
    match (Term.get_attr ssa address) with
    | Some word -> int_of_word word
    | None -> -1
  in


  let ssa_high_pc ssa =
    Term.enum blk_t ssa |> Seq.fold ~init:~-1 ~f:(fun high_pc blk ->
      Blk.elts blk |> Seq.fold ~init:high_pc ~f:(fun pc ->
        function
        | `Def def ->
          (match (Term.get_attr def address) with
          | Some pc_word -> max pc (int_of_word pc_word)
          | None -> pc)
        | `Phi phi ->
          (match (Term.get_attr phi address) with
          | Some pc_word -> max pc (int_of_word pc_word)
          | None -> pc)
        | `Jmp jmp ->
          (match (Term.get_attr jmp address) with
          | Some pc_word -> max pc (int_of_word pc_word)
          | None -> pc)))
  in


  let sub_json sub =
    let ssa = Sub.ssa sub in
    let json_name = `String (Sub.name ssa) in
    let json_tid = `String (Tid.to_string @@ Term.tid @@ ssa) in
    let json_low_pc = `Int (ssa_low_pc ssa) in
    let json_high_pc = `Int (ssa_high_pc ssa) in
    let json_blks = blks_json ssa in
    let json_cfg = cfg_json ssa in
    `Assoc [("name", json_name); ("tid", json_tid); ("low_pc", json_low_pc); ("high_pc", json_high_pc); ("blks", json_blks); ("cfg", json_cfg)]
  in


  let call_graph_json =
    let open Graphs.Callgraph in
    let string_of_src e = Tid.to_string @@ Edge.src @@ e in
    let string_of_dst e = Tid.to_string @@ Edge.dst @@ e in
    `List(
      Program.to_graph prog |>
      edges |>
      Seq.fold ~init:[] ~f:(fun ls e -> `Assoc ([("src", `String (string_of_src e)); ("dst", `String (string_of_dst e))]) :: ls))
  in


  let subs_json =
    `List (prog |> Term.enum sub_t |> Seq.fold ~init:[] ~f:(fun subs sub -> (sub_json sub) :: subs))
  in


  let pcs_json =
    let disasm = Project.disasm init_proj in
    let insns = Disasm.insns disasm in
    `List (Seq.to_list @@ Seq.map insns (fun (mem, insn) ->
      `Assoc ([("start_pc", `Int (int_of_word @@ Memory.min_addr @@ mem)); ("byte_length", `Int (Memory.length mem)); ("insn_name", `String (Insn.name insn))])))
  in


  let proj_json =
    `Assoc ([
      ("subs", subs_json);
      ("callgraph", call_graph_json);
      ("pcs", pcs_json)
      ])
  in


  (* print_string @@ pretty_to_string proj_json *)
  print_string @@ to_string proj_json


let () = Project.register_pass' top_function
