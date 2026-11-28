// See printrust.hh. The block emitters follow PrintC's (ghidra/printc.cc)
// closely, changing only the syntax.
#include "printrust.hh"
#include "funcdata.hh"

namespace ghidra {

PrintRustCapability PrintRustCapability::printRustCapability;

PrintRustCapability::PrintRustCapability(void) {
  name = "rust-language";
  isdefault = false;
}

PrintLanguage *PrintRustCapability::buildLanguage(Architecture *glb) {
  return new PrintRust(glb, name);
}

// `x as T`: binds tighter than * and +, looser than unary operators.
OpToken PrintRust::as_cast = {" as ", "", 2, 60, false, OpToken::binary, 0, 0, (OpToken *)0};
// Rust writes bitwise not as `!` too.
OpToken PrintRust::rust_not = {"!", "", 1, 62, false, OpToken::unary_prefix, 0, 0, (OpToken *)0};

PrintRust::PrintRust(Architecture *g, const string &nm) : PrintC(g, nm) {}

static string intName(bool sign, int4 size) {
  switch (size) {
    case 1: case 2: case 4: case 8: case 16:
      return (sign ? "i" : "u") + std::to_string(size * 8);
    default:
      return "[u8; " + std::to_string(size) + "]";
  }
}

string PrintRust::rustType(const Datatype *ct) {
  switch (ct->getMetatype()) {
    case TYPE_VOID: return "()";
    case TYPE_BOOL: return "bool";
    case TYPE_INT: return intName(true, ct->getSize());
    case TYPE_UINT: return intName(false, ct->getSize());
    case TYPE_UNKNOWN: return intName(false, ct->getSize());
    case TYPE_FLOAT:
      if (ct->getSize() == 4) return "f32";
      if (ct->getSize() == 8) return "f64";
      return "f" + std::to_string(ct->getSize() * 8);
    case TYPE_CODE: return "fn()";
    case TYPE_PTR: {
      const Datatype *to = ((const TypePointer *)ct)->getPtrTo();
      if (to->getMetatype() == TYPE_CODE) return "fn()";
      return "*mut " + rustType(to);
    }
    case TYPE_ARRAY: {
      const TypeArray *a = (const TypeArray *)ct;
      return "[" + rustType(a->getBase()) + "; " + std::to_string(a->numElements()) + "]";
    }
    default: {
      string n = ct->getDisplayName();
      return n.empty() ? genericTypeName(ct) : n;
    }
  }
}

// Every type is one token in Rust, so the C machinery for declarators
// (`int4 *x[3]`) collapses to a single atom.
void PrintRust::pushTypeStart(const Datatype *ct, bool noident) {
  pushOp(&type_expr_nospace, (const PcodeOp *)0);
  pushAtom(Atom(rustType(ct), typetoken, EmitMarkup::type_color, ct));
}

void PrintRust::pushTypeEnd(const Datatype *ct) {}

void PrintRust::pushType(const Datatype *ct) {
  pushAtom(Atom(rustType(ct), typetoken, EmitMarkup::type_color, ct));
}

void PrintRust::opCast(const PcodeOp *op) {
  Datatype *dt = op->getOut()->getHighTypeDefFacing();
  if (option_nocasts) {
    pushVn(op->getIn(0), op, mods);
    return;
  }
  // Operands enter the RPN stack in order, but varnodes are expanded lazily
  // (pushVn queues them), so expand the expression now, before the type.
  pushOp(&as_cast, op);
  pushVn(op->getIn(0), op, mods);
  recurse();
  pushType(dt);
}

void PrintRust::opIntNegate(const PcodeOp *op) { opUnary(&rust_not, op); }

void PrintRust::emitVarDecl(const Symbol *sym) {
  int4 id = emit->beginVarDecl(sym);
  pushSymbol(sym, (Varnode *)0, (PcodeOp *)0);
  recurse();
  emit->print(": ");
  emit->print(rustType(sym->getType()), EmitMarkup::type_color);
  emit->endVarDecl(id);
}

void PrintRust::emitVarDeclStatement(const Symbol *sym) {
  emit->tagLine();
  emit->print("let mut", EmitMarkup::keyword_color);
  emit->spaces(1);
  emitVarDecl(sym);
  emit->print(SEMICOLON);
}

void PrintRust::emitFunctionDeclaration(const Funcdata *fd) {
  const FuncProto *proto = &fd->getFuncProto();
  int4 id = emit->beginFuncProto();
  emit->print("fn", EmitMarkup::keyword_color);
  emit->spaces(1);
  int4 id1 = emit->openGroup();
  emitSymbolScope(fd->getSymbol());
  emit->tagFuncName(fd->getDisplayName(), EmitMarkup::funcname_color, fd, (PcodeOp *)0);
  int4 id2 = emit->openParen(OPEN_PAREN);
  pushScope(fd->getScopeLocal());
  int4 sz = proto->numParams();
  bool comma = false;
  for (int4 i = 0; i < sz; ++i) {
    ProtoParameter *param = proto->getParam(i);
    if (isSet(hide_thisparam) && param->isThisPointer()) continue;
    if (comma) emit->print(COMMA);
    comma = true;
    Symbol *sym = param->getSymbol();
    if (sym != (Symbol *)0)
      emitVarDecl(sym);
    else {
      emit->print("_: ");
      emit->print(rustType(param->getType()), EmitMarkup::type_color);
    }
  }
  if (proto->isDotdotdot()) {
    if (sz != 0) emit->print(COMMA);
    emit->print(DOTDOTDOT);
  }
  emit->closeParen(CLOSE_PAREN, id2);
  Datatype *out = proto->getOutputType();
  if (out->getMetatype() != TYPE_VOID) {
    emit->print(" -> ");
    int4 rid = emit->beginReturnType((Varnode *)0);
    emit->print(rustType(out), EmitMarkup::type_color);
    emit->endReturnType(rid);
  }
  emit->closeGroup(id1);
  emit->endFuncProto(id);
}

// `if cond {` : the condition is printed without parentheses
// (comma_separate makes opCbranch skip them).
void PrintRust::emitBlockIf(const BlockIf *bl) {
  const PcodeOp *op;
  PendingBrace pendingBrace(option_brace_ifelse);
  if (isSet(pending_brace)) emit->setPendingPrint(&pendingBrace);
  pushMod();
  unsetMod(no_branch | only_branch | pending_brace);
  pushMod();
  setMod(no_branch);
  FlowBlock *condBlock = bl->getBlock(0);
  condBlock->emit(this);
  popMod();
  emitCommentBlockTree(condBlock);
  if (emit->hasPendingPrint(&pendingBrace)) {
    emit->cancelPendingPrint();
    emit->spaces(1);
  } else
    emit->tagLine();
  op = condBlock->lastOp();
  emit->tagOp(KEYWORD_IF, EmitMarkup::keyword_color, op);
  emit->spaces(1);
  pushMod();
  setMod(only_branch | comma_separate);
  condBlock->emit(this);
  popMod();
  FlowBlock::block_type mainType = bl->getType();
  if (mainType == FlowBlock::t_ifgoto) {
    emit->spaces(1);
    emitGotoStatement(condBlock, ((const BlockIfGoto *)bl)->getGotoTarget(), ((const BlockIfGoto *)bl)->getGotoType());
  } else {
    setMod(no_branch);
    int4 id = emit->openBraceIndent(OPEN_CURLY, option_brace_ifelse);
    int4 id1 = emit->beginBlock(bl->getBlock(1));
    bl->getBlock(1)->emit(this);
    emit->endBlock(id1);
    emit->closeBraceIndent(CLOSE_CURLY, id);
    if (mainType == FlowBlock::t_ifelse) {
      emit->tagLine();
      emit->print(KEYWORD_ELSE, EmitMarkup::keyword_color);
      FlowBlock *elseBlock = bl->getBlock(2);
      FlowBlock::block_type type = elseBlock->getType();
      if (type == FlowBlock::t_if || type == FlowBlock::t_ifelse || type == FlowBlock::t_ifgoto) {
        setMod(pending_brace);
        int4 id2 = emit->beginBlock(elseBlock);
        elseBlock->emit(this);
        emit->endBlock(id2);
      } else {
        int4 id2 = emit->openBraceIndent(OPEN_CURLY, option_brace_ifelse);
        int4 id3 = emit->beginBlock(elseBlock);
        elseBlock->emit(this);
        emit->endBlock(id3);
        emit->closeBraceIndent(CLOSE_CURLY, id2);
      }
    } else if (mainType == FlowBlock::t_ifnoexit) {
      FlowBlock *followBlock = bl->getBlock(2);
      int4 id2 = emit->beginBlock(followBlock);
      followBlock->emit(this);
      emit->endBlock(id2);
    }
  }
  popMod();
  if (pendingBrace.getIndentId() >= 0) emit->closeBraceIndent(CLOSE_CURLY, pendingBrace.getIndentId());
}

// `while cond {`. A C `for (init; cond; step)` becomes
// `init; while cond { ..; step; }` (Rust has no C-style for).
void PrintRust::emitBlockWhileDo(const BlockWhileDo *bl) {
  const PcodeOp *op;
  int4 indent;
  pushMod();
  unsetMod(no_branch | only_branch);
  emitAnyLabelStatement(bl);
  FlowBlock *condBlock = bl->getBlock(0);
  op = condBlock->lastOp();
  const PcodeOp *initOp = bl->getInitializeOp();
  const PcodeOp *stepOp = bl->getIterateOp();
  if (bl->hasOverflowSyntax()) {
    emit->tagLine();
    emit->tagOp("loop", EmitMarkup::keyword_color, op);
    indent = emit->openBraceIndent(OPEN_CURLY, option_brace_loop);
    pushMod();
    setMod(no_branch);
    condBlock->emit(this);
    popMod();
    emitCommentBlockTree(condBlock);
    emit->tagLine();
    emit->tagOp(KEYWORD_IF, EmitMarkup::keyword_color, op);
    emit->spaces(1);
    pushMod();
    setMod(only_branch | comma_separate);
    condBlock->emit(this);
    popMod();
    emit->spaces(1);
    emitGotoStatement(condBlock, (const FlowBlock *)0, FlowBlock::f_break_goto);
  } else {
    emitCommentBlockTree(condBlock);
    if (stepOp != (PcodeOp *)0 && initOp != (PcodeOp *)0) {
      emit->tagLine();
      int4 id3 = emit->beginStatement(initOp);
      emitExpression(initOp);
      emit->endStatement(id3);
      emit->print(SEMICOLON);
    }
    emit->tagLine();
    emit->tagOp(KEYWORD_WHILE, EmitMarkup::keyword_color, op);
    emit->spaces(1);
    pushMod();
    setMod(comma_separate);
    condBlock->emit(this);
    popMod();
    indent = emit->openBraceIndent(OPEN_CURLY, option_brace_loop);
  }
  setMod(no_branch);
  int4 id2 = emit->beginBlock(bl->getBlock(1));
  bl->getBlock(1)->emit(this);
  emit->endBlock(id2);
  if (stepOp != (PcodeOp *)0 && !bl->hasOverflowSyntax()) {
    emit->tagLine();
    int4 id4 = emit->beginStatement(stepOp);
    emitExpression(stepOp);
    emit->endStatement(id4);
    emit->print(SEMICOLON);
  }
  emit->closeBraceIndent(CLOSE_CURLY, indent);
  popMod();
}

// C `do { body } while (cond);` becomes `loop { body; if !(cond) { break; } }`.
void PrintRust::emitBlockDoWhile(const BlockDoWhile *bl) {
  const PcodeOp *op;
  pushMod();
  unsetMod(no_branch | only_branch);
  emitAnyLabelStatement(bl);
  emit->tagLine();
  emit->print("loop", EmitMarkup::keyword_color);
  int4 id = emit->openBraceIndent(OPEN_CURLY, option_brace_loop);
  pushMod();
  int4 id2 = emit->beginBlock(bl->getBlock(0));
  setMod(no_branch);
  bl->getBlock(0)->emit(this);
  emit->endBlock(id2);
  popMod();
  emit->tagLine();
  op = bl->getBlock(0)->lastOp();
  emit->tagOp(KEYWORD_IF, EmitMarkup::keyword_color, op);
  emit->print(" !(");
  pushMod();
  setMod(only_branch | comma_separate);
  bl->getBlock(0)->emit(this);
  popMod();
  emit->print(") { ");
  emit->print(KEYWORD_BREAK, EmitMarkup::keyword_color);
  emit->print("; }");
  emit->closeBraceIndent(CLOSE_CURLY, id);
  popMod();
}

void PrintRust::emitBlockInfLoop(const BlockInfLoop *bl) {
  pushMod();
  unsetMod(no_branch | only_branch);
  emitAnyLabelStatement(bl);
  emit->tagLine();
  emit->print("loop", EmitMarkup::keyword_color);
  int4 id = emit->openBraceIndent(OPEN_CURLY, option_brace_loop);
  int4 id1 = emit->beginBlock(bl->getBlock(0));
  bl->getBlock(0)->emit(this);
  emit->endBlock(id1);
  emit->closeBraceIndent(CLOSE_CURLY, id);
  popMod();
}

}  // namespace ghidra
