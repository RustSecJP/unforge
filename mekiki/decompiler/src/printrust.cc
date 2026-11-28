// See printrust.hh. The block emitters follow PrintC's (ghidra/printc.cc)
// closely, changing only the syntax.
#include "printrust.hh"
#include "funcdata.hh"
#include "op.hh"

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

// ---- slices ---------------------------------------------------------------

// The symbol a varnode belongs to, or null.
static const Symbol *symbolOf(const Varnode *vn) {
  if (vn == (const Varnode *)0 || vn->isConstant() || vn->isAnnotation()) return (const Symbol *)0;
  try {
    return vn->getHigh()->getSymbol();
  } catch (LowlevelError &) {
    return (const Symbol *)0;  // no high-level variable (dead or not yet merged)
  }
}

// Looks through casts and copies that are not printed on their own.
static const Varnode *throughCasts(const Varnode *vn) {
  while (vn->isWritten() && vn->isImplied()) {
    OpCode c = vn->getDef()->code();
    if (c != CPUI_CAST && c != CPUI_COPY) break;
    vn = vn->getDef()->getIn(0);
  }
  return vn;
}

// If `addr` (the address a LOAD of `size` bytes reads) is `ptr + index*size`,
// `ptr + c` or `ptr` for a parameter `ptr`, returns ptr's symbol and fills
// index / cindex.
static const Symbol *elementAddress(const Varnode *addr, int4 size, const Varnode *&index, uintb &cindex) {
  index = (const Varnode *)0;
  cindex = 0;
  addr = throughCasts(addr);
  const Symbol *direct = symbolOf(addr);
  if (direct != (const Symbol *)0 && direct->getCategory() == Symbol::function_parameter) return direct;
  if (!addr->isWritten() || !addr->isImplied()) return (const Symbol *)0;
  const PcodeOp *def = addr->getDef();
  if (def->code() == CPUI_PTRADD) {
    const Varnode *k = def->getIn(2);
    if (!k->isConstant() || (int4)k->getOffset() != size) return (const Symbol *)0;
    const Symbol *base = symbolOf(throughCasts(def->getIn(0)));
    if (base == (const Symbol *)0 || base->getCategory() != Symbol::function_parameter) return (const Symbol *)0;
    const Varnode *i = def->getIn(1);
    if (i->isConstant()) cindex = i->getOffset(); else index = i;
    return base;
  }
  if (def->code() != CPUI_INT_ADD) return (const Symbol *)0;
  for (int4 side = 0; side < 2; ++side) {
    const Symbol *base = symbolOf(throughCasts(def->getIn(side)));
    if (base == (const Symbol *)0 || base->getCategory() != Symbol::function_parameter) continue;
    const Varnode *off = throughCasts(def->getIn(1 - side));
    if (off->isConstant()) {
      if (off->getOffset() % size != 0) return (const Symbol *)0;
      cindex = off->getOffset() / size;
      return base;
    }
    if (size == 1) {
      index = off;
      return base;
    }
    if (off->isWritten() && off->isImplied() && off->getDef()->code() == CPUI_INT_MULT) {
      const PcodeOp *m = off->getDef();
      for (int4 j = 0; j < 2; ++j) {
        const Varnode *k = m->getIn(1 - j);
        if (k->isConstant() && (int4)k->getOffset() == size) {
          index = m->getIn(j);
          return base;
        }
      }
    }
    return (const Symbol *)0;
  }
  return (const Symbol *)0;
}

static bool isComparison(OpCode c) {
  return c == CPUI_INT_LESS || c == CPUI_INT_LESSEQUAL || c == CPUI_INT_SLESS || c == CPUI_INT_SLESSEQUAL ||
         c == CPUI_INT_EQUAL || c == CPUI_INT_NOTEQUAL;
}

// Rust passes `&[T]` and `&str` as two arguments, pointer then length. A
// pair of parameters is taken for a slice when the pointer is only read as
// `ptr[i]` with one element size, is never reassigned, and the length is
// compared with something (a bounds check or a loop bound) without being
// the index itself.
void PrintRust::findSlices(const Funcdata *fd) {
  slices.clear();
  sliceLoads.clear();
  const FuncProto &proto = fd->getFuncProto();
  int4 n = proto.numParams();
  for (int4 i = 0; i + 1 < n; ++i) {
    const Symbol *ptr = proto.getParam(i)->getSymbol();
    const Symbol *len = proto.getParam(i + 1)->getSymbol();
    if (ptr == (const Symbol *)0 || len == (const Symbol *)0) continue;
    int4 wsize = glb->getDefaultDataSpace()->getAddrSize();
    if (proto.getParam(i)->getSize() != wsize || proto.getParam(i + 1)->getSize() != wsize) continue;
    bool ok = true, lenCompared = false;
    int4 esize = 0;
    Datatype *elem = (Datatype *)0;
    map<const PcodeOp *, SliceLoad> loads;
    list<PcodeOp *>::const_iterator it;
    for (it = fd->beginOpAlive(); ok && it != fd->endOpAlive(); ++it) {
      const PcodeOp *op = *it;
      for (int4 k = 0; k < op->numInput(); ++k) {
        const Varnode *in = op->getIn(k);
        if (symbolOf(in) == len && isComparison(op->code())) lenCompared = true;
      }
      const Varnode *out = op->getOut();
      if (out != (const Varnode *)0 && symbolOf(out) == ptr) ok = false;  // reassigned
      if (op->code() != CPUI_LOAD) continue;
      const Varnode *index;
      uintb cindex;
      int4 size = op->getOut()->getSize();
      if (elementAddress(op->getIn(1), size, index, cindex) != ptr) continue;
      if (index != (const Varnode *)0 && symbolOf(index) == len) ok = false;  // len used as an index: not a length
      if (esize != 0 && esize != size) ok = false;
      esize = size;
      if (elem == (Datatype *)0) elem = op->getOut()->getHighTypeDefFacing();
      loads[op] = SliceLoad{ptr, index, cindex};
    }
    if (!ok || !lenCompared || loads.empty()) continue;
    // Text: an element read is compared with a printable ASCII constant.
    bool text = false;
    if (esize == 1) {
      for (auto &l : loads) {
        const Varnode *v = l.first->getOut();
        list<PcodeOp *>::const_iterator d;
        for (d = v->beginDescend(); !text && d != v->endDescend(); ++d) {
          const PcodeOp *use = *d;
          // look through a sign/zero extension of the byte
          if ((use->code() == CPUI_INT_ZEXT || use->code() == CPUI_INT_SEXT) && use->getOut() != (Varnode *)0 &&
              use->getOut()->beginDescend() != use->getOut()->endDescend())
            use = *use->getOut()->beginDescend();
          if (!isComparison(use->code())) continue;
          for (int4 k = 0; k < use->numInput(); ++k) {
            const Varnode *c = use->getIn(k);
            if (c->isConstant() && c->getOffset() >= 0x20 && c->getOffset() < 0x7f) text = true;
          }
        }
      }
    }
    slices.push_back(SliceParam{ptr, len, elem, text});
    sliceLoads.insert(loads.begin(), loads.end());
    ++i;  // the length is taken
  }
}

const PrintRust::SliceParam *PrintRust::sliceOfPtr(const Symbol *sym) const {
  for (const SliceParam &s : slices)
    if (s.ptr == sym) return &s;
  return (const SliceParam *)0;
}

const PrintRust::SliceParam *PrintRust::sliceOfLen(const Symbol *sym) const {
  for (const SliceParam &s : slices)
    if (s.len == sym) return &s;
  return (const SliceParam *)0;
}

void PrintRust::docFunction(const Funcdata *fd) {
  findSlices(fd);
  PrintC::docFunction(fd);
  slices.clear();
  sliceLoads.clear();
}

// `v[i]` for a recognized slice element read.
void PrintRust::opLoad(const PcodeOp *op) {
  map<const PcodeOp *, SliceLoad>::const_iterator it = sliceLoads.find(op);
  if (it == sliceLoads.end()) {
    PrintC::opLoad(op);
    return;
  }
  const SliceLoad &l = it->second;
  const SliceParam *s = sliceOfPtr(l.ptr);
  string base = l.ptr->getDisplayName() + (s != (const SliceParam *)0 && s->text ? ".as_bytes()" : "");
  pushOp(&subscript, op);
  pushAtom(Atom(base, vartoken, EmitMarkup::param_color, op, (const Varnode *)0));
  if (l.index != (const Varnode *)0)
    pushVn(l.index, op, mods);
  else
    pushAtom(Atom(std::to_string(l.cindex), syntax, EmitMarkup::const_color, op, (const Varnode *)0));
}

// The length of a slice prints as `v.len()`; its pointer, outside `v[i]`, as `v.as_ptr()`.
void PrintRust::pushSymbol(const Symbol *sym, const Varnode *vn, const PcodeOp *op) {
  if (const SliceParam *s = sliceOfLen(sym)) {
    pushAtom(Atom(s->ptr->getDisplayName() + ".len()", vartoken, EmitMarkup::param_color, op, vn));
    return;
  }
  if (const SliceParam *s = sliceOfPtr(sym)) {
    pushAtom(Atom(s->ptr->getDisplayName() + ".as_ptr()", vartoken, EmitMarkup::param_color, op, vn));
    return;
  }
  PrintC::pushSymbol(sym, vn, op);
}

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
    if (param->getSymbol() != (Symbol *)0 && sliceOfLen(param->getSymbol()) != (const SliceParam *)0) continue;
    if (comma) emit->print(COMMA);
    comma = true;
    Symbol *sym = param->getSymbol();
    const SliceParam *slice = sym != (Symbol *)0 ? sliceOfPtr(sym) : (const SliceParam *)0;
    if (slice != (const SliceParam *)0) {
      int4 vid = emit->beginVarDecl(sym);
      emit->print(sym->getDisplayName(), EmitMarkup::param_color);
      emit->print(": ");
      emit->print(slice->text ? "&str" : "&[" + rustType(slice->elem) + "]", EmitMarkup::type_color);
      emit->endVarDecl(vid);
    } else if (sym != (Symbol *)0)
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
  } else if (RangeLoop range; findRangeLoop(bl, condBlock->lastOp(), true, range)) {
    emitCommentBlockTree(condBlock);
    emitRangeHeader(range);
    indent = emit->openBraceIndent(OPEN_CURLY, option_brace_loop);
    suppressed.insert(range.step);
    if (range.copy != (const PcodeOp *)0) suppressed.insert(range.copy);
    setMod(no_branch);
    int4 id2 = emit->beginBlock(bl->getBlock(1));
    bl->getBlock(1)->emit(this);
    emit->endBlock(id2);
    suppressed.clear();
    emit->closeBraceIndent(CLOSE_CURLY, indent);
    popMod();
    return;
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

// ---- counting loops --------------------------------------------------------

// Recognizes `var' = var + 1` compared with a bound, where `var` is the phi
// (MULTIEQUAL) of the loop head merging an entry value and `var'`:
//   bottom test (do-while): continue while `var' != bound` or `var' < bound`
//   top test (while-do):    continue while `var != bound`  or `var < bound`
// and nothing else writes the loop variable.
// The basic blocks under a structured block. Ops belong to basic blocks
// (BlockBasic); the structured tree refers to them through BlockCopy.
static void basicBlocks(const FlowBlock *b, set<const FlowBlock *> &out) {
  if (b == (const FlowBlock *)0) return;
  if (b->getType() == FlowBlock::t_copy) {
    out.insert(b->subBlock(0));
    return;
  }
  if (b->getType() == FlowBlock::t_basic) {
    out.insert(b);
    return;
  }
  const BlockGraph *g = dynamic_cast<const BlockGraph *>(b);
  if (g == (const BlockGraph *)0) return;
  for (int4 i = 0; i < g->getSize(); ++i) basicBlocks(g->subBlock(i), out);
}

static thread_local set<const FlowBlock *> loopBlocks;

static bool inside(const PcodeOp *op, const FlowBlock *) {
  return loopBlocks.count(op->getParent()) != 0;
}

// `out = in + 1`
static bool isIncrement(const PcodeOp *op, const Varnode *in) {
  return op != (const PcodeOp *)0 && op->code() == CPUI_INT_ADD && op->getIn(0) == in && op->getIn(1)->isConstant() &&
         op->getIn(1)->getOffset() == 1;
}

bool PrintRust::findRangeLoop(const FlowBlock *loop, const PcodeOp *cbranch, bool topTest, RangeLoop &out) {
  if (cbranch == (const PcodeOp *)0 || cbranch->code() != CPUI_CBRANCH) return false;
  loopBlocks.clear();
  basicBlocks(loop, loopBlocks);
  const Varnode *b = cbranch->getIn(1);
  if (!b->isWritten()) return false;
  const PcodeOp *cmp = b->getDef();
  OpCode c = cmp->code();
  bool flip = cbranch->isBooleanFlip();
  // the printed condition is the "keep looping" condition
  bool ne = (c == CPUI_INT_NOTEQUAL && !flip) || (c == CPUI_INT_EQUAL && flip);
  bool lt = (c == CPUI_INT_LESS || c == CPUI_INT_SLESS) && !flip;
  if (!ne && !lt) return false;
  for (int4 side = 0; side < 2; ++side) {
    if (lt && side == 1) break;  // `i < bound`: the counter is the left operand
    const Varnode *counted = cmp->getIn(side);
    const Varnode *bound = cmp->getIn(1 - side);
    // the phi of the loop head, the increment, and an optional copy back
    const Varnode *phiOut = (const Varnode *)0;
    const PcodeOp *step = (const PcodeOp *)0, *copy = (const PcodeOp *)0;
    if (topTest) {
      phiOut = counted;  // tested before the step
    } else if (counted->isWritten()) {
      step = counted->getDef();
      if (step->code() != CPUI_INT_ADD) continue;
      phiOut = step->getIn(0);
    }
    if (phiOut == (const Varnode *)0 || !phiOut->isWritten() || phiOut->getDef()->code() != CPUI_MULTIEQUAL) continue;
    const PcodeOp *phi = phiOut->getDef();
    if (phi->numInput() < 2 || !inside(phi, loop)) continue;
    const Varnode *start = (const Varnode *)0;
    int4 entries = 0;
    bool entriesShareVar = true;
    for (int4 k = 0; k < phi->numInput(); ++k) {
      const Varnode *in = phi->getIn(k);
      const PcodeOp *d = in->isWritten() ? in->getDef() : (const PcodeOp *)0;
      if (d != (const PcodeOp *)0 && d->code() == CPUI_COPY && d->getIn(0)->isWritten() && inside(d, loop) &&
          isIncrement(d->getIn(0)->getDef(), phiOut) && (step == (const PcodeOp *)0 || step == d->getIn(0)->getDef())) {
        copy = d;
        step = d->getIn(0)->getDef();
      } else if (isIncrement(d, phiOut) && (step == (const PcodeOp *)0 || step == d)) {
        step = d;
      } else {
        start = in;
        ++entries;
        try {
          if (in->getHigh() != phiOut->getHigh()) entriesShareVar = false;
        } catch (LowlevelError &) {
          entriesShareVar = false;
        }
      }
    }
    // Several ways into the loop: fine when they all carry the loop
    // variable itself (`for i in i..n`).
    if (entries > 1) {
      if (!entriesShareVar) continue;
      start = phiOut;
    }
    if (start == (const Varnode *)0 || step == (const PcodeOp *)0 || !isIncrement(step, phiOut)) continue;
    // with a copy back, the temporary may feed only the copy and the test
    if (copy != (const PcodeOp *)0) {
      const Varnode *tmp = step->getOut();
      bool only = true;
      for (list<PcodeOp *>::const_iterator d = tmp->beginDescend(); d != tmp->endDescend(); ++d)
        if (*d != copy && *d != cmp) only = false;
      if (!only) continue;
    }
    // inside the loop, nothing else may write the loop variable
    HighVariable *h;
    try {
      h = phiOut->getHigh();
    } catch (LowlevelError &) {
      continue;
    }
    bool clean = true;
    for (int4 k = 0; k < h->numInstances(); ++k) {
      const Varnode *v = h->getInstance(k);
      if (!v->isWritten()) continue;
      const PcodeOp *d = v->getDef();
      if (d == phi || d == step || d == copy || !inside(d, loop)) continue;
      clean = false;
    }
    if (!clean) continue;
    out = RangeLoop{phiOut, start, bound, step, copy, cbranch};
    return true;
  }
  return false;
}

// `for var in start..bound {`
void PrintRust::emitRangeHeader(const RangeLoop &r) {
  emit->tagLine();
  emit->tagOp(KEYWORD_FOR, EmitMarkup::keyword_color, r.cond);
  emit->spaces(1);
  pushVn(r.var, r.cond, mods);
  recurse();
  emit->print(" in ", EmitMarkup::keyword_color);
  // the entry value is printed as an expression (a constant or a variable);
  // a copy into the loop variable itself is shown as its source
  const Varnode *start = r.start;
  if (start->isWritten() && start->getDef()->code() == CPUI_COPY) start = start->getDef()->getIn(0);
  pushVn(start, r.cond, mods);
  recurse();
  emit->print("..");
  pushVn(r.bound, r.cond, mods);
  recurse();
}

// PrintC::emitBlockBasic, skipping `suppressed` statements.
void PrintRust::emitBlockBasic(const BlockBasic *bb) {
  const PcodeOp *inst;
  bool separator;
  commsorter.setupBlockList(bb);
  emitLabelStatement(bb);
  if (isSet(only_branch)) {
    inst = bb->lastOp();
    if (inst->isBranch()) emitExpression(inst);
    return;
  }
  separator = false;
  list<PcodeOp *>::const_iterator iter;
  for (iter = bb->beginOp(); iter != bb->endOp(); ++iter) {
    inst = *iter;
    if (inst->notPrinted()) continue;
    if (suppressed.count(inst) != 0) continue;
    if (inst->isBranch()) {
      if (isSet(no_branch)) continue;
      if (inst->code() == CPUI_BRANCH) continue;
    }
    const Varnode *vn = inst->getOut();
    if ((vn != (const Varnode *)0) && (vn->isImplied())) continue;
    if (separator) {
      if (isSet(comma_separate)) {
        emit->print(COMMA);
        emit->spaces(1);
      } else {
        emitCommentGroup(inst);
        emit->tagLine();
      }
    } else if (!isSet(comma_separate)) {
      emitCommentGroup(inst);
      emit->tagLine();
    }
    emitStatement(inst);
    separator = true;
  }
  if (isSet(flat) && isSet(nofallthru)) {
    inst = bb->lastOp();
    emit->tagLine();
    int4 id = emit->beginStatement(inst);
    emit->print(KEYWORD_GOTO, EmitMarkup::keyword_color);
    emit->spaces(1);
    if (bb->sizeOut() == 2) {
      if (inst->isFallthruTrue())
        emitLabel(bb->getOut(1));
      else
        emitLabel(bb->getOut(0));
    } else
      emitLabel(bb->getOut(0));
    emit->print(SEMICOLON);
    emit->endStatement(id);
  }
}

// C `do { body } while (cond);` becomes `loop { body; if !(cond) { break; } }`.
void PrintRust::emitBlockDoWhile(const BlockDoWhile *bl) {
  const PcodeOp *op;
  RangeLoop range;
  if (findRangeLoop(bl, bl->getBlock(0)->lastOp(), false, range)) {
    pushMod();
    unsetMod(no_branch | only_branch);
    emitAnyLabelStatement(bl);
    emitRangeHeader(range);
    int4 id = emit->openBraceIndent(OPEN_CURLY, option_brace_loop);
    suppressed.insert(range.step);
    if (range.copy != (const PcodeOp *)0) suppressed.insert(range.copy);
    pushMod();
    int4 id2 = emit->beginBlock(bl->getBlock(0));
    setMod(no_branch);
    bl->getBlock(0)->emit(this);
    emit->endBlock(id2);
    popMod();
    suppressed.clear();
    emit->closeBraceIndent(CLOSE_CURLY, id);
    popMod();
    return;
  }
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
