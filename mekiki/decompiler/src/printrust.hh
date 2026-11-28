// A Rust-flavored output language for Ghidra's decompiler.
//
// Built on Ghidra's C printer (PrintC, like Ghidra's own PrintJava): the
// decompiler's analysis is unchanged, only how the result is written
// differs:
//   - types:        int4 -> i32, uint1 * -> *mut u8, undefined8 -> u64, T[4] -> [T; 4]
//   - declarations: `let mut x: i32;`, `fn f(a: *mut u8, n: i64) -> i32`
//   - casts:        `x as i32`
//   - control flow: `if c {`, `while c {`, `loop { ..; if !(c) { break; } }`, `loop {`
//   - bitwise not:  `!x`
//   - counting loops: `i = start; loop { ..; i = i + 1; if !(i != n) break }`
//                   (and Ghidra's for-loops) become `for i in start..n { .. }`
//   - slices:       a (pointer, length) parameter pair that is indexed and
//                   bounds-checked becomes `v: &[T]`, `v[i]`, `v.len()`; a byte
//                   slice compared with characters becomes `s: &str`, `s.as_bytes()[i]`
// What it does not do (yet): iterators and Option/Result. Elsewhere the
// output reads like unsafe Rust over raw pointers, which is what the
// machine code does.
#ifndef MEKIKI_PRINTRUST_HH
#define MEKIKI_PRINTRUST_HH

#include "printc.hh"

namespace ghidra {

class PrintRustCapability : public PrintLanguageCapability {
  PrintRustCapability(void);
  PrintRustCapability(const PrintRustCapability &op2) = delete;
  PrintRustCapability &operator=(const PrintRustCapability &op) = delete;
public:
  static PrintRustCapability printRustCapability;
  virtual PrintLanguage *buildLanguage(Architecture *glb);
};

class PrintRust : public PrintC {
  static OpToken as_cast;
  static OpToken rust_not;
  /// A (pointer, length) parameter pair recognized as one slice parameter.
  struct SliceParam {
    const Symbol *ptr;
    const Symbol *len;
    Datatype *elem;
    bool text;  ///< bytes compared with printable characters: shown as `&str`
  };
  /// A LOAD that reads an element of a slice: `ptr[index]`.
  struct SliceLoad {
    const Symbol *ptr;
    const Varnode *index;   ///< null when the index is the constant `cindex`
    uintb cindex;
  };
  vector<SliceParam> slices;
  map<const PcodeOp *, SliceLoad> sliceLoads;
  /// Statements not to print (the `i = i + 1` of a loop shown as `for`).
  set<const PcodeOp *> suppressed;
  /// A counting loop: `for var in start..bound`.
  struct RangeLoop {
    const Varnode *var;     ///< the loop variable (phi output)
    const Varnode *start;   ///< its value on entry
    const Varnode *bound;   ///< exclusive upper bound
    const PcodeOp *step;    ///< the `var = var + 1` statement
    const PcodeOp *copy;    ///< `var = tmp` after `tmp = var + 1`, or null
    const PcodeOp *cond;    ///< the branch (context for printing)
  };
  bool findRangeLoop(const FlowBlock *loop, const PcodeOp *cbranch, bool topTest, RangeLoop &out);
  void emitRangeHeader(const RangeLoop &r);
  void findSlices(const Funcdata *fd);
  const SliceParam *sliceOfPtr(const Symbol *sym) const;
  const SliceParam *sliceOfLen(const Symbol *sym) const;
public:
  PrintRust(Architecture *g, const string &nm = "rust-language");
  string rustType(const Datatype *ct);
  virtual void pushType(const Datatype *ct);
  virtual void pushTypeStart(const Datatype *ct, bool noident);
  virtual void pushTypeEnd(const Datatype *ct);
  virtual void opCast(const PcodeOp *op);
  virtual void opIntNegate(const PcodeOp *op);
  virtual void emitVarDecl(const Symbol *sym);
  virtual void emitVarDeclStatement(const Symbol *sym);
  virtual void emitFunctionDeclaration(const Funcdata *fd);
  virtual void emitBlockIf(const BlockIf *bl);
  virtual void emitBlockWhileDo(const BlockWhileDo *bl);
  virtual void emitBlockDoWhile(const BlockDoWhile *bl);
  virtual void emitBlockInfLoop(const BlockInfLoop *bl);
  virtual void docFunction(const Funcdata *fd);
  virtual void emitBlockBasic(const BlockBasic *bb);
  virtual void opLoad(const PcodeOp *op);
  virtual void pushSymbol(const Symbol *sym, const Varnode *vn, const PcodeOp *op);
};

}  // namespace ghidra

#endif
