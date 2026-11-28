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
// What it does not do (yet): Rust idioms such as slices, iterators and
// Option/Result. The output reads like unsafe Rust over raw pointers, which
// is what the machine code does.
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
};

}  // namespace ghidra

#endif
