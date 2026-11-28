// mekiki-decomp: Ghidra's C++ decompiler (ghidra/, Apache-2.0) driven without
// Ghidra's Java side. Mekiki starts it as a separate process, so a crash or a
// runaway analysis on a hostile binary never takes the app down.
//
// usage: mekiki-decomp <specdir> <file> <target>, then commands on stdin:
//   seg <vaddr> <fileoff> <filesz> <flags>   a PT_LOAD mapping (hex; flags like "RE")
//   sym <addr> <name>                         a known function name (hex address)
//   ptr <slot> <value>                        8-byte pointer the loader writes at slot (relocation)
//   ext <slot> <name>                         slot points to the imported symbol <name>
//   lang <rust|c>                             output language for the next decompiles (default rust)
//   decompile <addr>                          code for the function at addr, then "@@END <ms>ms"
// Errors are reported as "@@ERROR <message>". All numbers are hex.
#include "sleigh_arch.hh"
#include "printrust.hh"
#include "funcdata.hh"
#include "loadimage.hh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>
#include <map>

using namespace ghidra;
using std::istreambuf_iterator; using std::cin; using std::cout; using std::cerr; using std::endl; using std::getline; using std::ws; namespace chrono = std::chrono;

struct Seg { uint8 vaddr, off, size; bool writable; };

// Relocated pointer slots: slot address -> the 8-byte value the loader writes.
typedef std::map<uint8, uint8> Overlays;

class MemLoadImage : public LoadImage {
  vector<uint1> data;
  vector<Seg> segs;
  Overlays overlays;
public:
  MemLoadImage(const string &f, const vector<Seg> &s, const Overlays &o) : LoadImage(f), segs(s), overlays(o) {
    ifstream in(f, ios::binary);
    data.assign(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
  }
  void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
    uint8 a = addr.getOffset();
    for (int4 i = 0; i < size; ++i) {
      ptr[i] = 0;
      uint8 x = a + i;
      for (const Seg &s : segs) {
        if (x >= s.vaddr && x - s.vaddr < s.size) {
          uint8 o = s.off + (x - s.vaddr);
          if (o < data.size()) ptr[i] = data[o];
          break;
        }
      }
    }
    // Apply relocations that touch [a, a + size).
    auto it = overlays.lower_bound(a >= 7 ? a - 7 : 0);
    for (; it != overlays.end() && it->first < a + size; ++it)
      for (int4 b = 0; b < 8; ++b) {
        uint8 x = it->first + b;
        if (x >= a && x < a + size) ptr[x - a] = (uint1)(it->second >> (8 * b));
      }
  }
  // Constants and jump tables live in segments that are not writable.
  void getReadonly(RangeList &list) const override {
    for (const Seg &s : segs)
      if (!s.writable && s.size > 0) list.insertRange(spc, s.vaddr, s.vaddr + s.size - 1);
    // Relocated slots (the GOT) are written once at load time and then read-only
    // (RELRO), so their values can be propagated into indirect calls.
    for (auto &o : overlays) list.insertRange(spc, o.first, o.first + 7);
  }
  AddrSpace *spc = nullptr;
  string getArchType(void) const override { return "mekiki"; }
  void adjustVma(long) override {}
};

// Rust functions (and C ones Rust calls) that never return: panics, failed
// unwrap/expect, allocation failure, process exit. Telling the decompiler
// keeps it from printing the unreachable code that follows the call.
static bool isNoReturnName(const string &n) {
  static const char *contains[] = {
    "core::panicking::", "std::panicking::begin_panic", "std::panicking::rust_panic",
    "core::option::unwrap_failed", "core::option::expect_failed", "core::result::unwrap_failed",
    "core::slice::index::slice_", "core::str::slice_error_fail", "alloc::alloc::handle_alloc_error",
    "alloc::raw_vec::capacity_overflow", "alloc::raw_vec::handle_error", "std::process::exit",
    "std::process::abort", "std::sys::pal::unix::abort_internal", "__rust_start_panic",
    "rust_panic", "core::cell::panic_already_borrowed", "core::cell::panic_already_mutably_borrowed",
  };
  for (const char *c : contains)
    if (n.find(c) != string::npos) return true;
  static const char *exact[] = { "exit", "_exit", "abort", "__stack_chk_fail", "__assert_fail" };
  for (const char *e : exact)
    if (n == e) return true;
  return false;
}

class MemArchitecture : public SleighArchitecture {
  vector<Seg> segs;
  Overlays overlays;
public:
  MemArchitecture(const string &f, const string &t, const vector<Seg> &s, const Overlays &o, ostream *e)
      : SleighArchitecture(f, t, e), segs(s), overlays(o) {}
  void buildLoader(DocumentStorage &store) override {
    collectSpecFiles(*errorstream);
    loader = new MemLoadImage(getFilename(), segs, overlays);
  }
  void postSpecFile(void) override {
    Architecture::postSpecFile();
    ((MemLoadImage *)loader)->spc = getDefaultCodeSpace();
  }
  void resolveArchitecture(void) override {
    archid = getTarget();
    SleighArchitecture::resolveArchitecture();
  }
};

extern "C" int mekiki_decomp_main(int argc, char **argv) {
  if (argc < 4) { cerr << "usage: mekiki-decomp <specdir> <file> <target>\n"; return 2; }
  AttributeId::initialize();
  ElementId::initialize();
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();
  SleighArchitecture::specpaths.addDir2Path(argv[1]);

  // Referencing the capability keeps printrust.o (and its registration) in the link.
  if (PrintRustCapability::printRustCapability.getName().empty()) return 1;
  vector<Seg> segs;
  vector<pair<uint8, string>> syms;
  Overlays overlays;
  // Imports get stand-in addresses far from the image, named after the symbol,
  // so a call through their GOT slot prints as a call to the name.
  const uint8 IMPORT_BASE = 0xfff0000000000000ULL;
  uint8 nextImport = IMPORT_BASE;
  string lang = "rust-language";
  string line;
  MemArchitecture *arch = nullptr;
  auto ensure = [&]() {
    if (arch) return;
    arch = new MemArchitecture(argv[2], argv[3], segs, overlays, &cerr);
    DocumentStorage store;
    arch->init(store);
    // Like Ghidra's "Respect Read-only Flags" (on by default there): values in
    // read-only memory, including relocated GOT slots, are treated as constants.
    arch->readonlypropagate = true;
    arch->setPrintLanguage(lang);
    Scope *global = arch->symboltab->getGlobalScope();
    for (auto &s : syms) {
      Address a(arch->getDefaultCodeSpace(), s.first);
      Funcdata *f = global->findFunction(a);
      if (f == nullptr) f = global->addFunction(a, s.second)->getFunction();
      if (f != nullptr && isNoReturnName(s.second)) f->getFuncProto().setNoReturn(true);
    }
  };
  while (getline(cin, line)) {
    istringstream in(line);
    string cmd;
    in >> cmd;
    try {
      if (cmd == "seg") {
        Seg s; string flags; in >> hex >> s.vaddr >> s.off >> s.size >> flags;
        s.writable = flags.find('W') != string::npos; segs.push_back(s);
      } else if (cmd == "sym") {
        uint8 a; string name; in >> hex >> a; getline(in >> ws, name); syms.push_back({a, name});
      } else if (cmd == "ptr") {
        uint8 slot, value; in >> hex >> slot >> value; overlays[slot] = value;
      } else if (cmd == "ext") {
        uint8 slot; string name; in >> hex >> slot; getline(in >> ws, name);
        overlays[slot] = nextImport;
        syms.push_back({nextImport, name});
        nextImport += 0x10;
      } else if (cmd == "lang") {
        string l; in >> l;
        lang = (l == "c") ? "c-language" : "rust-language";
        if (arch) arch->setPrintLanguage(lang);
      } else if (cmd == "decompile") {
        ensure();
        uint8 a; in >> hex >> a;
        auto t0 = chrono::steady_clock::now();
        Address addr(arch->getDefaultCodeSpace(), a);
        Scope *global = arch->symboltab->getGlobalScope();
        Funcdata *fd = global->findFunction(addr);
        if (fd == nullptr) {
          ostringstream nm; nm << "FUN_" << hex << a;
          fd = global->addFunction(addr, nm.str())->getFunction();
        }
        arch->clearAnalysis(fd);
        Action *act = arch->allacts.getCurrent();
        act->reset(*fd);
        act->perform(*fd);
        arch->print->setOutputStream(&cout);
        arch->print->docFunction(fd);
        auto ms = chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - t0).count();
        arch->clearAnalysis(fd);  // free this function's analysis
        cout << "@@END " << ms << "ms" << endl;
      }
    } catch (LowlevelError &e) {
      cout << "@@ERROR " << e.explain << endl;
    } catch (std::exception &e) {
      cout << "@@ERROR " << e.what() << endl;
    }
  }
  return 0;
}
