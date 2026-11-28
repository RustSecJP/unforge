// mekiki-decomp: Ghidra's C++ decompiler (ghidra/, Apache-2.0) driven without
// Ghidra's Java side. Mekiki starts it as a separate process, so a crash or a
// runaway analysis on a hostile binary never takes the app down.
//
// usage: mekiki-decomp <specdir> <file> <target>, then commands on stdin:
//   seg <vaddr> <fileoff> <filesz> <flags>   a PT_LOAD mapping (hex; flags like "RE")
//   sym <addr> <name>                         a known function name (hex address)
//   decompile <addr>                          C for the function at addr, then "@@END <ms>ms"
// Errors are reported as "@@ERROR <message>". All numbers are hex.
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>

using namespace ghidra;
using std::istreambuf_iterator; using std::cin; using std::cout; using std::cerr; using std::endl; using std::getline; using std::ws; namespace chrono = std::chrono;

struct Seg { uint8 vaddr, off, size; bool writable; };

class MemLoadImage : public LoadImage {
  vector<uint1> data;
  vector<Seg> segs;
public:
  MemLoadImage(const string &f, const vector<Seg> &s) : LoadImage(f), segs(s) {
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
  }
  // Constants and jump tables live in segments that are not writable.
  void getReadonly(RangeList &list) const override {
    for (const Seg &s : segs)
      if (!s.writable && s.size > 0) list.insertRange(spc, s.vaddr, s.vaddr + s.size - 1);
  }
  AddrSpace *spc = nullptr;
  string getArchType(void) const override { return "mekiki"; }
  void adjustVma(long) override {}
};

class MemArchitecture : public SleighArchitecture {
  vector<Seg> segs;
public:
  MemArchitecture(const string &f, const string &t, const vector<Seg> &s, ostream *e) : SleighArchitecture(f, t, e), segs(s) {}
  void buildLoader(DocumentStorage &store) override {
    collectSpecFiles(*errorstream);
    loader = new MemLoadImage(getFilename(), segs);
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

  vector<Seg> segs;
  vector<pair<uint8, string>> syms;
  string line;
  MemArchitecture *arch = nullptr;
  auto ensure = [&]() {
    if (arch) return;
    arch = new MemArchitecture(argv[2], argv[3], segs, &cerr);
    DocumentStorage store;
    arch->init(store);
    Scope *global = arch->symboltab->getGlobalScope();
    for (auto &s : syms) {
      Address a(arch->getDefaultCodeSpace(), s.first);
      if (global->findFunction(a) == nullptr) global->addFunction(a, s.second);
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
