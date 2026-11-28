// Builds the decompiler helper (decompiler/, C++ + Rust) and puts it where
// Tauri expects a sidecar: src-tauri/binaries/mekiki-decomp-<target triple>.
//
// The target is the one Tauri builds for (TAURI_ENV_TARGET_TRIPLE, set for
// beforeBuildCommand), else the host. For `universal-apple-darwin` both
// macOS architectures are built and also joined with lipo.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const root = join(import.meta.dirname, '..')
const manifest = join(root, 'decompiler', 'Cargo.toml')
const host = /host: (\S+)/.exec(execFileSync('rustc', ['-vV']).toString())[1]
const target = process.env.TAURI_ENV_TARGET_TRIPLE || host
const ext = target.includes('windows') ? '.exe' : ''
const binaries = join(root, 'src-tauri', 'binaries')
mkdirSync(binaries, { recursive: true })

function build(triple) {
  const args = ['build', '--release', '--manifest-path', manifest]
  if (triple !== host) args.push('--target', triple)
  execFileSync('cargo', args, { stdio: 'inherit' })
  const dir = triple === host ? 'release' : join(triple, 'release')
  return join(root, 'decompiler', 'target', dir, `mekiki-decomp${ext}`)
}

if (target === 'universal-apple-darwin') {
  // Tauri builds each architecture, then joins them, so it wants all three.
  const triples = ['aarch64-apple-darwin', 'x86_64-apple-darwin']
  const parts = triples.map(build)
  triples.forEach((t, i) => copyFileSync(parts[i], join(binaries, `mekiki-decomp-${t}`)))
  const out = join(binaries, `mekiki-decomp-${target}`)
  execFileSync('lipo', ['-create', '-output', out, ...parts], { stdio: 'inherit' })
} else {
  copyFileSync(build(target), join(binaries, `mekiki-decomp-${target}${ext}`))
}
console.log(`mekiki-decomp for ${target} is ready`)
