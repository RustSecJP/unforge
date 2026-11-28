// Builds the decompiler helper (decompiler/, C++ + Rust) and puts it where
// Tauri expects a sidecar: src-tauri/binaries/mekiki-decomp-<target triple>.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

const root = join(import.meta.dirname, '..')
const triple = /host: (\S+)/.exec(execFileSync('rustc', ['-vV']).toString())[1]
const ext = process.platform === 'win32' ? '.exe' : ''
execFileSync('cargo', ['build', '--release', '--manifest-path', join(root, 'decompiler', 'Cargo.toml')], { stdio: 'inherit' })
mkdirSync(join(root, 'src-tauri', 'binaries'), { recursive: true })
copyFileSync(join(root, 'decompiler', 'target', 'release', `mekiki-decomp${ext}`), join(root, 'src-tauri', 'binaries', `mekiki-decomp-${triple}${ext}`))
console.log(`mekiki-decomp for ${triple} is ready`)
