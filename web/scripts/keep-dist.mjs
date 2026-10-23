// Recreates dist/.gitkeep after `vite build` (emptyOutDir removes it). The file is committed so
// that `//go:embed all:dist` (web/embed.go) compiles on a checkout without a web build.
import { writeFile } from 'node:fs/promises';

await writeFile(new URL('../dist/.gitkeep', import.meta.url), '');
