// Builds the dashboard into ONE self-contained gzipped HTML file that the firmware
// serves from LittleFS (/index.html.gz). No CDN, no external requests: the device
// has no internet access guarantee and every asset must come off flash.
//
//   node build.mjs            -> ../data/index.html.gz  (+ dist/index.html for inspection)
//   node build.mjs --watch     -> same, rebuilt whenever web/src changes
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, watch as fsWatch } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, 'dist');
const outFile = resolve(here, '../data/index.html.gz');
const css = () => readFileSync(resolve(dist, 'style.css'), 'utf8');

async function buildOnce() {
  mkdirSync(dist, { recursive: true });

  // 1. Tailwind v4 (JIT, content 自动探测)
  execFileSync(resolve(here, 'node_modules/.bin/tailwindcss'), [
    '-i', resolve(here, 'src/style.css'),
    '-o', resolve(dist, 'style.css'),
    '--minify',
  ], { stdio: 'inherit' });

  // 2. Preact app (IIFE, minified)
  await build({
    entryPoints: [resolve(here, 'src/app.jsx')],
    outfile: resolve(dist, 'app.js'),
    bundle: true,
    minify: true,
    format: 'iife',
    target: ['es2020'],
    jsx: 'automatic',
    jsxImportSource: 'preact',
    legalComments: 'none',
    define: { 'process.env.NODE_ENV': '"production"' },
  });

  const styles = css();
  const js = readFileSync(resolve(dist, 'app.js'), 'utf8');

  // 3. Inline everything into one document
  const html = `<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#ffffff">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#000000">
<link rel="icon" href="data:,">
<title>S3 AdBlock</title>
<style>${styles}</style>
</head><body><div id="app"></div>
<script>${js}</script>
</body></html>`;

  writeFileSync(resolve(dist, 'index.html'), html);
  const gz = gzipSync(Buffer.from(html, 'utf8'), { level: 9 });
  writeFileSync(outFile, gz);

  const kb = (n) => (n / 1024).toFixed(1) + ' KB';
  console.log(`html   ${kb(Buffer.byteLength(html))}  (css ${kb(styles.length)}, js ${kb(js.length)})`);
  console.log(`gzip   ${kb(gz.length)}  ->  ${outFile}`);
}

if (!process.argv.includes('--watch')) {
  await buildOnce();
} else {
  await buildOnce();
  console.log('\nwatching web/src for changes (ctrl-c to stop)…');
  let timer = 0;
  fsWatch(resolve(here, 'src'), { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      buildOnce().catch((e) => console.error('[watch] build failed:', e.message));
    }, 150);
  });
}
