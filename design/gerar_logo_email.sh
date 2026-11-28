#!/bin/sh
# Gera static/email/logo.png (3x, fundo transparente) a partir de design/logo_email.html, num contêiner.
set -e
cd "$(dirname "$0")/.."
TMP=$(mktemp -d); chmod 777 "$TMP"; cp design/logo_email.html "$TMP/"
cat > "$TMP/gerar.js" <<'JS'
const puppeteer = require('puppeteer');
(async () => {
  const b = await puppeteer.launch({args: ['--no-sandbox']}); const p = await b.newPage();
  await p.setViewport({width: 600, height: 200, deviceScaleFactor: 3});
  await p.goto('file:///out/logo_email.html', {waitUntil: 'networkidle0'}); await p.evaluateHandle('document.fonts.ready');
  const el = await p.$('#logo'); const box = await el.boundingBox();
  await el.screenshot({path: '/out/logo.png', omitBackground: true});
  console.log(Math.round(box.width) + 'x' + Math.round(box.height));
  await b.close();
})();
JS
docker run --rm -v "$TMP":/out -w /home/pptruser ghcr.io/puppeteer/puppeteer:24.10.0 sh -c 'cp /out/gerar.js . && node gerar.js'
cp "$TMP/logo.png" static/email/logo.png; rm -rf "$TMP"
