#!/bin/sh
# Gera static/social-card.jpg (1200x630) a partir de design/social_card.html + ilustração do hero.
# Requer Docker. Uso: sh design/gerar_social_card.sh
set -e
cd "$(dirname "$0")/.."
OUT=$(mktemp -d); chmod 777 "$OUT"
docker run --rm -v "$PWD":/app:ro -v "$OUT":/out -w /app python:3.11-slim sh -c '
  pip install -q jinja2 >/dev/null 2>&1
  python -c "
from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup
env = Environment(loader=FileSystemLoader([\"templates\", \"design\"]))
fig = env.get_template(\"partials/hero_bg.svg\").render(hb=\"hbc\", modo=\"mobile\")
open(\"/out/card.html\", \"w\").write(env.get_template(\"social_card.html\").render(figura=Markup(fig)))
"; chmod 666 /out/card.html'
cat > "$OUT/shot.js" <<'JS'
const puppeteer = require('puppeteer');
(async () => {
  const b = await puppeteer.launch({args: ['--no-sandbox']}); const p = await b.newPage();
  await p.setViewport({width: 1200, height: 630, deviceScaleFactor: 1});
  await p.goto('file:///out/card.html', {waitUntil: 'networkidle0', timeout: 60000});
  await p.evaluateHandle('document.fonts.ready');
  await p.screenshot({path: '/out/card.png'}); await b.close();
})();
JS
docker run --rm -v "$OUT":/out -w /home/pptruser ghcr.io/puppeteer/puppeteer:24.10.0 sh -c "cp /out/shot.js ./s.js && node s.js"
docker run --rm --entrypoint magick -v "$OUT":/w -w /w dpokidov/imagemagick:latest card.png -strip -interlace Plane -quality 88 card.jpg
cp "$OUT/card.jpg" static/social-card.jpg
echo "static/social-card.jpg atualizado ($(du -h static/social-card.jpg | cut -f1))"
