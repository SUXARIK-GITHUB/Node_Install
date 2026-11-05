#!/usr/bin/env python3
"""Generate an offline HTML index linking to source site previews.

No scripts or network; generation is opt-in and idempotent through --check.
Never deploy this gallery to the public node webroot.
"""
import argparse
import html
from pathlib import Path
import sys

try:
    from cover_variants import NAMES as CLASSIC, THEMES as OLD
    from site_catalog import NAMES as NEW, THEMES as NEW_THEMES
except ImportError:
    from scripts.cover_variants import NAMES as CLASSIC, THEMES as OLD
    from scripts.site_catalog import NAMES as NEW, THEMES as NEW_THEMES

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'preview/site-gallery/index.html'


def e(value):
    return html.escape(value,quote=True)


def generate():
    cards=[]
    count=len(CLASSIC)+len(NEW)
    for n in CLASSIC+NEW:
        klassic=n in OLD
        spec=OLD[n] if klassic else NEW_THEMES[n]
        title=spec['names'][0] if klassic else spec.title
        category=spec['label'] if klassic else spec.category
        visual='Original editorial · R12' if klassic else spec.layout
        base='cover-variants' if klassic else 'site-catalog'
        url=f'../../{base}/{n}/index.html'
        icon=f'../../{base}/{n}/favicon.svg'
        cards.append(f'<article class="tile"><a href="{e(url)}" target="_blank" rel="noopener" aria-label="Открыть {e(title)}">'
                     f'<div class="logo"><img alt="" src="{e(icon)}" loading="lazy" width="74" height="74"></div>'
                     f'<p class="category">{e(category)}</p><h2>{e(title)}</h2>'
                     f'<p class="details">{e(n)} · {e(visual)}</p><span class="visit">Открыть сайт ↗</span></a></article>')
    return ('''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'">
<title>Node_Install — галерея {count} сайтов</title>
<style>
:root{color-scheme:dark;--bg:#0b1018;--panel:#141c2a;--muted:#a8b6cb;--line:#283347;--accent:#8de6c4}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;color:#eff4fc;background:var(--bg);font-family:system-ui,-apple-system,sans-serif}
a{color:inherit}.container{max-width:1480px;padding:0 28px;margin:auto}header{padding:64px 0 46px;border-bottom:1px solid var(--line)}
.eyebrow{letter-spacing:.16em;text-transform:uppercase;color:var(--accent);font-size:.85rem;font-weight:700}
h1{letter-spacing:-.065em;font-size:clamp(2.5rem,7vw,6.2rem);line-height:1.06;margin:15px 0 20px;max-width:17ch}
.intro{max-width:78ch;color:var(--muted);line-height:1.8;font-size:1.05rem}.stats{display:flex;gap:18px;flex-wrap:wrap;margin-top:24px}.pill{border:1px solid var(--line);border-radius:30px;padding:9px 17px;font-size:.9rem}
.section-title{padding:32px 0 16px;display:flex;justify-content:space-between;gap:20px;color:var(--muted);font-size:.87rem}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:70px}.tile{border:1px solid var(--line);background:var(--panel);border-radius:20px;min-width:0;transition:transform .15s,border-color .15s}
.tile:hover{transform:translateY(-3px);border-color:var(--accent)}.tile a{display:block;height:100%;text-decoration:none;padding:26px}.logo{min-height:90px}.logo img{display:block;max-width:74px;max-height:74px}
.tile h2{font-size:clamp(1.05rem,1.3vw,1.35rem);letter-spacing:-.035em;line-height:1.3;margin:9px 0 13px;overflow-wrap:break-word}.category{color:var(--accent);font-size:.75rem;font-weight:750;letter-spacing:.07em;margin:16px 0 0;min-height:2em}
.details{font-size:.78rem;color:var(--muted);min-height:3em;overflow-wrap:anywhere}.visit{display:inline-block;margin-top:15px;font-size:.86rem;font-weight:700}
footer{border-top:1px solid var(--line);padding:30px 0;color:var(--muted);font-size:.84rem}
@media(max-width:1180px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:760px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.container{padding:0 15px}.tile a{padding:16px}}
@media(max-width:440px){.grid{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}.tile{transition:none}}
</style></head><body><div class="container"><header><p class="eyebrow">Node_Install / Site Gallery</p><h1>{count} отдельных тематик. Один каталог.</h1>
<p class="intro">Статические демонстрационные сайты из полного архива Node_Install. 96 вариантов построены на общем генераторе, 12 имеют отдельную авторскую композицию, ещё 12 — исходные исторические. Каждый открывается локально. Служебные настройки VPS, Nginx, REALITY и XHTTP при просмотре не меняются. Для реального развёртывания нужен staging и отдельная команда.</p>
<div class="stats"><span class="pill">{count} тематик</span><span class="pill">{len(NEW)} новых</span><span class="pill">12 исторических</span><span class="pill">16 базовых и 12 авторских композиций</span><span class="pill">Без JS и CDN</span></div></header>
<p class="intro">Дополнительно: <a href="visual-review-desktop.jpg" target="_blank" rel="noopener">контактный лист десктопных снимков</a> · <a href="visual-review-mobile.jpg" target="_blank" rel="noopener">контактный лист мобильных снимков</a> · <a href="visual-review-r23.json" target="_blank" rel="noopener">результаты offline-проверки Chromium</a>.</p>
<div class="section-title"><span>Каталог исходных сайтов — выбери любую карточку</span><span>Только локальный просмотр</span></div>
<main class="grid">'''+''.join(cards)+'''</main><footer><p>Откройте этот index.html в браузере из полностью распакованного архива. Если страницы не открываются, проверьте, что папки site-catalog/ и cover-variants/ лежат рядом с preview/.</p></footer>
</div></body></html>\n''').replace('{count}',str(count)).replace('{len(NEW)}',str(len(NEW))).encode('utf-8')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check',action='store_true')
    args=p.parse_args(argv)
    for n in CLASSIC+NEW:
        base='cover-variants' if n in CLASSIC else 'site-catalog'
        for fn in ('index.html','favicon.svg'):
            if not (ROOT/base/n/fn).is_file():
                print('GALLERY=STOP SOURCE_MISSING '+n+'/'+fn,file=sys.stderr)
                return 1
    content=generate()
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes()!=content:
            print('GALLERY=STOP OUTDATED_OR_MISSING',file=sys.stderr)
            return 1
        print(f'GALLERY=PASS links={len(CLASSIC)+len(NEW)}');return 0
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    OUTPUT.write_bytes(content)
    print(f'GALLERY=GENERATED links={len(CLASSIC)+len(NEW)}',OUTPUT)
    return 0


if __name__=='__main__':raise SystemExit(main())
