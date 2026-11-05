#!/usr/bin/env python3
"""Opt-in, multi-page editorial cover bundles for staging nodes.

Uses the existing twelve original VKarmani themes and domain-derived palette.
No remote content, JavaScript, accounts, forms, external resources or services.
Default install.sh cover behavior is intentionally unchanged.
"""
import argparse
import hashlib
import html
from pathlib import Path
import sys

try:
    from cover_variants import NAMES, THEMES, LAYOUTS, render, valid_domain
except ImportError:
    from scripts.cover_variants import NAMES, THEMES, LAYOUTS, render, valid_domain

PAGES = ('journal.html', 'about.html', 'questions.html')
# Original editorial copy; each theme has its own introduction, not repeated
# pseudo-business claims or copied content from third-party websites.
EDITORIAL = {
    '01-atelier': ('Мы рассматриваем форму через материал: сначала эскиз, затем проба поверхности и только после этого — завершённый предмет.',
                   'Особое внимание уделено работе рук, изменчивому свету и небольшим деталям, которые легко пропустить.'),
    '02-archive': ('Повседневная история часто сохраняется не в больших памятниках, а в письмах, открытках и уличных обозначениях.',
                  'В этом выпуске собраны способы замечать такие свидетельства и бережно описывать семейные собрания.'),
    '03-observatory': ('Наблюдения неба начинаются с привычки записывать дату, условия и положение заметных объектов.',
                      'Мы знакомимся с созвездиями и фазами Луны без сложного оборудования и без имитации измерений в реальном времени.'),
    '04-fieldnotes': ('Короткая прогулка требует внимания к погоде, маршруту и тому, как меняется ландшафт на протяжении дня.',
                      'Здесь важнее наблюдение и бережное отношение к природе, чем рекорды дистанции или скорости.'),
    '05-readingroom': ('Читательский дневник позволяет замечать не только сюжет, но и ритм языка, детали обстановки и собственные вопросы.',
                       'Небольшие заметки помогают возвращаться к книгам и сохранять впечатления без оценок и рейтингов.'),
    '06-foundry': ('Инженерное мышление проявляется в точности разметки, последовательности действий и возможности разобрать конструкцию.',
                   'Мы изучаем культуру прототипирования и фактуру материалов через понятные бытовые примеры.'),
    '07-botanica': ('Комнатные растения растут в разном темпе, а наблюдение за ними учит учитывать свет, воду и сезонные изменения.',
                    'Справочные материалы посвящены простым привычкам ухода без обещаний мгновенного результата.'),
    '08-nocturne': ('Звуковой пейзаж складывается из далёких и близких источников: шагов, дождя, транспорта и тишины.',
                    'Мы предлагаем упражнения на внимательное слушание и заметки о том, как воспринимается пространство.'),
    '09-kitchen': ('В домашней кухне многое зависит от последовательности: подготовка продуктов, температура и баланс вкусов.',
                   'Материалы собраны как повседневные наблюдения, а не как профессиональные рекомендации или каталог заказов.'),
    '10-atlas': ('Картография соединяет точность условных обозначений с любопытством к маршрутам и истории мест.',
                 'Небольшие очерки посвящены чтению карт, ориентирам и способам описания собственного путешествия.'),
    '11-tides': ('Вода, ветер и освещение непрерывно меняют характер берегового пейзажа, даже если точка наблюдения остаётся той же.',
                 'Заметки помогают увидеть сезонные ритмы и уважительно относиться к природным условиям.'),
    '12-cinema': ('Кинорассказ складывается из света, движения камеры, монтажа и пауз между репликами.',
                  'Мы изучаем визуальный язык через короткие авторские заметки, не пересказывая чужие фильмы.'),
}
EXTRA = PAGES + ('robots.txt', 'sitemap.xml')
STYLES = b'''
/* Optional R20 editorial pages: local styles, no remote fonts or imports. */
.rich-head{padding:76px var(--gutter) 56px;background:var(--card);border-bottom:1px solid var(--rule)}
.rich-head h1{max-width:15ch;font-size:clamp(2.7rem,5.7vw,5rem);margin:20px 0}
.rich-head p{max-width:63ch;line-height:1.8}
.rich-crumb{font-size:.77rem;font-weight:750;letter-spacing:.08em}
.rich-crumb a{text-decoration:underline;text-underline-offset:4px}
.rich-content{padding:64px var(--gutter) 95px;max-width:1040px}
.rich-content h2{font-size:clamp(1.7rem,3vw,2.8rem);margin:18px 0}
.rich-content>p,.rich-entry p{max-width:65ch;line-height:1.85}
.rich-entry{border-top:1px solid var(--rule);padding:35px 0}
.rich-entry .kicker{display:block;margin-bottom:15px}
.rich-entry h2{max-width:28ch}
.rich-detail{padding:20px 0;border-bottom:1px solid var(--rule)}
.rich-detail summary{cursor:pointer;font-weight:750}
.rich-detail p{margin:16px 0;max-width:65ch}
.rich-nav{display:flex;gap:18px;flex-wrap:wrap;margin-top:45px;padding-top:22px;border-top:1px solid var(--rule)}
.rich-nav a{text-decoration:underline;text-underline-offset:5px;font-weight:650}
@media(max-width:760px){.rich-head{padding:46px 22px}.rich-content{padding:45px 22px 64px}}
'''


def _page(theme, domain, body, heading, subtitle):
    spec = THEMES[theme]
    seed = hashlib.sha256((theme + '\n' + domain).encode('ascii')).digest()
    name = spec['names'][int.from_bytes(seed[1:3], 'big') % 4]
    nav = ''.join(f'<a href="/{p}">{html.escape(caption)}</a>' for p, caption in (
        ('journal.html', 'Материалы'), ('about.html', 'Об издании'),
        ('questions.html', 'Вопросы')))
    def e(s):
        return html.escape(s, quote=True)
    return (f'<!doctype html>\n<html lang="ru"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="description" content="{e(subtitle)}">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'">'
            f'<title>{e(heading)} — {e(name)}</title>'
            f'<link rel="stylesheet" href="/style.css">'
            f'<link rel="icon" href="/favicon.svg" type="image/svg+xml"></head>'
            f'<body class="theme theme-{LAYOUTS[NAMES.index(theme)]}"><div class="page">'
            f'<header class="top"><a class="brand" href="/"><span class="brand-icon" aria-hidden="true">{e(spec["emoji"])}</span>{e(name)}</a>'
            f'<nav aria-label="Разделы сайта"><a href="/">Главная</a>{nav}</nav></header>'
            f'<main><section class="rich-head"><div class="rich-crumb"><a href="/">Главная</a> / {e(heading)}</div>'
            f'<h1>{e(heading)}</h1><p>{e(subtitle)}</p></section>'
            f'<section class="rich-content">{body}'
            f'<nav class="rich-nav" aria-label="Другие разделы"><a href="/">На главную</a>{nav}</nav>'
            f'</section></main><footer class="foot"><span>{e(name)} · редакционные материалы · 2026</span>'
            f'<a href="/">Главная ↑</a></footer></div></body></html>\n').encode('utf-8')


def render_rich(theme, domain):
    # R21 curated sites are independent templates, not variants of the R20 twelve.
    try:
        from site_catalog import THEMES as CATALOG, render as render_catalog
    except ImportError:
        from scripts.site_catalog import THEMES as CATALOG, render as render_catalog
    if theme in CATALOG:
        return render_catalog(theme, domain, rich=True)
    if theme not in NAMES:
        raise ValueError('unknown theme')
    valid_domain(domain)
    base = render(theme, domain)
    spec = THEMES[theme]
    def e(value):
        return html.escape(value, quote=True)
    intro = ''.join('<p>' + e(note) + '</p>' for note in EDITORIAL[theme])
    articles = intro + ''.join(
        f'<article class="rich-entry"><span class="kicker">Материал {i + 1:02d}</span>'
        f'<h2>{e(title)}</h2><p>{e(description)}</p></article>'
        for i, (title, description) in enumerate(spec['items'])
    )
    about = (f'<h2>{e(spec["label"])}</h2><p>{e(spec["intro"])}</p>'
             f'<p>{e(EDITORIAL[theme][0])}</p>'
             f'<p>Небольшое независимое редакционное пространство. Здесь публикуются'
             f' тематические наблюдения и оригинальные векторные иллюстрации.'
             f' Мы не предлагаем платные услуги, не ведём личные кабинеты и не запрашиваем персональные данные.</p>')
    faqs = ''.join(f'<details class="rich-detail"><summary>{e(q)}</summary><p>{e(a)}</p></details>'
                   for q, a in spec['faq'])
    rich = dict(base)
    rich['index.html'] = base['index.html'].replace(
        b'</nav><span class="issue">',
        ('<a href="/journal.html">Материалы</a><a href="/about.html">Об издании</a>'
         '<a href="/questions.html">Вопросы</a></nav><span class="issue">').encode(), 1).replace(
        '<a href="#notes" aria-label="К материалам">'.encode(),
        '<a href="/journal.html" aria-label="К материалам">'.encode())
    rich['style.css'] = base['style.css'] + STYLES
    rich['journal.html'] = _page(theme, domain, articles,
                                  'Материалы и заметки', spec['intro'])
    rich['about.html'] = _page(theme, domain, about,
                                'Об издании', spec['intro'])
    rich['questions.html'] = _page(theme, domain, faqs,
                                    'Вопросы и ответы', spec['intro'])
    rich['robots.txt'] = (f'User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n').encode('ascii')
    rich['sitemap.xml'] = ('<?xml version="1.0" encoding="utf-8"?>\n'
                           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
                           ''.join(f'<url><loc>https://{domain}/{path}</loc></url>\n'
                                   for path in ('',) + PAGES) + '</urlset>\n').encode('utf-8')
    if (not rich['index.html'].count(b'href="/journal.html"') >= 1 or
            any(len(content) > 128 * 1024 for content in rich.values())):
        raise ValueError('invalid generated rich bundle')
    return rich


def main(argv=None):
    try:
        from site_catalog import NAMES as CATALOG_NAMES
    except ImportError:
        from scripts.site_catalog import NAMES as CATALOG_NAMES
    all_names = NAMES + CATALOG_NAMES
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--name', choices=all_names)
    parser.add_argument('--domain', default='preview.example.test')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if args.list and not args.name and args.output is None:
        print('\n'.join(all_names)); return 0
    if args.list or not args.name or args.output is None:
        parser.error('use --list OR --name NAME --domain DOMAIN --output NEW_DIR')
    out = args.output
    if out.exists() or out.is_symlink() or not out.parent.is_dir():
        print('RICH_COVER=STOP OUTPUT_ALREADY_PRESENT_OR_PARENT_MISSING', file=sys.stderr)
        return 1
    try:
        data = render_rich(args.name, args.domain)
        out.mkdir(mode=0o755)
        for name, content in data.items():
            p = out / name
            with p.open('xb') as dest:
                dest.write(content)
            p.chmod(0o644)
    except (OSError, ValueError) as exc:
        if out.exists():
            for name in data if 'data' in locals() else ():
                (out / name).unlink(missing_ok=True)
            out.rmdir()
        print('RICH_COVER=STOP SOURCE_OR_OUTPUT_INVALID', type(exc).__name__, file=sys.stderr)
        return 1
    print('RICH_COVER=PREPARED_OFFLINE THEME=' + args.name + ' OUTPUT=' + str(out))
    print('LIVE_NGINX=UNTOUCHED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
