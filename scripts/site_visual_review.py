#!/usr/bin/env python3
"""Offline Chromium visual-layout QA of every generated cover, at desktop/mobile sizes.

The temporary in-browser document has its local CSS inlined and CSP meta removed
ONLY for screenshot rendering from about:blank; source files, deployed CSP and
network services are never modified. The independent site_audit.py validates
CSP, local links and asset restrictions. Requires optional Playwright+Chromium.
Never connects to a public URL or executes shell code from a site.
"""
import argparse
import json
from pathlib import Path
import re
import sys

try:
    from cover_rich import render_rich
    from cover_variants import NAMES as OLD
    from site_catalog import NAMES as NEW
    from site_audit import audit_bundle
except ImportError:
    from scripts.cover_rich import render_rich
    from scripts.cover_variants import NAMES as OLD
    from scripts.site_catalog import NAMES as NEW
    from scripts.site_audit import audit_bundle

ALL = tuple(OLD) + tuple(NEW)
SIZES = {'desktop': (1280, 800), 'mobile': (390, 844)}


def offline_html(bundle, page='index.html'):
    """Prepare an isolated about:blank page without blocked file:// requests."""
    html = bundle[page].decode('utf-8')
    css = bundle['style.css'].decode('utf-8')
    html, metas = re.subn(r'<meta\b[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*>',
                          '', html, flags=re.I)
    # Deployed CSP is independently inspected by site_audit; remove only in-memory
    # to allow Playwright to render trusted CSS inside an about:blank page.
    html, links = re.subn(r'<link\b(?=[^>]*rel=["\']stylesheet["\'])[^>]*>',
                          lambda _m: '<style>' + css + '</style>', html, flags=re.I)
    if links != 1 or not metas:
        raise ValueError('VISUAL_SOURCE_CSS_OR_CSP_CONTRACT_MISSING')
    # Keep navigational links intact; never follow them during screenshot.
    return html


def capture(output, domain, names, browser_executable, screenshots=True):
    from playwright.sync_api import sync_playwright
    from PIL import Image, ImageDraw, ImageFont
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('OUTPUT_DIRECTORY_MUST_NOT_EXIST')
    output.mkdir(mode=0o755)
    rows, shots, failures = [], {'desktop': [], 'mobile': []}, []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=browser_executable, headless=True,
                     args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
                           '--disable-background-networking', '--disable-extensions'])
        try:
            for name in names:
                bundle = render_rich(name, domain)
                audit_bundle(bundle, domain, rich=True)
                html = offline_html(bundle)
                for mode, (w, h) in SIZES.items():
                    page = browser.new_page(viewport={'width': w, 'height': h}, device_scale_factor=1,
                                             java_script_enabled=False)
                    try:
                        page.set_content(html, wait_until='domcontentloaded', timeout=12000)
                        metrics = page.evaluate('''() => {
                            const root=document.documentElement;
                            const head=document.querySelector('h1');
                            const nav=document.querySelector('nav');
                            const title=document.querySelector('title');
                            const body=document.body;
                            return {
                              viewport:root.clientWidth, document_width:root.scrollWidth,
                              heading_visible:!!head && head.getBoundingClientRect().width>0 &&
                                 head.getBoundingClientRect().height>0 && getComputedStyle(head).fontSize !== '0px',
                              title_present:!!title && title.textContent.trim().length>4,
                              nav_present:!!nav && nav.getBoundingClientRect().width>0,
                              css_color:getComputedStyle(body).color,
                              main_present:!!document.querySelector('main'),
                              text_length:body.innerText.trim().length,
                            }
                        }''')
                        errors=[]
                        if metrics['document_width'] > w + 2:
                            errors.append('HORIZONTAL_OVERFLOW')
                        for field in ('heading_visible','title_present','nav_present','main_present'):
                            if not metrics[field]: errors.append('MISSING_'+field.upper())
                        if metrics['text_length'] < 180:
                            errors.append('INSUFFICIENT_VISIBLE_CONTENT')
                        record={'theme':name,'viewport':mode,'width':w,'height':h,
                                'document_width':metrics['document_width'],
                                'text_length':metrics['text_length'], 'issues':errors}
                        rows.append(record)
                        if errors: failures.append(record)
                        if screenshots:
                            png=page.screenshot(type='jpeg',quality=60,animations='disabled',
                                                full_page=False, timeout=12000)
                            from io import BytesIO
                            shots[mode].append((name, Image.open(BytesIO(png)).convert('RGB').copy()))
                    finally:
                        page.close()
        finally:
            browser.close()
    if screenshots:
        for mode, items in shots.items():
            # A reproducible contact sheet makes visual review of all 120 sites
            # possible without opening hundreds of files manually.
            thumb_w, thumb_h, label_h, cols = 256, 160, 26, 8
            rows_n=(len(items)+cols-1)//cols
            montage=Image.new('RGB',(cols*thumb_w,rows_n*(thumb_h+label_h)), '#edf0f4')
            draw=ImageDraw.Draw(montage)
            for i,(name,photo) in enumerate(items):
                x=(i%cols)*thumb_w; y=(i//cols)*(thumb_h+label_h)
                photo.thumbnail((thumb_w-6,thumb_h-5),Image.Resampling.LANCZOS)
                montage.paste(photo,(x+3,y+2))
                draw.text((x+5,y+thumb_h+3),name,fill='#13202a')
            montage.save(output/('contact-'+mode+'.jpg'),quality=82,optimize=True)
    result={'schema':1,'sites':len(names),'viewports':len(SIZES),'checks':len(rows),
            'failed':len(failures),'failures':failures,'checks_detail':rows,
            'limitations':['Offline about:blank rendering, not HTTPS or browser live-server probe',
                           'Visual screenshot review is necessary; metrics alone are not a design-quality proof',
                           'No JavaScript enabled, no remote assets, no real client connectivity']}
    (output/'visual-review.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    return result


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',required=True,type=Path,help='new empty output directory')
    ap.add_argument('--domain',default='preview.example.test')
    ap.add_argument('--browser',default='/usr/bin/chromium')
    ap.add_argument('--theme', choices=ALL)
    ap.add_argument('--no-screenshots',action='store_true')
    ap.add_argument('--start',type=int,default=0,help='zero-based first site to review')
    ap.add_argument('--count',type=int,default=None,help='limit the reviewed site batch')
    args=ap.parse_args(argv)
    try:
        if args.start < 0 or (args.count is not None and args.count < 1):
            raise ValueError('INVALID_BATCH_RANGE')
        names=(args.theme,) if args.theme else ALL[args.start:args.start+args.count if args.count is not None else None]
        if not names:raise ValueError('EMPTY_SITE_BATCH')
        result=capture(args.output,args.domain,names,args.browser, not args.no_screenshots)
    except (ImportError,OSError,ValueError,TypeError) as exc:
        print('VISUAL_REVIEW=FAIL '+type(exc).__name__,file=sys.stderr)
        return 1
    print(json.dumps({k:v for k,v in result.items() if k not in ('checks_detail','failures','limitations')},sort_keys=True))
    return 0 if result['failed']==0 else 2


if __name__=='__main__':sys.exit(main())
