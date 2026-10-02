#!/usr/bin/env python3
"""Optional Chromium visual QA, not a dependency installed on nodes.
Uses in-memory HTML and exact CSS; real MIME/HTTPS/CSP behavior is tested by Nginx integration tests.
"""
import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse
from common import module

NAMES=('orbit','fold','grid','horizon')
WIDTHS=(320,375,390,620,768,900,1024,1440,1920)


def seeds(domain):
    result={}
    for n in range(1024):
        seed=f'{n:064x}'
        variant=hashlib.sha256((domain+':'+seed).encode()).digest()[2]%4
        result.setdefault(variant,seed)
        if len(result)==4:return result
    raise AssertionError('could not select four deterministic preview seeds')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--chromium',default=shutil.which('chromium'))
    args=parser.parse_args()
    from playwright.sync_api import sync_playwright
    args.output.mkdir(parents=True,exist_ok=True)
    m=module('VK_SITE_TOOL_PY');domain='node.example.com'
    report={'transport':'in-memory HTML + exact CSS, not the VPN path',
            'cases':[],'external_requests':[],'page_errors':[], 'http_errors':[], 'site_bytes':{}}
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=args.chromium,headless=True,args=['--no-sandbox'])
        report['browser_version']=browser.version
        try:
            for variant,seed in sorted(seeds(domain).items()):
                data,assets=m.render(domain,seed)
                css=next(v.decode() for k,v in assets.items() if k.endswith('.css'))
                visual=re.sub(r'<link rel="stylesheet" href="[^"]+">','<style>'+css+'</style>',data.decode())
                visual=re.sub(r'<link rel="icon"[^>]+>','',visual)
                report['site_bytes'][NAMES[variant]]=len(data)+sum(map(len,assets.values()))
                for width in WIDTHS:
                    page=browser.new_page(viewport={'width':width,'height':960},device_scale_factor=1)
                    page.on('request',lambda r:report['external_requests'].append(r.url) if urlparse(r.url).scheme not in ('file','data') else None)
                    page.on('pageerror',lambda e:report['page_errors'].append(str(e)))
                    page.on('response',lambda r:report['http_errors'].append([r.status,r.url]) if r.status>=400 else None)
                    try:
                        page.set_content(visual,wait_until='load')
                        metrics=page.evaluate('''() => ({scroll:document.documentElement.scrollWidth,width:innerWidth,
                          sheets:document.styleSheets.length,scripts:document.scripts.length,
                          hero:document.querySelector('h1').getBoundingClientRect().toJSON(),
                          desc:document.querySelector('.description').getBoundingClientRect().toJSON(),
                          header:document.querySelector('.header').getBoundingClientRect().toJSON(),
                          copy:document.querySelector('.copy').getBoundingClientRect().toJSON(),
                          art:document.querySelector('.sculpture').getBoundingClientRect().toJSON(),
                          footer:document.querySelector('.footer').getBoundingClientRect().toJSON()})''')
                        assert metrics['scroll']<=width,(variant,width,metrics)
                        assert metrics['sheets']==1 and metrics['scripts']==0,(variant,width,metrics)
                        assert metrics['hero']['bottom']<=metrics['desc']['top']+1,(variant,width,metrics)
                        assert metrics['header']['bottom']<=metrics['hero']['top']+1,(variant,width,metrics)
                        assert metrics['art']['right']<=width+1 and metrics['art']['left']>=-1,(variant,width,metrics)
                        page.emulate_media(reduced_motion='reduce')
                        assert page.evaluate('getComputedStyle(document.documentElement).scrollBehavior')=='auto'
                        assert page.locator('.quiet-link').get_attribute('href')=='#about'
                        assert page.locator('#about').count()==1
                        page.locator('.quiet-link').focus()
                        assert page.evaluate('document.activeElement.className')=='quiet-link'
                        if width in (390,1440):
                            page.evaluate('document.activeElement.blur(); window.scrollTo(0,0)')
                            page.screenshot(path=str(args.output/f'{NAMES[variant]}-{width}.png'),full_page=True)
                        report['cases'].append({'variant':NAMES[variant],'width':width,'result':'PASS'})
                    finally:page.close()
        finally:browser.close()
    assert not report['external_requests'] and not report['page_errors'] and not report['http_errors'],report
    report['result']='PASS'
    (args.output/'browser-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
