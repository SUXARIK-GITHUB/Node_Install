#!/usr/bin/env python3
"""Optional browser acceptance. Playwright/Chromium are TEST tools, not node dependencies.
Renders the generated HTML and identical CSS in memory; actual file delivery/TLS is tested separately.
"""
import argparse
import json
import re
from pathlib import Path
import shutil
import tempfile
from urllib.parse import urlparse
from common import module


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--chromium',default=shutil.which('chromium'))
    args=parser.parse_args()
    from playwright.sync_api import sync_playwright
    args.output.mkdir(parents=True,exist_ok=True)
    m=module('VK_SITE_TOOL_PY')
    report={'transport':'in-memory HTML + exact CSS asset (browser navigation restricted in sandbox)', 'cases':[],'engine':'Chromium','external_requests':[],'page_errors':[],'http_errors':[]}
    with tempfile.TemporaryDirectory(prefix='vk-browser-cover-') as d:
        root=Path(d)
        data,assets=m.render('venom.vkarmani.com');(root/'index.html').write_bytes(data)
        for name,body in assets.items():(root/name).parent.mkdir(exist_ok=True);(root/name).write_bytes(body)
        (root/'favicon.ico').write_bytes(b'')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=args.chromium,headless=True,args=['--no-sandbox'])
            report['browser_version']=browser.version
            for width in [320,375,390,620,768,900,1024,1440,1920]:
                page=browser.new_page(viewport={'width':width,'height':960},device_scale_factor=1)
                page.on('request',lambda r:report['external_requests'].append(r.url) if urlparse(r.url).scheme not in ('file','data') else None)
                page.on('pageerror',lambda e:report['page_errors'].append(str(e)))
                page.on('response',lambda r:report['http_errors'].append([r.status,r.url]) if r.status>=400 else None)
                css=next(v.decode() for k,v in assets.items() if k.endswith('.css'))
                visual=re.sub(r'<link rel="stylesheet" href="[^"]+">', '<style>'+css+'</style>', data.decode())
                visual=re.sub(r'<link rel="icon"[^>]+>', '', visual)
                page.set_content(visual,wait_until='load')
                metrics=page.evaluate('''() => ({scroll:document.documentElement.scrollWidth, width:innerWidth,
                  sheets:document.styleSheets.length, scripts:document.scripts.length,
                  text:document.querySelector('h1').innerText, background:getComputedStyle(document.body).backgroundColor,
                  hero:document.querySelector('h1').getBoundingClientRect().toJSON(),
                  desc:document.querySelector('.description').getBoundingClientRect().toJSON()})''')
                assert metrics['scroll']<=width,(width,metrics)
                assert metrics['sheets']==1 and metrics['scripts']==0,metrics
                assert metrics['background']=='rgb(16, 18, 17)',metrics
                assert metrics['hero']['bottom']<=metrics['desc']['top'],metrics
                page.emulate_media(reduced_motion='reduce')
                assert page.evaluate('getComputedStyle(document.documentElement).scrollBehavior')=='auto'
                assert page.locator('.quiet-link').get_attribute('href')=='#about'
                assert page.locator('#about').count()==1
                if width in (390,1440):
                    page.evaluate('window.scrollTo(0,0)')
                    page.screenshot(path=str(args.output/f'cover-{width}.png'),full_page=True)
                report['cases'].append({'width':width,'result':'PASS','horizontal_overflow':False})
                page.close()
            browser.close()
        assert not report['external_requests'] and not report['page_errors'] and not report['http_errors'],report
        report['site_bytes']=len(data)+sum(map(len,assets.values()))
        report['result']='PASS'
        (args.output/'browser-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
