#!/usr/bin/env python3
"""Curated visual direction for the 96 catalog publications.

Static, deterministic SVG and CSS only.  The art concepts are assigned by
subject, not selected by the request domain or by runtime randomness.  No
external assets, scripts, network calls, author claims or user data.
"""
from dataclasses import dataclass
from html import escape
import hashlib
import re


@dataclass(frozen=True)
class Direction:
    subject_art: str
    editorial: str
    canvas: str


# Each site has its own subject pictogram, page treatment and illustration
# canvas. These three decisions are intentionally editorial, not DNS-derived.
# No site takes its visual direction from the public hostname.
_SOURCE = '''
13-cloud-ledger|server|diagram|blueprint
14-edge-metrics|chart|ledger|blueprint
15-code-library|code|folio|notebook
16-data-vault|archive|exhibit|archive
17-aperture-docs|book|manual|notebook
18-api-foundry|nodes|diagram|blueprint
19-observation-lab|lens|laboratory|diagram
20-type-system|type|typographic|poster
21-satellite-atlas|orbit|atlas|starfield
22-circuit-notes|circuit|workshop|blueprint
23-linen-studio|textile|folio|fabric
24-print-house|press|typographic|print
25-clay-table|pottery|workshop|craft
26-gallery-light|lamp|exhibit|gallery
27-architecture-folio|building|atlas|blueprint
28-typography-press|type|typographic|print
29-oak-furniture|chair|workshop|craft
30-fragrance-index|bottle|exhibit|fabric
31-textile-library|textile|folio|fabric
32-visual-studio|shapes|exhibit|poster
33-coffee-roastery|coffee|kitchen|craft
34-slow-bakery|bread|kitchen|craft
35-citrus-studio|citrus|kitchen|poster
36-tea-library|tea|folio|fabric
37-olive-table|olive|kitchen|craft
38-cocoa-atelier|cocoa|exhibit|craft
39-fermentation-notes|microbe|laboratory|diagram
40-vineyard-journal|grape|folio|landscape
41-rooftop-garden|plant|field|botanical
42-spice-atlas|spice|atlas|poster
43-island-guide|island|atlas|landscape
44-mountain-trails|peak|field|landscape
45-urban-walks|walk|atlas|map
46-railway-journal|train|ledger|map
47-coastal-science|wave|laboratory|landscape
48-stargazing-club|telescope|atlas|starfield
49-forest-class|tree|field|botanical
50-sailing-guide|sail|field|landscape
51-birdwatch|bird|field|botanical
52-lake-stories|lake|folio|landscape
53-vinyl-label|record|exhibit|gallery
54-short-film|film|exhibit|gallery
55-poetry-room|poem|typographic|print
56-museum-index|frame|exhibit|gallery
57-photography-archive|camera|exhibit|gallery
58-book-society|books|folio|archive
59-audio-stories|audio|typographic|poster
60-stage-notes|stage|exhibit|gallery
61-history-pages|scroll|ledger|archive
62-vintage-objects|clock|workshop|archive
63-editorial-desk|press|typographic|print
64-civic-guide|building|manual|notebook
65-library-project|books|folio|archive
66-learning-studio|pencil|manual|notebook
67-project-maps|routes|diagram|map
68-shipments-notes|parcel|ledger|map
69-ecology-brief|leaf|field|botanical
70-weather-lab|cloud|laboratory|starfield
71-energy-notes|energy|diagram|blueprint
72-workshop-careers|tools|workshop|craft
73-quiet-storage|archive|ledger|archive
74-network-patterns|nodes|manual|blueprint
75-digital-safety|lock|manual|notebook
76-source-control|branch|diagram|blueprint
77-data-visualization|chart|typographic|diagram
78-open-standards|book|manual|notebook
79-glass-workshop|glass|exhibit|gallery
80-botanical-scent|plant|field|botanical
81-poster-gallery|type|typographic|poster
82-light-atelier|lamp|exhibit|gallery
83-bookbinding|binding|workshop|print
84-product-sketch|pencil|workshop|blueprint
85-bread-journal|bread|kitchen|craft
86-herbal-tea|tea|field|botanical
87-gelato-notes|scoop|kitchen|poster
88-small-bistro|plate|kitchen|craft
89-culinary-archive|recipe|folio|archive
90-beekeeping-notes|honey|field|botanical
91-bike-trails|bike|field|landscape
92-coastal-cities|building|atlas|map
93-nordic-cabins|cabin|field|landscape
94-mountain-weather|cloud|laboratory|landscape
95-maritime-maps|compass|atlas|map
96-garden-paths|routes|field|botanical
97-design-museum|shapes|exhibit|gallery
98-film-reels|film|ledger|gallery
99-analog-camera|camera|folio|archive
100-piano-notes|piano|typographic|poster
101-zine-press|press|typographic|print
102-folklore-notes|scroll|folio|archive
103-makers-school|tools|workshop|craft
104-typography-school|type|manual|notebook
105-city-planning|routes|atlas|map
106-material-science|glass|laboratory|diagram
107-astronomy-reference|orbit|atlas|starfield
108-volunteer-journal|hands|folio|poster
'''


def _directions():
    result = {}
    for line in _SOURCE.strip().splitlines():
        name, icon, editorial, canvas = line.split('|')
        if name in result:
            raise RuntimeError('duplicate direction: ' + name)
        result[name] = Direction(icon, editorial, canvas)
    if len(result) != 96:
        raise RuntimeError('incomplete curated directions')
    return result


DIRECTIONS = _directions()

# Original minimal pictograms in a consistent 200x200 coordinate system.
# They are deliberately simple editorial illustrations, not product icons.
# stroke and fill properties are assigned by the enclosing SVG group.
PICTOGRAMS = {
 'server': '<rect x="36" y="30" width="128" height="40" rx="9"/><rect x="36" y="80" width="128" height="40" rx="9"/><rect x="36" y="130" width="128" height="40" rx="9"/><path d="M53 50h12M53 100h12M53 150h12M93 50h53M93 100h53M93 150h53"/>',
 'chart': '<path d="M28 30v143h146"/><path d="M44 142l35-32 28 18 29-69 30 12"/><circle cx="79" cy="110" r="7"/><circle cx="136" cy="59" r="7"/>',
 'code': '<rect x="25" y="40" width="150" height="120" rx="12"/><path d="M74 81l-24 20 24 20M123 81l24 20-24 20M113 70l-28 65"/>',
 'archive': '<rect x="37" y="51" width="126" height="118" rx="8"/><path d="M35 83h130M78 51V30h44v21M73 117h55M80 140h40"/>',
 'book': '<path d="M100 52Q66 28 26 43v112q46-9 74 12 31-21 74-12V43q-44-13-74 9ZM100 52v115M43 70q22-3 40 5M115 75q20-8 40-5"/>',
 'nodes': '<circle cx="38" cy="100" r="17"/><circle cx="103" cy="37" r="17"/><circle cx="162" cy="108" r="17"/><circle cx="94" cy="163" r="17"/><path d="M52 88L90 49M118 51l30 42M147 121l-42 31M78 152l-28-37"/>',
 'lens': '<circle cx="88" cy="86" r="53"/><path d="M129 127l47 47M53 81h69M87 51v71"/>',
 'type': '<path d="M29 52V34h142v18M100 35v137M68 171h64"/><path d="M40 96h31v14H40zM129 111h29v13h-29z"/>',
 'orbit': '<circle cx="98" cy="100" r="29"/><ellipse cx="98" cy="100" rx="83" ry="37" transform="rotate(-28 98 100)"/><ellipse cx="98" cy="100" rx="63" ry="73" transform="rotate(28 98 100)"/><circle cx="32" cy="117" r="8"/>',
 'circuit': '<rect x="60" y="59" width="80" height="81" rx="9"/><path d="M77 35v23M102 35v23M124 35v23M77 141v22M102 141v22M124 141v22M36 78h24M36 102h24M36 124h24M141 78h23M141 102h23M141 124h23"/><circle cx="101" cy="100" r="22"/>',
 'textile': '<path d="M28 34v132M57 34v132M86 34v132M115 34v132M144 34v132M173 34v132M24 55q77-39 153 0M24 96q77 39 153 0M24 136q77-39 153 0"/>',
 'press': '<rect x="39" y="49" width="121" height="101"/><path d="M52 64h98M52 86h44M52 105h95M52 123h84M80 150v24M119 150v24M59 174h82"/>',
 'pottery': '<path d="M58 59h84l-8 30q-17 14-7 40l11 27q-34 28-76 0l11-27q11-26-7-40zM47 48h106M69 111h63"/>',
 'lamp': '<path d="M100 28v40M64 70h72l28 55H36zM48 126h104M100 126v39M72 168h56"/><path d="M18 144l-9 14M181 145l9 14"/>',
 'building': '<path d="M28 85l72-47 73 47H28zM34 164h132M54 93v68M88 93v68M121 93v68M153 93v68"/>',
 'chair': '<path d="M55 33v95h92V75q0-27-29-27M55 127l-9 48M147 127l11 48M53 108h94"/>',
 'bottle': '<path d="M81 27h38M87 27v44q-31 16-31 53v35q0 15 44 15t44-15v-35q0-37-31-53V27M60 118h80M82 143h36"/>',
 'shapes': '<rect x="20" y="30" width="74" height="74" rx="10"/><circle cx="142" cy="77" r="40"/><path d="M34 168l42-62 42 62zM137 122l44 45-45 0z"/>',
 'coffee': '<path d="M37 79h111v42q-4 42-55 42t-56-42zM148 93h17q24 0 14 27-7 15-28 15M60 54q-18-19 0-35M98 54q-18-19 0-35M136 54q-18-19 0-35"/>',
 'bread': '<path d="M31 107q-8-51 38-57 17-36 52-13 38-6 47 30 27 21-3 73l-23 27H55zM72 87l17 27M108 76l20 30"/>',
 'citrus': '<circle cx="96" cy="100" r="75"/><circle cx="96" cy="100" r="57"/><path d="M96 43v114M39 100h114M56 61l80 79M136 61l-80 79"/>',
 'tea': '<path d="M37 81h108v36q-5 40-54 40t-54-40zM145 90h22q20 15 0 31h-19M42 173h104M67 56q-14-17 0-31M107 56q-14-17 0-31"/>',
 'olive': '<path d="M45 161Q65 50 144 40M55 141q-41-3-39-44 34 5 39 44M93 94q-7-39 29-51 4 34-29 51"/><ellipse cx="124" cy="116" rx="24" ry="31"/>',
 'cocoa': '<path d="M100 25C42 37 30 83 43 122q19 56 57 51 45 4 59-51Q176 61 100 25zM100 42v122M63 69l30 31-24 34M137 69l-30 31 24 34"/>',
 'microbe': '<circle cx="100" cy="100" r="50"/><path d="M100 23v25M100 152v25M23 100h25M152 100h25M46 45l18 18M136 136l18 18M154 45l-18 18M64 136l-18 18"/><circle cx="83" cy="87" r="8"/><circle cx="120" cy="113" r="12"/>',
 'grape': '<path d="M99 47Q111 32 134 29M101 44q-26-23-56-12 10 37 51 30"/><circle cx="81" cy="75" r="21"/><circle cx="120" cy="75" r="21"/><circle cx="64" cy="109" r="21"/><circle cx="101" cy="109" r="21"/><circle cx="140" cy="109" r="21"/><circle cx="83" cy="142" r="21"/><circle cx="120" cy="142" r="21"/><circle cx="102" cy="171" r="14"/>',
 'plant': '<path d="M103 178V34M103 127Q46 112 37 72q59-2 66 55ZM103 91q60-15 65-60-56 5-65 60ZM103 157q-50-9-56-38 44-2 56 38Z"/>',
 'spice': '<path d="M69 42h61M77 42v30h46V42M61 73h78v92q-39 19-78 0zM74 109h54M83 133h36"/><circle cx="100" cy="104" r="6"/>',
 'island': '<path d="M22 135q50-58 76-18 39-50 79 18M25 155q32-12 65 0 33 14 64 0 21-8 40 0M99 112V44M99 44q34-8 52 18-41 19-52-18M99 56q-29-18-52 12 42 12 52-12"/>',
 'peak': '<path d="M12 167L78 60l36 53 22-35 55 89zM50 105l28-45 27 41M134 80l13 21"/>',
 'walk': '<circle cx="109" cy="39" r="17"/><path d="M105 58l-20 52 34 21 15 43M86 107l-36 35M93 83l39-8 24 23M96 130l-24 47"/>',
 'train': '<rect x="44" y="33" width="112" height="121" rx="26"/><path d="M61 53h77v57H61zM60 133h80M77 154l-21 28M123 154l21 28"/><circle cx="70" cy="135" r="4"/><circle cx="130" cy="135" r="4"/>',
 'wave': '<path d="M15 89q22-43 46 0t46 0 47 0 38 0M15 133q22-43 46 0t46 0 47 0 38 0M15 174q22-43 46 0t46 0 47 0 38 0"/>',
 'telescope': '<path d="M42 65l92-31 21 46-92 31zM78 103l29 35M107 138v40M107 138l-49 40M107 138l43 40"/>',
 'tree': '<path d="M100 174V95M100 107l-33-23M100 132l38-30M100 35q-57-13-64 35-33 31 8 52 15 37 57 9 43 26 58-9 42-23 10-56-6-47-69-31Z"/>',
 'sail': '<path d="M96 22v138M85 37L35 133h50zM105 52l50 84h-50zM20 166q38 23 79 0 40 23 81 0"/>',
 'bird': '<path d="M15 119q46-57 86-7 28-65 85-48-22 48-71 67-33 15-57 41l5-39z"/><circle cx="151" cy="82" r="4"/>',
 'lake': '<path d="M25 88l45-43 28 31 27-23 50 35M23 118q26-15 52 0t52 0 51 0M23 149q26-15 52 0t52 0 51 0M23 180q26-15 52 0t52 0 51 0"/>',
 'record': '<circle cx="100" cy="100" r="78"/><circle cx="100" cy="100" r="52"/><circle cx="100" cy="100" r="20"/><path d="M47 46q-40 52 0 103"/>',
 'film': '<rect x="26" y="47" width="148" height="112" rx="7"/><path d="M53 47v112M147 47v112M26 77h27M26 130h27M147 77h27M147 130h27M85 78l39 26-39 24z"/>',
 'poem': '<path d="M45 38h110v132H45zM66 69h68M66 93h55M66 117h68M66 141h39"/>',
 'frame': '<rect x="28" y="30" width="144" height="140"/><rect x="44" y="46" width="112" height="108"/><path d="M57 137l34-47 24 26 23-35 9 56z"/>',
 'camera': '<path d="M24 66h41l13-20h50l11 20h37v96H24zM74 114a26 26 0 1 0 52 0 26 26 0 1 0-52 0M142 85h14"/>',
 'books': '<path d="M36 46h35v118H36zM78 31h36v133H78zM123 54l36-9 20 115-36 9zM44 72h20M86 55h20M142 80l18-4"/>',
 'audio': '<path d="M27 93h27l31-29v91l-31-29H27zM107 79q31 21 0 62M123 57q56 44 0 108"/>',
 'stage': '<path d="M29 34h143v132H29zM29 37q27 41 42 61-37 10-42 63M171 37q-27 41-42 61 37 10 42 63M70 148h60"/>',
 'scroll': '<path d="M54 51q-24-12-24 16t24 17h95v83q-14 17-27 0H54V66q0-24 23-24h72v43M54 163q13 29 34 0M75 98h54M75 125h40"/>',
 'clock': '<circle cx="100" cy="102" r="72"/><circle cx="100" cy="102" r="52"/><path d="M100 61v41l34 24"/>',
 'pencil': '<path d="M39 141l89-94 28 28-94 89-33 9zM113 62l28 28M46 143l17 18"/>',
 'routes': '<circle cx="42" cy="46" r="15"/><circle cx="165" cy="74" r="15"/><circle cx="93" cy="164" r="15"/><path d="M54 55q60-34 98 11M156 91q-9 53-51 65M79 164q-43-7-37-101"/>',
 'parcel': '<path d="M32 71l68-38 68 38v90l-68 36-68-36zM32 71l68 38 68-38M100 109v87M68 50l68 38"/>',
 'leaf': '<path d="M37 160q11-130 128-124Q181 160 37 160M44 154q70-57 112-107M78 128l-15-50M107 102l-1-42"/>',
 'cloud': '<path d="M51 150q-36-5-34-39 2-31 34-35Q62 31 108 41q31 7 37 34 39 0 40 36t-32 39zM65 168h80"/>',
 'energy': '<path d="M109 15L43 109h53l-17 76 79-109h-54z"/>',
 'tools': '<path d="M57 35q-27 14-20 46 7 29 38 32l69 66 31-30-67-69q9-31-17-48l-1 34-19 17-28-14z"/>',
 'lock': '<rect x="43" y="88" width="115" height="86" rx="9"/><path d="M65 87V65a36 36 0 0 1 71 0v22M101 116v28"/>',
 'branch': '<circle cx="49" cy="31" r="12"/><circle cx="152" cy="83" r="12"/><circle cx="49" cy="170" r="12"/><path d="M49 45v110M49 104q15-28 47-27h43"/>',
 'glass': '<path d="M67 32h66l-10 94q-23 21-46 0zM77 126l-27 42h102l-29-42M81 55h38M76 91h48"/>',
 'binding': '<rect x="40" y="39" width="120" height="132" rx="5"/><path d="M61 39v132M73 64h66M73 92h51M73 124h66M73 150h48"/><path d="M54 55h14M54 91h14M54 126h14"/>',
 'scoop': '<circle cx="101" cy="69" r="49"/><path d="M73 111l23 69h13l20-69M88 140h26"/>',
 'plate': '<circle cx="100" cy="100" r="72"/><circle cx="100" cy="100" r="52"/><path d="M25 46v110M14 46v48h22V46M175 46v110M175 46q-24 21-9 48h9"/>',
 'recipe': '<path d="M48 33h104v145H48zM70 67h60M70 98h43M70 129h60M86 148l12 9 26-25"/>',
 'honey': '<path d="M62 45h76M72 45v23h56V45M59 70h82v101H59zM66 115l34-27 34 27-34 28z"/>',
 'bike': '<circle cx="43" cy="147" r="34"/><circle cx="157" cy="147" r="34"/><path d="M43 147l45-75 24 75H43l43-72M112 147l45-75M82 63h32M154 68h22"/>',
 'cabin': '<path d="M30 94l70-61 70 61v83H30zM18 94l82-70 82 70M74 177v-51h51v51M47 110h14M144 110h14"/>',
 'compass': '<circle cx="100" cy="100" r="75"/><path d="M99 36l32 69-31 61-30-69zM100 36v130M36 100h128"/>',
 'piano': '<rect x="25" y="31" width="150" height="140" rx="8"/><path d="M55 31v140M85 31v140M115 31v140M145 31v140M43 31v81h24V31M98 31v81h24V31M146 31v81h21V31"/>',
 'hands': '<path d="M26 119L58 79q10-11 21 0l17 21 17-21q11-11 22 0l38 40-34 50H62zM60 128l35 24M136 128l-34 24"/>',
}


# Per-canvas composition differs visually even when two subjects use the same
# graphical vocabulary. SVG never references external resources.
def illustration(theme):
    direction = DIRECTIONS[theme.name]
    seed = hashlib.sha256(theme.name.encode('ascii')).digest()
    ink = 'currentColor'
    canvas = direction.canvas
    inset = 18 + seed[0] % 24
    coordinates = {
        'blueprint': f'<path d="M30 95H710M30 190H710M30 285H710M30 380H710M{inset*3} 22V420M{inset*5} 22V420M{inset*7} 22V420" fill="none" stroke="currentColor" opacity=".08" stroke-width="2"/><rect x="111" y="75" width="518" height="320" fill="var(--art-light)" rx="6" opacity=".48"/>',
        'notebook': '<rect x="115" y="32" width="492" height="387" rx="8" fill="var(--art-light)" opacity=".43"/><path d="M145 37V415M156 110H570M156 160H570M156 210H570M156 260H570M156 310H570M156 360H570" stroke="currentColor" opacity=".13" stroke-width="2"/>',
        'archive': '<rect x="142" y="48" width="464" height="338" transform="rotate(7 374 217)" fill="var(--art-light)" opacity=".72"/><rect x="120" y="42" width="464" height="338" transform="rotate(-5 352 211)" fill="var(--card)" stroke="currentColor" stroke-width="2" opacity=".7"/>',
        'diagram': '<circle cx="365" cy="227" r="179" fill="var(--art-light)" opacity=".55"/><path d="M85 210h120M529 210h127M364 50v48M364 357v69" stroke="currentColor" opacity=".25" stroke-dasharray="6 8" stroke-width="3"/>',
        'poster': '<path d="M32 30h672v371H32z" fill="var(--art-light)" opacity=".63"/><path d="M56 64l160 0M522 355h130" stroke="currentColor" stroke-width="8" opacity=".18"/>',
        'fabric': '<path d="M30 35h680v369H30z" fill="var(--art-light)" opacity=".42"/><path d="M60 30V404M110 30V404M160 30V404M210 30V404M260 30V404M310 30V404M360 30V404M410 30V404M460 30V404M510 30V404M560 30V404M610 30V404M660 30V404" stroke="currentColor" opacity=".07" stroke-width="4"/>',
        'print': '<rect x="65" y="30" width="610" height="360" fill="var(--card)" stroke="currentColor" stroke-width="7"/><path d="M95 68h150M488 350h150" stroke="currentColor" stroke-width="5" opacity=".24"/>',
        'craft': '<ellipse cx="361" cy="367" rx="252" ry="28" fill="var(--art-light)"/><path d="M70 385l90-270M595 110l80 280" stroke="currentColor" opacity=".09" stroke-width="16"/>',
        'gallery': '<rect x="135" y="40" width="470" height="335" fill="var(--art-light)" stroke="currentColor" stroke-width="11"/><rect x="160" y="65" width="420" height="285" fill="var(--card)" opacity=".56"/>',
        'landscape': '<circle cx="521" cy="117" r="70" fill="var(--art-light)"/><path d="M0 320L110 208 238 295 347 175 461 284 581 163 740 310V422H0z" fill="var(--art-light)" opacity=".68"/>',
        'botanical': '<circle cx="365" cy="223" r="169" fill="var(--art-light)" opacity=".58"/><path d="M129 374q73-142 163-79M607 380q-90-151-151-53" stroke="currentColor" stroke-width="6" opacity=".17" fill="none"/>',
        'map': '<path d="M24 28l180 30 160-30 174 37 179-31v362l-179 32-174-37-160 30-180-30z" fill="var(--art-light)" opacity=".55"/><path d="M204 58v363M364 28v362M538 65v362" stroke="currentColor" stroke-width="4" opacity=".12"/>',
        'starfield': ''.join(f'<circle cx="{42+seed[i]*2 % 640}" cy="{41+seed[i+1] % 330}" r="{2+seed[i+2]%4}" fill="currentColor" opacity=".25"/>' for i in range(0,21,3)),
    }[canvas]
    # A first-person editorial plate: subject mark, then large subject-specific
    # line illustration, then a readable exhibit caption. For long subjects,
    # reduce the caption's font size instead of clipping/truncating its text.
    caption = theme.subjects[0]
    caption_font = min(22, max(12, 570 // max(len(caption), 1)))
    ink_icon = PICTOGRAMS[direction.subject_art]
    emblem = escape(theme.emblem)
    artwork_description = 'Авторская иллюстрация:' if theme.language == 'ru' else 'Original illustration:'
    label = escape(f'{artwork_description} {theme.title} — {caption}')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" class="hero-art" viewBox="0 0 740 470"'
            f' role="img" aria-label="{label}">'
            + coordinates
            + f'<text x="57" y="68" fill="currentColor" opacity=".55" font-size="16" font-weight="700" letter-spacing="2">{emblem}</text>'
            + f'<circle cx="365" cy="219" r="137" fill="var(--highlight)" opacity=".13"/>'
            + f'<g transform="translate(242 97) scale(1.24)" fill="none" stroke="{ink}" stroke-width="7" stroke-linecap="round" stroke-linejoin="round">{ink_icon}</g>'
            + '<path d="M50 409H689" stroke="currentColor" stroke-width="2" opacity=".22"/>'
            + f'<text x="55" y="442" font-size="{caption_font}" fill="currentColor" font-weight="700">{escape(caption)}</text>'
            + '</svg>')


# Stronger, topic-appropriate layout differentiation than the shared r56 hero.
# Each site gets only its own CSS from this compact set of editorial treatments;
# the existing responsive base and six reading compositions remain intact.
DIRECTION_CSS = {
 'diagram': '''.hero{background:linear-gradient(110deg,var(--paper),var(--card));border-bottom:3px solid var(--highlight)}.hero-copy{border-left:6px solid var(--highlight);padding-left:clamp(18px,3vw,42px)}.hero h1{font-size:clamp(2.8rem,5vw,6rem)}.visual{border:1px solid var(--line);border-radius:5px;box-shadow:16px 18px 0 -11px var(--highlight)}.card{border-radius:4px}.cards .card:nth-child(even){border-top:4px solid var(--highlight)}.top{border-bottom:2px solid var(--highlight)}''',
 'ledger': '''.hero{grid-template-columns:1.1fr .9fr;background:var(--card);border-bottom:1px solid var(--line)}.hero h1{font-size:clamp(3.2rem,5.7vw,6.6rem)}.visual{background:var(--paper);border:4px double var(--line);border-radius:0}.section-heading{border-bottom:3px double var(--line);padding-bottom:24px}.card{border:0;border-bottom:1px solid var(--line);border-radius:0}.feature{border-radius:0;border-top-width:2px}''',
 'exhibit': '''.hero{min-height:640px;gap:6vw}.hero h1{font-weight:650;max-width:12ch}.visual{border:22px solid var(--line);border-radius:0;transform:rotate(-1deg);box-shadow:15px 19px 0 -12px var(--highlight)}.cards .card{border-radius:0}.cards .card:nth-child(3n){background:var(--art-light)}.section-heading .eyebrow{letter-spacing:.3em}''',
 'manual': '''.hero{grid-template-columns:.86fr 1.14fr;min-height:480px}.hero h1{font-size:clamp(2.8rem,4.8vw,5.3rem)}.visual{border:1px solid var(--line);border-radius:3px}.hero-copy{padding-left:clamp(0px,2vw,24px)}.card{border-left:6px solid var(--highlight);border-radius:2px}.top{background:var(--card)}.inner-head{border-left:9px solid var(--highlight)}''',
 'typographic': '''.hero{display:flex;flex-direction:column;text-align:center;min-height:0;padding-top:95px;gap:34px}.hero-copy{max-width:960px}.hero h1{font-size:clamp(4rem,8vw,9rem);line-height:.91;letter-spacing:-.08em}.hero .lead{margin-inline:auto}.visual{width:min(100%,940px);border-radius:0;border-top:10px solid var(--highlight);min-height:0}.section-heading{margin-inline:auto;text-align:center}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.feature blockquote{font-style:italic}''',
 'laboratory': '''.hero{grid-template-columns:1fr 1fr;min-height:530px}.hero h1{font-family:system-ui,sans-serif;font-size:clamp(2.8rem,4.6vw,5.2rem);letter-spacing:-.07em}.visual{background:var(--art-light);border:1px solid var(--highlight);border-radius:0}.hero-copy .eyebrow{font-family:ui-monospace,monospace}.section{border-top:1px solid var(--line)}.cards .card{border-radius:0;border-top:5px solid var(--highlight)}.reading-index{border-radius:0}''',
 'workshop': '''.hero{grid-template-columns:1.04fr .96fr;background:linear-gradient(180deg,var(--paper),var(--art-light))}.hero h1{font-size:clamp(3.1rem,5.8vw,6.3rem)}.visual{border-radius:24px 5px 24px 5px;box-shadow:12px 12px 0 -6px var(--highlight)}.cards .card{border-radius:2px 20px 2px 20px}.card:nth-child(2n){background:var(--art-light)}.section-heading{border-left:5px solid var(--highlight);padding-left:25px}''',
 'kitchen': '''.hero{min-height:540px}.hero h1{font-family:Georgia,serif;font-size:clamp(3.1rem,5.6vw,6.6rem);letter-spacing:-.06em}.visual{background:var(--art-light);border-radius:45% 45% 18% 18%}.hero .cta{border-radius:5px}.cards .card{border-radius:28px 4px 28px 4px}.feature{border-radius:24px 4px 24px 4px;background:var(--art-light)}.about{border-top:8px solid var(--highlight)}''',
 'atlas': '''.hero{grid-template-columns:1.05fr .95fr;min-height:550px}.hero h1{font-size:clamp(3rem,5vw,6rem)}.visual{border-radius:50% 50% 12px 12px;border:2px solid var(--line)}.hero-copy{position:relative}.hero-copy:before{content:"";display:block;width:90px;height:9px;background:var(--highlight);margin-bottom:40px}.cards .card{border-top:6px solid var(--highlight);border-radius:0}.strip{letter-spacing:.12em}''',
 'field': '''.hero{grid-template-columns:.95fr 1.05fr;background:var(--card)}.hero h1{font-family:Georgia,serif;font-weight:600;font-size:clamp(3.2rem,5.8vw,6.5rem)}.visual{border:10px solid var(--paper);border-radius:12px;box-shadow:0 2px 0 var(--line)}.card{border-radius:15px;border-left:5px solid var(--highlight)}.section{background:var(--paper)}.feature{border-left:9px solid var(--highlight);border-top:1px solid var(--line)}''',
 'folio': '''.hero{grid-template-columns:1.2fr .8fr;border-bottom:1px solid var(--line)}.hero h1{font-family:Georgia,serif;font-weight:600;font-size:clamp(3.6rem,6vw,7.5rem)}.hero-copy{border-top:2px solid var(--highlight);padding-top:20px}.visual{border-radius:0;transform:rotate(1.2deg);box-shadow:12px 12px 0 -6px var(--art-light)}.cards .card{border:0;border-left:1px solid var(--line);border-radius:0}.feature{background:var(--art-light)}'''
}


def _scope_css(css, prefix):
    """Scope authored selectors above old layout selectors without changing them."""
    def sub(match):
        selector = match.group(1)
        if selector.strip().startswith('@'):
            return selector + '{'
        scoped = ','.join(prefix + ' ' + part.strip() for part in selector.split(','))
        return scoped + '{'
    return re.sub(r'(?:(?<=\{)|(?<=\})|^)([^{}]+)\{', sub, css)


def css_for(theme):
    direction = DIRECTIONS[theme.name]
    prefix = 'body.direction-' + direction.editorial
    base = DIRECTION_CSS[direction.editorial]
    # The mobile fixes must have equal-or-higher specificity to all desktop
    # layout/composition selectors already emitted by the r56 generator.
    mobile = '''@media(max-width:760px){.hero{display:flex;flex-direction:column;min-height:0;gap:24px;padding:36px 20px;text-align:left}.hero-copy{padding-left:0;border-left:0;max-width:100%}.hero-copy:before{margin-bottom:20px}.hero h1{font-size:clamp(2.5rem,10vw,4.4rem);line-height:1.06}.hero .lead{margin-left:0;margin-right:0}.visual{width:100%;max-width:100%;transform:none;min-height:0;border-width:2px;box-shadow:none;border-radius:12px}.cards .card{transform:none}.cards{display:grid;grid-template-columns:minmax(0,1fr)}.section-heading{padding-left:0}.feature{border-left:1px solid var(--line)}.top nav{gap:12px 18px}.top nav a{min-height:40px;display:inline-flex;align-items:center}}@media(max-width:350px){.brand{font-size:1.12rem;letter-spacing:-.025em}.hero h1{font-size:2.38rem}.section,.about,.inner-body,.inner-head{padding-left:17px;padding-right:17px}}@media print{.visual{transform:none!important;box-shadow:none!important}.hero{background:#fff!important;color:#111!important}}'''
    return ('\n' + _scope_css(base, prefix) + '\n' + _scope_css(mobile, prefix) + '\n').encode('utf-8')


def validate(catalog_names):
    names = set(catalog_names)
    if set(DIRECTIONS) != names:
        raise ValueError('visual direction catalog coverage mismatch')
    if not {d.editorial for d in DIRECTIONS.values()} == set(DIRECTION_CSS):
        raise ValueError('unused or missing editorial direction')
    if not {d.subject_art for d in DIRECTIONS.values()} <= set(PICTOGRAMS):
        raise ValueError('unknown artwork pictogram')
    return True
