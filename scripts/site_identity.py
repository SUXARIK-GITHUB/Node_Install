#!/usr/bin/env python3
"""Presentation architecture and genuine educational exhibits for the catalog.

The eight reading architectures change page hierarchy and information priority,
not just theme colors. Static content only: no analytics, fake authors, fabricated
services, invented activity timestamps or third-party resources.
"""

from html import escape

ARCHITECTURES = {
    'terminal': 'manual', 'documentation': 'manual',
    'dashboard': 'laboratory', 'research': 'laboratory',
    'editorial': 'folio', 'magazine': 'folio',
    'modern': 'studio', 'workshop': 'studio', 'architecture': 'studio',
    'gallery': 'exhibition', 'museum': 'exhibition', 'luxury': 'exhibition',
    'cafe': 'kitchen', 'food': 'kitchen',
    'nature': 'field', 'coastal': 'field',
}

# Specialised original text that includes concrete parameters, safe constraints,
# examples, useful procedures, and uncertainty. Each entry belongs to one site.
# These are not invented measurements, interviews, certifications or results.
EXHIBITS = {
 '13-cloud-ledger': (
    'Release handoff: a small example',
    'Consider an application made of a web process, an API and a data store. Draw three boxes and arrows for the calls, then describe one customer task: saving a draft. If the store is unavailable, the web page can still load, but saving must fail visibly rather than displaying a false confirmation. The diagram becomes useful only when it names the affected user action.',
    'A release record can include the artifact digest, configuration version, database compatibility requirement and an exact rollback condition. Record who verifies the result, but do not publish real credentials or secrets. A green startup log alone is not sufficient: verify a read, a write and recovery from a deliberately failed request in a separate test environment.',
    'For recovery exercises, restore a backup into a fresh destination, check its schema and selected records, then test that the application can read it. Keep recovery time and permissible data loss as different questions. No sample values on this page represent measurements from a real service.'),
 '14-edge-metrics': (
    'How to read a small latency sample',
    'Take a deliberately illustrative set of response times in milliseconds: 80, 82, 85, 91, 95, 98, 102, 105, 109 and 900. The median is 96.5 ms, while the slowest request takes 900 ms. Their arithmetic mean is 174.7 ms. Each statistic answers a different question, and ten observations are not enough to predict a production percentile.',
    'Before comparing a new release with an old one, use the same request mix, region, load and measurement interval. Name both the client-observed duration and server processing time. If a trace spans several services, verify clock alignment and avoid adding overlapping spans as though they were sequential work.',
    'An alert description should state the symptom, minimum duration, affected population and a first check. For example, a sustained rise in failed requests may justify investigation; one isolated slow browser request rarely does. Every threshold is local to the system being observed.'),
 '18-api-foundry': (
    'A small interface contract in practice',
    'Imagine POST /notes receiving a JSON object with a required title and optional labels. Decide explicitly whether an empty title is rejected, whether an unknown property is ignored, and which fields are returned after creation. Document success and validation failure with separate examples; do not make clients infer the contract from a stack trace.',
    'For repeatable submissions, accept an idempotency key and compare it with the original request body. A repeat with the same key and body should not create a second object. A different body with the same key needs a documented conflict response. The key is not a substitute for authentication or transaction safety.',
    'A migration can add an optional field before making it required. Older clients may omit the field until compatibility is established. Describe version boundaries, error codes and retries as part of the interface, not merely as implementation notes.'),
 '23-linen-studio': (
    'A textile sample sheet',
    'To compare two linen swatches, note the weave, dry hand, drape and opacity against the same light source. Let both samples rest in the same room before evaluating them. A photograph alone cannot show how the material bends or feels at the edge.',
    'Use a small comparison matrix: sample A and B in the columns; softness, creasing, transparency and care requirements in the rows. Add the intended use, because a sheer curtain and a kitchen towel demand different properties. Avoid declaring a material universally better without a particular use.',
    'If a swatch is washed, document the care label, water temperature and drying method first. Compare the finished dimensions with the original only after full drying. These observations are a way to make an informed choice, not a substitute for a manufacturer specification.'),
 '20-type-system': (
    'A readable interface specimen',
    'Start with three text levels rather than a large decorative scale: a page title, a section heading and body copy. Test them with actual paragraphs, error messages and long words. A hierarchy fails when every label looks equally important, even if the individual font sizes are mathematically harmonious.',
    'Build a simple button specimen in normal, hover, focused and disabled states. Keyboard focus must remain visibly distinct without relying on color alone. Test a narrow layout at increased text size and ensure that the button label does not disappear or force unwanted horizontal scrolling.',
    'For color choices, test real foreground and background pairs rather than a palette screenshot. WCAG contrast thresholds differ for normal and large text; icons, boundaries and focus states need separate inspection. Store the tested pair together with its intended component.'),
 '21-satellite-atlas': (
    'What a pixel can and cannot reveal',
    'A raster cell represents a ground footprint. A picture displayed at two hundred percent zoom still contains the same source measurements; it does not gain new streets or tree crowns. Check the stated pixel size and sensor characteristics before interpreting any small object.',
    'Cloud cover, shadow and viewing angle can all prevent a clear comparison between two dates. Mask unknown areas instead of explaining them as real landscape change. Record the acquisition dates, coordinate system and processing steps with the map, so the limitations are visible.',
    'For a classroom exercise, sketch a coastline on squared paper, then redraw it using larger cells. Notice which narrow features disappear. This illustrates resolution loss without claiming that the drawing is an actual satellite observation.'),
 '22-circuit-notes': (
    'From diagram to testable bench notes',
    'Write the supply voltage, expected current range, polarity and disconnection method at the top of a low-voltage teaching circuit. Mark component orientation on the diagram. Before supplying power, visually inspect connections and check for accidental shorts using an appropriate meter.',
    'Separate a proposed reading from an actual reading. A sensor value should be recorded with its units, instrument, conditions and an uncertainty note; a single number without these labels is hard to compare. Never treat a classroom sketch as a certified electrical design.',
    'Work only within safe low-voltage equipment and known component ratings. Mains wiring, batteries with high fault current and unfamiliar power supplies require appropriate training and protective measures. This example is a documentation exercise, not construction authorization.'),
 '24-print-house': (
    'A print proof checklist',
    'Prepare two copies of a one-page specimen: one on coated paper and one on uncoated stock. Include thin lines, small lettering, a grayscale ramp and a large solid area. Inspect edge sharpness, legibility and how ink sits on the chosen surface. Paper behavior matters more than a color seen on an uncalibrated display.',
    'Before approving a short run, confirm trim size, bleed, safe margins, fold direction and final page order. For a folded booklet, proof the imposed sheets, not just the reading-order PDF. Record which edition was approved, so a later correction does not silently replace the wrong file.',
    'A printer-specific profile, substrate and finishing method can change the result. Use an actual proof for production decisions; no color sample on this static page is calibrated to a particular press.'),
 '26-gallery-light': (
    'One object under three lighting conditions',
    'Set a harmless object on a matte surface, then observe it near a window, under a diffused lamp and under a small directional light. Keep the viewpoint fixed. Describe the shape and hardness of the shadows before deciding which setup communicates the object best.',
    'A glossy surface may reveal the reflection of a light source while a textured matte surface spreads highlights. Instead of saying the second surface is darker, compare where reflections appear and what details remain legible. Move only one light at a time to learn which change caused which effect.',
    'Try three crops of the same scene: close detail, balanced view and wider context. The extra empty space may change the implied scale. Record these as visual studies, not measurements or photographs of an actual exhibition.'),
 '27-architecture-folio': (
    'An ordinary courtyard as a design study',
    'Draw the outline of a hypothetical courtyard and mark three things before choosing materials: the most-used walking route, places that spend much of the day in shade, and a clear passage for anyone with limited mobility. A beautiful geometric plan can still be inconvenient in everyday use.',
    'Compare the rhythm of adjacent façades by marking window intervals and entrance locations. A repeated interval is a clue to the visual order, but it says little about the building performance. Thermal design, drainage and structural safety require separate professional analysis.',
    'Use simple sketches and labels to record the difference between observation and proposal. This is an educational drawing exercise, not a surveyed plan of an existing property.'),
 '30-fragrance-index': (
    'A vocabulary for comparing aromas',
    'Describe an aroma on separate axes: brightness, perceived sweetness, herbal character, woodiness and persistence. Compare two familiar harmless materials, such as citrus peel and a dried herb, at a comfortable distance rather than reducing either to a single adjective.',
    'Record the material, storage conditions and the time between opening and observation. Smell is influenced by temperature, expectation and adaptation; impressions taken at different times cannot be treated as laboratory measurements. Never sample unknown substances or inhale concentrated materials.',
    'A pyramid of top, middle and base notes is one way to describe a composition, not a promise that everyone will perceive it identically. Use the vocabulary to communicate an impression while leaving room for variation.'),
 '33-coffee-roastery': (
    'A repeatable cup instead of a perfect recipe',
    'For a controlled tasting exercise, begin with 15 g of ground coffee and 250 g of water. Record grind setting, water temperature, total contact time and brewing method. Keep these variables stable when comparing two beans, and change only one factor when exploring why the cup tastes different.',
    'If the result tastes unusually bitter, finer grinding or longer contact may be contributing factors, but bean roast, water and equipment also matter. Record the change rather than claiming a universal correction. Taste is a personal observation, not an objective performance score.',
    'Use a clean food-safe vessel and sensible water temperatures. A kitchen scale is more reliable for comparison than a spoon because coffee density varies. Notes should include enough detail that another person could reproduce the process.'),
 '35-citrus-studio': (
    'Balance in a small citrus dressing',
    'Mix one part citrus juice with three parts neutral or olive oil for a simple tasting baseline, then add seasoning gradually. Different fruits vary in acidity and sweetness, so the ratio is a starting point, not a fixed rule. Taste on a plain vegetable before adjusting the dressing.',
    'Only zest the clean colored outer layer of fruit; the pale pith can add unwanted bitterness. Compare grated zest added before serving with juice added earlier. One contributes aromatic oils, the other adds acidity and moisture, so they are not interchangeable.',
    'Label ingredients when preparing food for others, especially where allergens may be involved. Store prepared mixtures according to food-safety guidance, and do not leave fresh mixtures at room temperature for extended periods.'),
 '41-rooftop-garden': (
    'A safe container-garden plan',
    'Before choosing pots for a roof or balcony, check permitted loads, wind exposure, drainage and building rules. Saturated soil is heavier than dry soil; even a small group of containers can add significant weight. Structural capacity must be confirmed by a responsible professional.',
    'For an observation notebook, record hours of direct sun, wind direction, container volume and how quickly the growing medium dries. Match plants to those conditions instead of choosing them only for appearance. Provide a clear route to inspect and water them safely.',
    'Drainage water must not damage the building or neighboring property. Keep access routes free and avoid tools or containers that can be blown from height. These notes do not replace site-specific engineering advice.'),
 '43-island-guide': (
    'Planning a quiet coastal walk',
    'Draw a possible shoreline route on a local public map and identify safe exits to higher ground. Check tide tables, weather and local access restrictions before setting out; a shoreline that is passable at one hour may not remain so. Plan the return independently of the outward route.',
    'Carry water, appropriate footwear and a charged means of communication. Avoid promising a particular beach, shop or ferry service without up-to-date local data. Record the terrain type and an alternate route, not merely a distance on a map.',
    'Observe coastlines without disturbing nesting birds, protected plants or private land. These notes describe a method for planning; they are not a verified guide to a specific island or current transport service.'),
 '56-museum-index': (
    'Write a useful object catalogue entry',
    'Begin with observable facts: object type, approximate dimensions if actually measured, material, distinguishing marks and present condition. Separate those from interpretation. A metal surface may appear old without giving a reliable manufacturing date.',
    'Photograph a harmless sample object from front, side and detail angles with consistent labels. Preserve original descriptions, and record changes as new revisions rather than overwriting the first observations. Do not display identifying information about a previous owner without permission.',
    'A good catalogue card lets a reader trace what is known, what was inferred and what remains unverified. The sample on this site is a teaching example, not a record from a real collection.'),
}

TITLES = {
    'manual': ('Как пользоваться материалами', 'How to use these guides'),
    'laboratory': ('Маршрут исследования', 'A small research plan'),
    'folio': ('Подробности выпуска', 'Inside the edition'),
    'studio': ('Рабочие этапы', 'A workbench sequence'),
    'exhibition': ('Смотреть внимательнее', 'Looking closer'),
    'kitchen': ('Заметки для практики', 'Things to try'),
    'field': ('Полевой блокнот', 'A field notebook'),
}


def architecture(spec):
    return ARCHITECTURES[spec.layout]


def homepage_resource(spec, observations, tasks):
    """Topical reading guide with explicit research/practice steps, no filler copy."""
    kind = architecture(spec)
    label = TITLES[kind][0 if spec.language == 'ru' else 1]
    steps = tasks if kind in {'laboratory', 'studio', 'kitchen', 'field'} else observations
    entries = ''.join(
        f'<li><a href="journal.html#story-{i + 1}">{escape(title)}</a>'
        f'<p>{escape(steps[i])}</p></li>'
        for i, title in enumerate(spec.subjects)
    )
    return (f'<section class="resource resource-{kind}" aria-label="{escape(label)}">'
            f'<div class="resource-heading"><span>{escape(spec.category)}</span>'
            f'<h2>{escape(label)}</h2></div><ol>{entries}</ol></section>')


def about_practice(spec, tasks):
    ru = spec.language == 'ru'
    heading = 'Четыре темы для самостоятельной работы' if ru else 'Four paths for further study'
    intro = ('Начните с материала, который ближе к вашей задаче. Каждый пункт ведёт к подробной заметке и практическому упражнению.' if ru else
             'Choose the subject most relevant to your question. Each item leads to an article and a practical exercise.')
    rows = ''.join(f'<li><a href="journal.html#story-{i + 1}">{escape(name)}</a><p>{escape(task)}</p></li>'
                   for i, (name, task) in enumerate(zip(spec.subjects, tasks)))
    return f'<section class="practice-list"><h2>{heading}</h2><p>{intro}</p><ol>{rows}</ol></section>'


def exhibit(spec):
    """Dedicated long-form specimen for a manually edited subset, or empty."""
    item = EXHIBITS.get(spec.name)
    if not item:
        return ''
    title, *paragraphs = item
    return ('<section class="exhibit" id="special-study"><p class="exhibit-label">'
            + ('Пример и разбор' if spec.language == 'ru' else 'Example and analysis')
            + '</p><h2>' + escape(title) + '</h2>'
            + ''.join('<p>' + escape(p) + '</p>' for p in paragraphs) + '</section>')


CSS = '''
.resource{margin:0 auto;padding:clamp(28px,5vw,74px) clamp(20px,5vw,90px);border-bottom:1px solid var(--line)}
.resource-heading{display:flex;align-items:baseline;gap:24px;justify-content:space-between;border-bottom:2px solid var(--highlight);margin-bottom:26px}
.resource-heading span{font-size:.83rem;letter-spacing:.06em;text-transform:uppercase}
.resource-heading h2{font-size:clamp(1.6rem,3vw,3rem);margin:6px 0 22px}
.resource ol{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));list-style:none;gap:24px;padding:0;margin:0;counter-reset:topic}
.resource li{min-width:0;border-top:1px solid var(--line);padding:20px 0 0;counter-increment:topic}
.resource li:before{content:'0' counter(topic);font-size:.78rem;font-weight:800;letter-spacing:.12em;color:var(--highlight);display:block;margin-bottom:14px}
.resource li a{display:block;font-weight:750;text-underline-offset:5px;font-size:1.22rem;line-height:1.3}
.resource li p{margin:12px 0 4px;font-size:.98rem;line-height:1.65;color:var(--muted)}
.practice-list{border-top:3px solid var(--highlight);margin:48px 0;padding:28px 0 0}
.practice-list ol{padding-left:20px;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px 42px}
.practice-list li{line-height:1.65;padding:10px}.practice-list li p{line-height:1.65;color:var(--muted);margin:8px 0}
.exhibit{padding:clamp(24px,5vw,68px);background:var(--card);border-top:5px solid var(--highlight);margin:28px 0 50px}
.exhibit h2{font-size:clamp(2rem,4vw,3.7rem);line-height:1.1;margin:15px 0 28px}
.exhibit p{max-width:74ch;line-height:1.9;font-size:1.05rem}.exhibit-label{text-transform:uppercase;letter-spacing:.14em;font-size:.77rem!important}
.layout-terminal .page,.layout-documentation .page{max-width:none}
.layout-terminal .top{position:relative;display:grid;grid-template-columns:1fr auto}
.layout-terminal .hero{min-height:390px;padding-bottom:15px}
.layout-terminal .section{max-width:1200px;margin:auto}.layout-terminal .resource{background:var(--card);border-top:1px solid var(--highlight)}
.layout-terminal .resource ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-terminal .resource li{border-top:3px solid var(--highlight);padding:20px 14px}
.layout-documentation .hero{grid-template-columns:minmax(0,1.5fr) minmax(230px,.5fr);min-height:390px}
.layout-documentation .resource{max-width:1100px;margin:auto}.layout-documentation .resource ol{display:block;columns:2;column-gap:70px}.layout-documentation .resource li{break-inside:avoid;margin-bottom:25px}
.layout-dashboard .hero{grid-template-columns:1fr 1fr;min-height:320px}
.layout-dashboard .resource{background:var(--card)}.layout-dashboard .resource ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-dashboard .resource li{border:1px solid var(--line);padding:20px}
.layout-research .resource{max-width:1200px;margin:auto}.layout-research .resource ol{grid-template-columns:1fr 1fr;gap:16px}.layout-research .resource li{background:var(--card);padding:24px;border-left:4px solid var(--highlight)}
.layout-editorial .resource{display:grid;grid-template-columns:minmax(220px,.35fr) 1fr;gap:50px}
.layout-editorial .resource-heading{display:block;border:0}.layout-editorial .resource ol{grid-template-columns:1fr 1fr}
.layout-magazine .hero{padding-top:95px}.layout-magazine .resource{background:var(--card)}.layout-magazine .resource ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-magazine .resource li a{font:700 1.7rem/1.2 Georgia,serif}
.layout-modern .resource{max-width:1080px;margin:auto}.layout-modern .resource li{background:var(--card);padding:27px;border-radius:24px}
.layout-workshop .resource{background:var(--card)}.layout-workshop .resource ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-workshop .resource li{border-left:3px solid var(--highlight);padding:16px}
.layout-architecture .resource{padding:75px clamp(24px,8vw,150px)}.layout-architecture .resource-heading{justify-content:flex-start}.layout-architecture .resource li:nth-child(2n){margin-top:48px}
.layout-gallery .resource{background:var(--card)}.layout-gallery .resource-heading{justify-content:center;text-align:center;display:block;border:0}.layout-gallery .resource ol{grid-template-columns:1.2fr .8fr;gap:50px}.layout-gallery .resource li:nth-child(2){margin-top:80px}
.layout-museum .resource{display:grid;grid-template-columns:250px 1fr;gap:45px}.layout-museum .resource-heading{display:block;border:0}.layout-museum .resource ol{grid-template-columns:repeat(2,minmax(0,1fr))}
.layout-luxury .resource{max-width:1020px;margin:auto;text-align:center}.layout-luxury .resource-heading{justify-content:center;display:block}.layout-luxury .resource ol{grid-template-columns:1fr 1fr;text-align:left}
.layout-cafe .resource{background:var(--card);border-radius:24px;max-width:1100px;margin:55px auto}.layout-cafe .resource ol{grid-template-columns:repeat(2,minmax(0,1fr))}
.layout-food .resource{display:grid;grid-template-columns:minmax(220px,.35fr) 1fr;gap:40px}.layout-food .resource-heading{display:block;border:0}.layout-food .resource ol{grid-template-columns:1fr 1fr}
.layout-nature .resource{max-width:1120px;margin:auto}.layout-nature .resource ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-nature .resource li{border-top:3px solid var(--highlight)}
.layout-coastal .resource{background:var(--card)}.layout-coastal .resource ol{grid-template-columns:repeat(2,minmax(0,1fr));gap:40px}
@media(max-width:1100px){.layout-terminal .resource ol,.layout-dashboard .resource ol,.layout-magazine .resource ol,.layout-workshop .resource ol,.layout-nature .resource ol{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.resource{padding:38px 22px!important;display:block!important;margin:0 auto!important;border-radius:0!important}.resource-heading{display:block!important;text-align:left!important;border-bottom:2px solid var(--highlight)!important;margin-bottom:20px}.resource ol,.layout-documentation .resource ol,.layout-gallery .resource ol,.layout-museum .resource ol,.layout-nature .resource ol,.layout-dashboard .resource ol,.layout-terminal .resource ol,.layout-magazine .resource ol,.layout-workshop .resource ol{display:grid!important;grid-template-columns:1fr!important;columns:auto}.resource li{padding:12px 0!important;margin:0!important}.practice-list ol{grid-template-columns:1fr}.exhibit{padding:24px 20px}.layout-documentation .hero{display:flex;flex-direction:column}}
@media print{.resource{background:#fff!important;border:0!important;padding:15px 0!important}.resource ol,.practice-list ol{display:block!important}.resource li,.practice-list li{break-inside:avoid;page-break-inside:avoid;padding:8px 0!important}.exhibit{padding:20px 0;background:#fff!important}}
'''.encode('utf-8')

EXHIBITS.update({
 '20-type-system': (
    'Проверка иерархии на реальном тексте',
    'Начните с трёх уровней текста: заголовка страницы, подзаголовка и основного абзаца. Используйте не слова-заглушки, а настоящие сообщения, включая длинные слова и ошибки заполнения. Иерархия не работает, если все подписи выглядят одинаково важными, даже когда размеры шрифтов математически согласованы.',
    'Покажите кнопку в обычном состоянии, при наведении, фокусе с клавиатуры и блокировке. Фокус должен оставаться различимым не только за счёт цвета. Проверьте макет на узком экране с увеличенным текстом: подписи не должны исчезать или вызывать горизонтальную прокрутку.',
    'Для контраста проверяйте реальные сочетания текста и фона, а не палитру на отдельном изображении. Требования к обычному и крупному тексту различаются; границы элементов, иконки и фокус также требуют проверки. Сохраняйте подтверждённую пару цветов вместе с указанием её назначения.'),
 '22-circuit-notes': (
    'От схемы к проверяемым записям',
    'Вверху учебной схемы с безопасным низким напряжением подпишите питание, предполагаемый диапазон тока, полярность и способ отключения. Обозначьте ориентацию компонентов. Перед включением визуально проверьте соединения и подходящим прибором убедитесь в отсутствии случайных замыканий.',
    'Разделяйте ожидаемое показание и полученное измерение. Значение датчика записывайте вместе с единицами, прибором, условиями и замечанием о погрешности: число без контекста трудно сравнивать. Не выдавайте рисунок для занятий за сертифицированную электрическую схему.',
    'Работайте только со знакомым безопасным низковольтным оборудованием в пределах его характеристик. Сетевое напряжение и источники с высоким током короткого замыкания требуют соответствующей подготовки и защиты. Этот пример посвящён документированию, а не разрешению на самостоятельную сборку.'),
 '23-linen-studio': (
    'Карточка сравнения тканей',
    'Чтобы сравнить два образца льна, отметьте тип переплетения, сухую фактуру, драпировку и прозрачность при одинаковом освещении. Дайте тканям полежать в одной комнате перед осмотром. Фотография сама по себе не показывает, как материал изгибается или ощущается на кромке.',
    'Составьте небольшую таблицу: образцы А и Б по столбцам, а мягкость, сминаемость, просвечивание и уход — по строкам. Добавьте предполагаемое назначение: для лёгкой шторы и кухонного полотенца важны разные свойства. Не называйте образец безусловно лучшим вне конкретной задачи.',
    'Если образец стирали, заранее запишите условия с этикетки, температуру воды и способ сушки. Сравнивайте размеры только после полного высыхания. Наблюдения помогают принять решение, но не заменяют характеристики производителя.'),
 '24-print-house': (
    'Как проверить пробный оттиск',
    'Подготовьте два экземпляра небольшой полосы: на мелованной и немелованной бумаге. Добавьте тонкие линии, мелкий текст, шкалу серого и крупную заливку. Сравните чёткость края, читаемость и то, как краситель ложится на поверхность. Поведение бумаги важнее цвета на некалиброванном экране.',
    'Перед утверждением небольшого тиража проверьте обрезной формат, вылеты, безопасные поля, направление сгиба и порядок страниц. Для брошюры нужен пробный экземпляр с настоящей раскладкой листов, а не только файл в порядке чтения. Запишите, какая именно редакция макета была утверждена.',
    'Цветовой профиль конкретной машины, материал и способ отделки меняют результат. Для производственного решения используйте реальный пробный оттиск: цвета на этой статической странице не откалиброваны под типографию.'),
 '27-architecture-folio': (
    'Обычный двор как учебный проект',
    'Нарисуйте схематичный двор и ещё до выбора материалов отметьте три вещи: привычный путь жителей, зоны длительной тени и свободный проход для людей с ограниченной подвижностью. Эффектная геометрия плана может оставаться неудобной в повседневной жизни.',
    'Сравните ритм соседних фасадов по расстояниям между окнами и положению входов. Повторение интервалов помогает увидеть визуальный порядок, но само по себе ничего не доказывает об энергоэффективности здания. Дренаж, несущие конструкции и теплотехника требуют профессиональной проверки.',
    'В эскизах отделяйте наблюдаемое от предложенного. Это учебное упражнение по композиции и доступности, а не обмерный план реального объекта и не строительная документация.'),
 '30-fragrance-index': (
    'Словарь для сравнения ароматов',
    'Опишите запах по нескольким направлениям: свежесть, кажущаяся сладость, травянистость, древесные оттенки и длительность ощущения. Сравните два знакомых безопасных материала, например цитрусовую кожуру и сушёную траву, с комфортного расстояния. Одного прилагательного редко достаточно для понятной записи.',
    'Запишите материал, условия хранения и время между открытием и наблюдением. Восприятие зависит от температуры, ожиданий и привыкания; заметки, сделанные в разных условиях, нельзя считать лабораторными измерениями. Не вдыхайте концентрированные или неизвестные вещества.',
    'Разделение на верхние, средние и базовые ноты — способ описать композицию, а не обещание одинакового восприятия у всех людей. Используйте термины для передачи впечатления, сохраняя место для индивидуальных различий.'),
 '33-coffee-roastery': (
    'Повторяемая чашка вместо идеального рецепта',
    'Для пробной дегустации можно взять 15 г молотого кофе и 250 г воды. Запишите помол, температуру воды, время контакта и способ заваривания. При сравнении двух зёрен держите эти условия постоянными и меняйте по одному параметру, если хотите понять, откуда возникает отличие вкуса.',
    'Если чашка кажется слишком горькой, на результат могли повлиять мелкий помол или длительный контакт, но значение также имеют обжарка, вода и оборудование. Отмечайте изменение, а не объявляйте универсальную поправку. Вкусовая оценка — личное наблюдение, а не объективный балл качества.',
    'Используйте чистую пищевую посуду и разумную температуру воды. Кухонные весы удобнее мерной ложки при сравнении: насыпная плотность зёрен различается. Запись должна быть достаточно подробной, чтобы опыт можно было повторить.'),
 '35-citrus-studio': (
    'Баланс простого цитрусового соуса',
    'Смешайте одну часть цитрусового сока с тремя частями растительного масла как отправную точку и понемногу добавляйте приправы. Плоды различаются по кислотности и сладости, поэтому соотношение не универсально. Пробуйте соус на нейтральном овоще, прежде чем менять состав.',
    'Снимайте только чистый окрашенный верхний слой кожуры: белая часть может давать ненужную горечь. Сравните цедру, добавленную непосредственно перед подачей, и сок, введённый раньше. Цедра приносит ароматические масла, а сок — кислоту и влагу, поэтому одно не заменяет другое.',
    'Для других людей отмечайте состав блюда, особенно вероятные аллергены. Соблюдайте правила хранения свежих смесей и не оставляйте их надолго при комнатной температуре.'),
 '41-rooftop-garden': (
    'План безопасного контейнерного сада',
    'До выбора горшков для крыши или балкона проверьте допустимую нагрузку, ветер, водоотвод и правила здания. Мокрый грунт тяжелее сухого; даже небольшая группа контейнеров может существенно увеличить нагрузку. Возможности конструкции должен подтвердить ответственный специалист.',
    'В дневнике наблюдений отмечайте часы прямого солнца, направление ветра, объём ёмкости и скорость просыхания субстрата. Подбирайте растения к этим условиям, а не только по фотографии. Оставляйте свободный безопасный проход для осмотра и полива.',
    'Стекающая вода не должна повреждать здание или соседние помещения. Не оставляйте предметы, которые ветер может сбросить с высоты. Эти материалы не заменяют инженерного обследования конкретной площадки.'),
 '43-island-guide': (
    'Как подготовить прогулку по побережью',
    'Наметьте возможный маршрут на актуальной общедоступной карте и отметьте безопасные выходы с берега. Перед прогулкой проверьте приливы, погоду и местные ограничения доступа: участок, доступный в один час, позже может оказаться опасным. Обратный путь продумайте отдельно.',
    'Возьмите воду, подходящую обувь и заряженное средство связи. Не рассчитывайте на конкретную переправу или кафе без проверки актуального расписания. Записывайте тип поверхности и запасной маршрут, а не только расстояние между точками.',
    'Наблюдайте за берегом, не тревожа гнездящихся птиц и не повреждая охраняемые растения. Материал описывает метод планирования, а не проверенный маршрут по конкретному острову.'),
 '56-museum-index': (
    'Карточка музейного предмета',
    'Начните с наблюдаемых признаков: тип предмета, размеры при реальном измерении, материал, характерные метки и состояние. Отделяйте их от интерпретаций. Металлическая поверхность может выглядеть старой, но не доказывает дату изготовления.',
    'Сфотографируйте безопасный учебный объект спереди, сбоку и крупным планом, используя одинаковые обозначения. Сохраняйте первоначальные описания, а правки фиксируйте как новые редакции. Не публикуйте данные прежнего владельца без разрешения.',
    'Хорошая каталожная запись показывает, что известно, что предположено и что требует проверки. Пример на странице учебный, а не запись о реальном музейном собрании.'),
})

HERO_LABELS = {
 'manual':('Указатель разделов','Guide index'),
 'laboratory':('План наблюдений','Observation routes'),
 'folio':('В этом номере','Contents of this issue'),
 'studio':('Поэтапный просмотр','Explore the process'),
 'exhibition':('Экспозиция','On display'),
 'kitchen':('На этой странице','On the table'),
 'field':('Маршрут чтения','Reading trail'),
}


def hero_outline(spec):
    kind=architecture(spec)
    label=HERO_LABELS[kind][0 if spec.language=='ru' else 1]
    parts=''.join(f'<li><a href="journal.html#story-{i + 1}"><span>{i+1:02d}</span>{escape(title)}</a></li>'
                  for i,title in enumerate(spec.subjects))
    return f'<aside class="hero-outline" aria-label="{escape(label)}"><p>{escape(label)}</p><ol>{parts}</ol></aside>'


CSS += '''
.hero{position:relative}.hero-outline{min-width:0;border-top:2px solid var(--highlight);padding:15px 0;margin-top:25px}
.hero-outline p{font-weight:750;text-transform:uppercase;letter-spacing:.12em;font-size:.73rem;margin:0 0 12px}
.hero-outline ol{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:9px}
.hero-outline li{min-width:0}.hero-outline a{display:flex;gap:8px;font-size:.9rem;line-height:1.45;text-decoration:none;border-bottom:1px solid var(--line);padding:5px 0}
.hero-outline a:hover{text-decoration:underline;text-underline-offset:4px}.hero-outline span{font-size:.73rem;font-weight:800;color:var(--highlight)}
.layout-terminal .hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(330px,.75fr);min-height:650px;gap:50px}
.layout-terminal .hero-copy{align-self:start}.layout-terminal .hero-outline{grid-column:1;grid-row:2;max-width:680px}.layout-terminal .hero .visual{grid-column:2;grid-row:1/3;align-self:stretch}
.layout-dashboard .hero{display:grid;grid-template-columns:1fr .75fr;gap:20px;padding-top:55px;padding-bottom:55px}.layout-dashboard .hero-outline{grid-column:1/3;grid-row:2;background:var(--card);padding:20px}
.layout-dashboard .hero-outline ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-dashboard .hero-outline a{display:block}
.layout-documentation .hero{display:grid;grid-template-columns:minmax(0,1fr) minmax(250px,.8fr);grid-template-rows:auto auto;min-height:480px}
.layout-documentation .hero-copy{grid-column:1;grid-row:1}.layout-documentation .hero .visual{grid-column:2;grid-row:1/3}.layout-documentation .hero-outline{grid-column:1;grid-row:2}
.layout-research .hero{display:grid;grid-template-columns:1.2fr .8fr;grid-template-rows:auto auto;min-height:530px}
.layout-research .hero .visual{grid-column:2;grid-row:1/3}.layout-research .hero-outline{grid-column:1;grid-row:2}.layout-research .hero h1{font-size:clamp(3rem,6vw,5.8rem)}
.layout-editorial .hero{display:grid;grid-template-columns:1.1fr .9fr;grid-template-rows:auto auto;gap:16px;min-height:680px}.layout-editorial .hero-copy{grid-column:1;grid-row:1}.layout-editorial .hero .visual{grid-column:2;grid-row:1/3}.layout-editorial .hero-outline{grid-column:1;grid-row:2}
.layout-magazine .hero{display:flex;flex-direction:column;align-items:stretch;text-align:center;padding-top:80px;gap:10px}.layout-magazine .hero-copy{max-width:100%;align-self:center}.layout-magazine .hero h1{font-size:clamp(3.8rem,8vw,9rem)}.layout-magazine .hero .visual{max-width:970px;align-self:center;max-height:260px;overflow:hidden}.layout-magazine .hero-outline{width:100%}.layout-magazine .hero-outline ol{grid-template-columns:repeat(4,minmax(0,1fr))}.layout-magazine .hero-outline a{display:block}
.layout-modern .hero{display:grid;grid-template-columns:.86fr 1.14fr;grid-template-rows:auto auto;gap:15px}.layout-modern .hero-outline{grid-column:1;grid-row:2}.layout-modern .hero .visual{grid-column:2;grid-row:1/3}
.layout-workshop .hero{display:grid;grid-template-columns:1.05fr .95fr;grid-template-rows:auto auto;gap:15px}.layout-workshop .hero .visual{grid-column:1;grid-row:1/3}.layout-workshop .hero-copy{grid-column:2;grid-row:1}.layout-workshop .hero-outline{grid-column:2;grid-row:2}
.layout-architecture .hero{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:auto auto;gap:5px}.layout-architecture .hero .visual{grid-column:1;grid-row:1/3;min-height:460px}.layout-architecture .hero-copy{grid-column:2;grid-row:1;padding-left:40px}.layout-architecture .hero-outline{grid-column:2;grid-row:2;margin-left:40px}
.layout-gallery .hero{display:grid;grid-template-columns:1.4fr .6fr;grid-template-rows:auto auto;gap:28px;padding-top:60px;padding-bottom:50px}.layout-gallery .hero .visual{grid-column:1;grid-row:1/3;min-height:510px;border-radius:0}.layout-gallery .hero-copy{grid-column:2;grid-row:1}.layout-gallery .hero-outline{grid-column:2;grid-row:2}
.layout-museum .hero{display:grid;grid-template-columns:.9fr 1.1fr;grid-template-rows:auto auto;gap:20px}.layout-museum .hero .visual{grid-column:1;grid-row:1/3;border:12px solid var(--line);border-radius:0}.layout-museum .hero-copy{grid-column:2;grid-row:1}.layout-museum .hero-outline{grid-column:2;grid-row:2}
.layout-luxury .hero{display:flex;flex-direction:column;text-align:center;align-items:center;gap:8px;padding-top:90px;padding-bottom:40px}.layout-luxury .hero h1{font-size:clamp(3.7rem,8vw,8rem)}.layout-luxury .hero .visual{max-width:850px;width:100%;max-height:285px;overflow:hidden}.layout-luxury .hero-outline{width:100%;max-width:900px}.layout-luxury .hero-outline ol{grid-template-columns:repeat(4,minmax(0,1fr))}
.layout-cafe .hero{display:grid;grid-template-columns:1.1fr .9fr;grid-template-rows:auto auto;gap:5px;padding-top:60px}.layout-cafe .hero .visual{grid-column:2;grid-row:1/3}.layout-cafe .hero-outline{grid-column:1;grid-row:2}.layout-cafe .hero h1{font-size:clamp(3.7rem,7vw,7.2rem)}
.layout-food .hero{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:auto auto;gap:15px}.layout-food .hero .visual{grid-column:1;grid-row:1/3;border-radius:50% 50% 10% 10%}.layout-food .hero-copy{grid-column:2;grid-row:1}.layout-food .hero-outline{grid-column:2;grid-row:2}
.layout-nature .hero{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:auto auto}.layout-nature .hero-copy{grid-column:1;grid-row:1}.layout-nature .hero-outline{grid-column:1;grid-row:2}.layout-nature .hero .visual{grid-column:2;grid-row:1/3;background:transparent;box-shadow:none}
.layout-coastal .hero{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:auto auto;min-height:650px}.layout-coastal .hero-copy{grid-column:1;grid-row:1}.layout-coastal .hero-outline{grid-column:1;grid-row:2}.layout-coastal .hero .visual{grid-column:2;grid-row:1/3;border-radius:0}
@media(max-width:920px){.hero.hero-expanded{display:flex!important;flex-direction:column!important;align-items:stretch!important;gap:16px!important;min-height:0!important;padding:35px 22px!important;text-align:left!important}.hero-expanded>.hero-copy,.hero-expanded>.visual,.hero-expanded>.hero-outline{grid-column:auto!important;grid-row:auto!important;order:0!important;margin:0!important;max-width:100%!important;min-width:0!important;padding-left:0!important}.hero-expanded>.visual{width:100%!important;max-height:280px!important;min-height:190px!important}.hero-expanded>.hero-outline ol{display:grid;grid-template-columns:1fr 1fr!important}.layout-magazine .hero-expanded h1,.layout-luxury .hero-expanded h1{font-size:clamp(2.75rem,10vw,5rem)}}
@media(max-width:440px){.hero-expanded>.hero-outline ol{grid-template-columns:1fr!important}}
@media print{.hero-outline{display:none!important}}
'''.encode('utf-8')
