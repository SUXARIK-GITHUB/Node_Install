#!/usr/bin/env python3
"""Twelve individually composed, independent, self-contained site designs.

Only local HTML, CSS and SVG. No JS, external endpoints, logins, data capture,
claims of live monitoring, or impersonation of third-party brands. These original
sample sites use nine-file bundles compatible with the locked-down Nginx route
allowlist in staging_web_deploy.py. These are not imports of third-party themes.
"""
from dataclasses import dataclass
from html import escape


def h(v):
    return escape(str(v), quote=True)


@dataclass(frozen=True)
class Signature:
    name: str
    title: str
    category: str
    language: str
    mode: str
    headline: str
    description: str
    emblem: str
    cards: tuple  # (heading, original multi-sentence paragraph)
    highlights: tuple  # (short fact, supporting detail)
    questions: tuple  # (question, answer)
    intro: str


SIGNATURES = {
    s.name: s for s in [
        Signature('109-copper-workshop', 'Медный ключ', 'Ремесленная мастерская', 'ru', 'workshop',
            'Вещи служат дольше, если их понимать', 'Небольшой справочник по уходу за инструментом, ремонту и материалам.', '⚙',
            (('Диагностика инструмента', 'Сначала очищают контактные поверхности и проверяют крепёж. Только после осмотра можно понять, есть ли смысл разбирать корпус и менять расходные детали.'),
             ('Поверхность и патина', 'Латунь темнеет неравномерно из-за влажности и контакта с руками. Мягкая очистка сохраняет фактуру лучше агрессивной полировки.'),
             ('Рабочее место', 'Подписанные лотки для мелких деталей и рассеянный свет уменьшают вероятность потери крепежа. Последовательность действий полезно фотографировать.'),
             ('Сборка и проверка', 'После ремонта проверяют люфт, движение и крепления без нагрузки. Нагрев, вибрации и шум — сигналы для повторного осмотра.')),
            (('01 / Материал', 'Дерево · латунь · сталь'), ('02 / Метод', 'Разобрать · изучить · собрать'), ('03 / Идея', 'Ремонт лучше замены')),
            (('Есть ли здесь запись на ремонт?', 'Нет. Это независимый справочный сайт с открытыми материалами, без заявок и сбора контактов.'),
             ('Можно ли повторять советы самостоятельно?', 'Работа с электроинструментом требует соблюдения инструкции изготовителя и правил безопасности.'),
             ('Где найти последовательность работы?', 'Основные заметки собраны в разделе «Практика»; его можно читать без регистрации.')),
            'Сделать хорошую вещь непросто. Поддерживать её в порядке — тоже ремесло.'),
        Signature('110-blue-harbor', 'Blue Harbor', 'Travel & Hospitality', 'en', 'hotel',
            'An unhurried guide to the coast', 'A quiet editorial space about shoreline architecture, light, and the rituals of travel.', '◒',
            (('A room with morning light', 'North-facing windows often create soft, even light throughout the day. Simple textiles and clear surfaces keep the room connected to the landscape.'),
             ('The walk to the water', 'A coastal path changes character with wind and season. Notes on tides, public access, and weather make a more useful walk than a list of landmarks.'),
             ('Designing a slower day', 'A short plan leaves room for an unexpected café or an extra hour by the sea. Good travel notes document atmosphere rather than promises.'),
             ('Quiet materials', 'Timber, stone, ceramics, and salt-weathered metal age differently. Their imperfections can make a place feel more memorable.')),
            (('Coastline', 'Observation rather than booking'), ('Journal', 'Architecture and tides'), ('Routes', 'Everyday excursions')),
            (('Can I book a room here?', 'No. Blue Harbor is an independent sample travel journal and does not accept reservations.'),
             ('Do the routes include live conditions?', 'No. Check local advisories, forecasts and tide tables before setting out.'),
             ('Are visitor details collected?', 'No registration, analytics, payment or contact forms are present.')),
            'Between the last street and the open water, there is always more to notice.'),
        Signature('111-atlas-docs', 'Atlas Interface', 'Developer Documentation', 'en', 'docs',
            'Predictable interfaces start with clear contracts', 'A practical documentation notebook about well-structured APIs and operational reliability.', '</>',
            (('Request validation', 'Define required fields, types, length boundaries and error responses before building a request handler. Distinguish malformed input from an unavailable dependency.'),
             ('Idempotent operations', 'Retries are routine on unstable networks. An idempotency key and explicit operation state help clients avoid accidentally repeating a change.'),
             ('Versioning contracts', 'Backward compatibility is easiest to keep when changes are additive and errors remain machine-readable. Record supported versions alongside examples.'),
             ('Observability', 'Measure the request path without exposing tokens, cookies, passwords or personal data in the resulting logs.')),
            (('Response model', 'Structured, documented errors'), ('Retries', 'Backoff with explicit limits'), ('Security', 'Least-privilege permissions')),
            (('Is this a production API?', 'No. This is self-contained technical reference material with no live endpoints.'),
             ('Can examples be copied?', 'Examples are intentionally generic. Review authentication, errors and limits for your own application.'),
             ('What is the most useful starting point?', 'Read the contract overview, then the sections on request validation and repeatable operations.')),
            'Documentation should explain not only the happy path but also what the caller can do when it fails.'),
        Signature('112-lumen-editions', 'Lumen Editions', 'Art & Editions', 'en', 'gallery',
            'A gallery of quiet, geometric gestures', 'Original visual studies in shape, surface and generous negative space.', '✳',
            (('Folding light', 'A study in three translucent planes: each layer reveals another edge. The composition uses only vectors and can be reproduced without external imagery.'),
             ('The wide margin', 'Whitespace gives each shape time to register. The next mark matters because the page leaves space for it.'),
             ('Cut paper', 'Overlapping fields suggest material thickness without imitating any particular real work or artist.'),
             ('An unfinished square', 'A broken frame is still legible; perception fills the missing corner. The exercise explores how little a form needs.')),
            (('Edition', 'Independent vector compositions'), ('Collection', 'Material and light'), ('Reading', 'Notes on process')),
            (('Are these works available to buy?', 'No, this is a non-commercial sample art journal and not a storefront.'),
             ('Are images fetched from a CDN?', 'No. All visuals are original, embedded vector illustrations.'),
             ('Can the content be viewed offline?', 'Yes. The pages and styling have no remote runtime dependencies.')),
            'The same shape becomes another object when it changes size, weight, or position.'),
        Signature('113-borough-kitchen', 'Кухня квартала', 'Сезонная кухня', 'ru', 'kitchen',
            'Простая еда. Большое внимание к деталям', 'Редакционный сборник сезонных блюд, кухонных приёмов и заметок о продуктах.', '✦',
            (('Овощи в печи', 'При высокой температуре поверхность карамелизуется быстрее, чем размягчается середина. Важно нарезать овощи близкими по размеру кусочками.'),
             ('Тёплый хлеб', 'Короткий список ингредиентов не упрощает процесс. Время брожения, влажность и правильное остывание влияют на мякиш.'),
             ('Зелень и кислота', 'Несколько капель лимонного сока часто раскрывают вкус бобовых и запечённых овощей. Кислоту добавляют постепенно.'),
             ('Домашний бульон', 'Прозрачность зависит от умеренного нагрева, а аромат — от аккуратного сочетания овощей и трав. Соль лучше корректировать ближе к концу.')),
            (('Сезон', 'Овощи и зелень'), ('Подход', 'Неспешная кухня'), ('На столе', 'Простые сочетания')),
            (('Можно ли заказать еду?', 'Нет. Этот сайт — самостоятельный кулинарный журнал, без приёма заказов.'),
             ('Здесь есть профессиональные рецептуры?', 'Материалы обзорные и не заменяют точные рецепты с проверенными условиями приготовления.'),
             ('Нужен ли аккаунт?', 'Нет, все страницы открываются без авторизации и сбора персональных данных.')),
            'Вкус начинается с привычных продуктов и привычки замечать небольшие отличия.'),
        Signature('114-herbarium-plates', 'Herbarium Plates', 'Natural History', 'en', 'botanical',
            'A field archive of leaves and seasonal forms', 'Illustrated botanical notes about pattern, climate, and the small structures of plants.', '❧',
            (('Leaf architecture', 'Veins distribute water and strengthen the blade. Their branching patterns provide useful visual clues, though identification should rely on multiple features.'),
             ('Seed dispersal', 'Wind, water, and animals move seeds in very different ways. Studying the surrounding habitat is as important as examining the seed itself.'),
             ('Pressed specimens', 'Drying a specimen carefully preserves a record of its shape. Collection must follow local conservation rules and should avoid protected plants.'),
             ('Seasonal change', 'The color of a leaf reflects changing pigments and environmental conditions. A dated sketch can communicate details that a single label misses.')),
            (('Specimens', 'Original illustrated studies'), ('Fieldwork', 'Observe without damage'), ('Archive', 'Notes by season')),
            (('Can I identify a wild plant from this website?', 'No. Illustrations are stylized and are not identification keys.'),
             ('Can I collect any specimen?', 'No. Respect protected areas, land access rules, and species conservation requirements.'),
             ('Is any personal location stored?', 'No. The pages are static and do not request geolocation.')),
            'The shape of a leaf records weather, time, and place without writing a single word.'),
        Signature('115-reading-room', 'Читальный зал', 'Книги и архивы', 'ru', 'library',
            'Полка, на которой всегда есть место новой мысли', 'Небольшая редакционная библиотека о чтении, каталогах и культуре заметок.', '▤',
            (('Поля на страницах', 'Короткая заметка на полях помогает спустя месяц вспомнить не цитату, а собственную реакцию. Записывать полезнее вопрос, чем готовый вывод.'),
             ('Тематические каталоги', 'Собранные вокруг одной темы материалы создают связи между произведениями. Хороший каталог объясняет принцип отбора.'),
             ('Домашний архив', 'Даже небольшая книжная коллекция нуждается в понятной системе названий и мест хранения. Последовательность важнее сложности.'),
             ('Медленное чтение', 'Иногда одной главы достаточно, чтобы увидеть авторский замысел. Пауза полезна, если после неё остаётся наблюдение.')),
            (('Каталог', 'Четыре редакционных темы'), ('Полка', 'Тексты без регистрации'), ('Принцип', 'Порядок и внимание')),
            (('Можно ли здесь взять книгу?', 'Нет. Читальный зал — информационный макет, без абонемента и учётных записей.'),
             ('Есть ли внешние библиотеки?', 'Нет, сайт не подключается к сторонним каталогам и не загружает трекеры.'),
             ('Можно ли пользоваться с телефона?', 'Да, страницы адаптируются под небольшие экраны.')),
            'У хорошего текста есть продолжение: то, что читатель замечает уже после закрытой книги.'),
        Signature('116-vinyl-room', 'Needle & Groove', 'Music Culture', 'en', 'vinyl',
            'Listen closely. Keep the whole side.', 'A record-collecting journal on sleeve design, analog listening and the care of physical media.', '♫',
            (('The first groove', 'A clean stylus, balanced tracking force and a level surface are the fundamentals of safe playback. Equipment care matters more than fashionable accessories.'),
             ('Sleeve as an object', 'A record cover has scale and tactile presence that thumbnails cannot reproduce. Typography and artwork shape our memory of the sound.'),
             ('A listening shelf', 'Grouping records by mood or discovery can be more rewarding than strict genre. A personal catalogue should make rediscovery easy.'),
             ('Proper storage', 'Keep sleeves upright, away from heat and moisture, and avoid touching the playing surface. Small habits extend the life of a collection.')),
            (('FORMAT', 'A / B sides'), ('SHELF', 'Analog observations'), ('STUDIO', 'Independent editorial')),
            (('Does this site stream music?', 'No. There are no audio players or copyrighted recordings.'),
             ('Are records sold here?', 'No. This is a static editorial site, not a store.'),
             ('Is any external player required?', 'No plugins or third-party services are needed to read the pages.')),
            'A record is a sequence of choices: surface, space, artwork, rhythm, and the space between tracks.'),
        Signature('117-civic-archive', 'Городская память', 'Архив городской среды', 'ru', 'archive',
            'Улицы меняются. Истории остаются', 'Независимые заметки о городской типографике, маршрутах и архитектурных деталях.', '▦',
            (('Следы вывесок', 'Старые крепления и контуры букв часто переживают саму вывеску. Внимательный взгляд на фасад помогает представить, как менялось назначение здания.'),
             ('Память двора', 'Двор отражает повседневные маршруты жителей. Небольшие изменения пространства можно фиксировать в эскизах и последовательных фотографиях.'),
             ('Городская сетка', 'Ширина тротуара, ритм дверей и расположение окон влияют на восприятие улицы. Геометрия здесь тесно связана с привычками людей.'),
             ('Бережная фиксация', 'Публичные наблюдения не должны раскрывать личные данные, номера квартир или детали частной жизни прохожих.')),
            (('Объект', 'Улица и архитектура'), ('Источники', 'Открытые наблюдения'), ('Метод', 'Описание без персональных данных')),
            (('Это официальный городской архив?', 'Нет. Это независимый демонстрационный редакционный проект.'),
             ('Есть ли в нём фотографии жителей?', 'Нет. Иллюстрации абстрактные и не содержат изображений реальных людей.'),
             ('Можно ли прислать материал?', 'Нет. Форм загрузки файлов и контактных форм здесь нет.')),
            'Порой самую точную историю города рассказывают форма двери и краска на старой стене.'),
        Signature('118-waypoint', 'Waypoint Field Club', 'Outdoor & Navigation', 'en', 'trail',
            'Paths are made of observations', 'A practical journal for reading maps, weather, and the landscape on a careful walk.', '△',
            (('Before the trail', 'A planned route should account for daylight, elevation, terrain and an exit option. Share the plan with a trusted person before departure.'),
             ('Contours and slopes', 'Close contour lines mean a steeper climb. Reading the terrain from a map helps anticipate effort before a hike.'),
             ('Weather windows', 'A pleasant forecast at the trailhead does not imply identical conditions at higher elevations. Check regional advisories.'),
             ('Leave the landscape intact', 'Follow established paths where possible and bring waste back. Observe wildlife without approaching or feeding it.')),
            (('FIELD NOTE', 'Maps, not live navigation'), ('ELEVATION', 'Read contour spacing'), ('ROUTE', 'Plan for the return')),
            (('Does this include live navigation?', 'No. Sketches are illustrative and cannot replace a map or a navigation device.'),
             ('Are the trails real?', 'No specific route or accessible destination is promised by this sample journal.'),
             ('Are current warnings included?', 'No. Consult official advisories and forecasts.')),
            'A good route begins long before the first step, with a map and a question about the terrain.'),
        Signature('119-type-lab', 'Текст и форма', 'Дизайн и типографика', 'ru', 'type',
            'Буквы создают архитектуру чтения', 'Набор заметок о гарнитурах, масштабах и том, как текст ведёт взгляд по странице.', 'Aa',
            (('Длина строки', 'Слишком длинная строка требует лишнего движения глаз. Ограниченная ширина колонки часто важнее экзотического выбора гарнитуры.'),
             ('Ритм заголовка', 'Контраст кеглей создаёт иерархию, но сам по себе не заменяет ясной структуры. Заголовок должен соответствовать следующему разделу.'),
             ('Контраст и фон', 'Цвет и насыщенность шрифта стоит проверять на небольших экранах и при низкой яркости. Эстетика не должна вредить читабельности.'),
             ('Знаки препинания', 'Тире, кавычки и пробелы делают набор узнаваемым. Типографические привычки влияют на скорость и комфорт чтения.')),
            (('КЕГЛЬ', 'Масштаб и пауза'), ('ИНТЕРВАЛ', 'Ритм строки'), ('ОТСТУП', 'Пространство текста')),
            (('Это коллекция готовых шрифтов?', 'Нет. Здесь используются стандартные системные шрифты, без распространения сторонних гарнитур.'),
             ('Можно ли менять размер текста?', 'Да. Вёрстка рассчитана на масштабирование браузера и системные настройки.'),
             ('Есть ли редактор шрифтов?', 'Нет. Это тематический справочный сайт, а не программный сервис.')),
            'Красивый набор не отвлекает от мысли — он помогает ей стать понятнее.'),
        Signature('120-celestial-index', 'Celestial Index', 'Astronomy & Observation', 'en', 'celestial',
            'A small atlas for looking up', 'An original illustrated guide to sky maps, orbital shapes and patient night observation.', '✧',
            (('Moonlight and contrast', 'The Moon can wash out faint stars and change what is visible. Planning an evening observation begins with lunar phase and weather.'),
             ('Finding direction', 'The apparent path of stars depends on latitude and time. A sky map is useful only when correctly oriented.'),
             ('Writing an observation', 'Record the time, conditions, instrument and what was actually visible. An honest note is more valuable than a dramatic description.'),
             ('Light around us', 'Shielded outdoor lights reduce glare and preserve the darkness needed for observing the sky.')),
            (('MAP', 'Illustrative star geometry'), ('NOTES', 'Observation method'), ('LIGHT', 'Dark-sky awareness')),
            (('Does this calculate live star positions?', 'No. Diagrams are educational artwork and not astronomical predictions.'),
             ('Is it safe to observe the Sun?', 'Never look directly at the Sun through an optical instrument without certified solar protection.'),
             ('Do the pages require internet access?', 'No. All resources are local static files.')),
            'There are useful stories in the sky, but they begin with careful records rather than guesses.'),
    ]
}

PALETTES = {
 'workshop': ('#f4ebdd','#2d2925','#9b4e2e','#e0cbb0','Georgia,serif'),
 'hotel': ('#e8eee9','#122d34','#1c7890','#b8d3d0','Georgia,serif'),
 'docs': ('#0a1421','#ecf6ff','#6fd6b4','#193347','ui-monospace,monospace'),
 'gallery': ('#f4f0ed','#201e1e','#c1493d','#dfd6d1','Georgia,serif'),
 'kitchen': ('#fff5df','#3f2b19','#d46729','#f0d6a9','Georgia,serif'),
 'botanical': ('#edf1e6','#1b3826','#3c8059','#cbdac7','Georgia,serif'),
 'library': ('#f4ede0','#2a2421','#9d5a3b','#e6d1b9','Georgia,serif'),
 'vinyl': ('#131315','#f7e9d7','#f3ac4b','#363136','ui-sans-serif,system-ui'),
 'archive': ('#eae7dc','#232724','#79836d','#d0d4c4','Georgia,serif'),
 'trail': ('#e9efe5','#183e34','#497e53','#cbdac7','ui-sans-serif,system-ui'),
 'type': ('#f5f2ea','#171a17','#b33f27','#d8d2ca','ui-sans-serif,system-ui'),
 'celestial': ('#0e1730','#eff2fb','#b9baff','#24375d','ui-sans-serif,system-ui'),
}

# Separate original vector studies for each site family, not a shared icon
# with a hue change. Keep SVG free of scripts/external references.
ART = {
 'workshop':'<path d="M72 338L304 80L565 330L420 438Z" fill="none" stroke="currentColor" stroke-width="5"/><path d="M120 324L307 140L490 324" fill="none" stroke="var(--accent)" stroke-width="22"/><circle cx="302" cy="290" r="88" fill="none" stroke="currentColor" stroke-width="6"/><circle cx="302" cy="290" r="23" fill="var(--accent)"/>',
 'hotel':'<circle cx="495" cy="106" r="64" fill="var(--accent)"/><path d="M20 275Q140 203 258 279T500 277T720 279V470H20Z" fill="var(--soft)"/><path d="M18 336Q128 295 254 338T503 337T720 339M18 398Q147 351 251 405T500 402T720 402" fill="none" stroke="currentColor" stroke-width="8" opacity=".7"/>',
 'docs':'<rect x="58" y="66" width="605" height="340" rx="17" fill="var(--soft)"/><circle cx="91" cy="93" r="8" fill="var(--accent)"/><circle cx="119" cy="93" r="8" fill="currentColor" opacity=".3"/><path d="M112 161L167 211L112 259M193 260H381M192 309H551" fill="none" stroke="var(--accent)" stroke-width="12" stroke-linecap="round"/>',
 'gallery':'<rect x="50" y="65" width="220" height="330" fill="var(--accent)"/><circle cx="476" cy="216" r="155" fill="none" stroke="currentColor" stroke-width="16"/><path d="M340 80L610 350M328 350L608 76" stroke="var(--accent)" stroke-width="20"/>',
 'kitchen':'<circle cx="360" cy="245" r="193" fill="var(--soft)"/><circle cx="360" cy="245" r="133" fill="none" stroke="var(--accent)" stroke-width="9"/><path d="M268 212Q356 120 440 212T268 212M292 340L431 175" fill="none" stroke="currentColor" stroke-width="13"/>',
 'botanical':'<path d="M350 430V70" stroke="currentColor" stroke-width="9"/><path d="M345 273C137 271 159 122 221 93C300 128 349 223 345 273M353 240C554 241 552 106 492 78C416 110 351 191 353 240M346 390C180 382 168 294 201 265C288 283 347 345 346 390" fill="var(--accent)"/><path d="M230 135L343 261M470 122L354 228M231 303L344 376" stroke="var(--bg)" stroke-width="8"/>',
 'library':'<path d="M85 96V406M223 96V406M370 96V406M524 96V406M653 96V406" stroke="currentColor" stroke-width="7"/><rect x="94" y="153" width="116" height="217" fill="var(--accent)"/><rect x="238" y="119" width="119" height="251" fill="var(--soft)"/><rect x="384" y="173" width="128" height="197" fill="var(--accent)"/><path d="M70 374H679" stroke="currentColor" stroke-width="20"/>',
 'vinyl':'<circle cx="361" cy="226" r="210" fill="#2c292d" stroke="var(--accent)" stroke-width="8"/><circle cx="361" cy="226" r="154" fill="none" stroke="#8a817b" stroke-width="2"/><circle cx="361" cy="226" r="104" fill="none" stroke="#8a817b" stroke-width="2"/><circle cx="361" cy="226" r="69" fill="var(--accent)"/><circle cx="361" cy="226" r="10" fill="#1b1b1b"/>',
 'archive':'<rect x="80" y="60" width="558" height="358" fill="var(--soft)" stroke="currentColor" stroke-width="8"/><path d="M123 90V389M201 90V389M320 90V389M450 90V389M575 90V389M93 153H625M93 251H625M93 340H625" stroke="currentColor" stroke-width="3"/><circle cx="404" cy="252" r="75" fill="var(--accent)"/>',
 'trail':'<path d="M50 380L222 154L334 280L489 68L675 380Z" fill="var(--soft)" stroke="currentColor" stroke-width="7"/><path d="M51 380L231 222L330 314L494 156L678 380" fill="none" stroke="var(--accent)" stroke-width="18"/><path d="M98 422H624" stroke="currentColor" stroke-width="10" stroke-dasharray="9 15"/>',
 'type':'<text x="100" y="327" font-family="Georgia,serif" font-size="315" font-weight="bold" fill="var(--accent)">Ag</text><path d="M100 368H645M100 98H645" stroke="currentColor" stroke-width="5"/><path d="M120 411H355M400 411H650" stroke="var(--accent)" stroke-width="10"/>',
 'celestial':'<circle cx="361" cy="239" r="174" fill="none" stroke="var(--accent)" stroke-width="3"/><ellipse cx="360" cy="239" rx="280" ry="98" fill="none" stroke="currentColor" stroke-width="5" transform="rotate(-29 360 239)"/><circle cx="362" cy="239" r="88" fill="var(--soft)"/><circle cx="170" cy="86" r="11" fill="var(--accent)"/><circle cx="577" cy="383" r="17" fill="var(--accent)"/><path d="M95 390L114 390M104 380V400M584 106H617M600 90V122" stroke="currentColor" stroke-width="4"/>',
}

LABELS = {
 'ru': ('Главная','Материалы','О проекте','Вопросы','Вернуться на главную','Независимый иллюстративный проект. Не является сервисом для заказа услуг.'),
 'en': ('Home','Stories','About','Questions','Back to home','Independent illustrative editorial project. No customer services or transactions.'),
}


def _svg(spec):
    return (f'<svg class="illustration" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 470" role="img" aria-label="Original illustrated {h(spec.category)} study">'
            + ART[spec.mode] + '</svg>')


def _main_design(spec):
    cards=''.join(f'<article class="study"><span class="n">0{i+1}</span><h3>{h(t)}</h3><p>{h(text)}</p></article>' for i,(t,text) in enumerate(spec.cards))
    kpis=''.join(f'<li><strong>{h(k)}</strong><span>{h(v)}</span></li>' for k,v in spec.highlights)
    graphics=_svg(spec)
    intro=f'<div class="story"><p class="kicker">{h(spec.category)}</p><h1>{h(spec.headline)}</h1><p class="lead">{h(spec.description)}</p><a class="cta" href="journal.html">{h(LABELS[spec.language][1])}</a></div>'
    mode=spec.mode
    # Twelve distinct DOM compositions; do not turn the catalogue into 12 skins
    # of one identical hero+cards website.
    if mode=='docs':
        special='<pre class="code"><code>GET /v1/examples\n200 OK\n{ "status": "example", "items": [] }</code></pre>'
        return f'<section class="docs-layout"><aside class="toc"><p>REFERENCE</p><a href="journal.html">Validation</a><a href="about.html">Overview</a><a href="questions.html">FAQ</a></aside><div class="docs-content">{intro}{special}<div class="studies">{cards}</div></div></section>'
    if mode=='vinyl':
        return f'<section class="record-stage"><div class="record-art">{graphics}</div>{intro}</section><div class="marquee">SIDE A · SIDE B · NOTES ON LISTENING</div><section class="studies track-list">{cards}</section>'
    if mode=='gallery':
        return f'<section class="gallery-title">{intro}</section><div class="gallery-grid"><div class="gallery-image">{graphics}</div><div class="gallery-highlights"><ul>{kpis}</ul></div></div><section class="studies gallery-studies">{cards}</section>'
    if mode=='library':
        return f'<div class="library-top"><p>THE READING SHELF · 2026</p>{intro}</div><section class="library-plate">{graphics}<ol>{kpis}</ol></section><section class="studies shelf-cards">{cards}</section>'
    if mode=='kitchen':
        return f'<section class="kitchen-title"><span class="round-label">SEASON / СЕЗОН</span>{intro}</section><section class="kitchen-visual">{graphics}<ul>{kpis}</ul></section><section class="studies kitchen-studies">{cards}</section>'
    if mode=='hotel':
        return f'<section class="hotel-hero"><div class="hotel-poster">{graphics}</div>{intro}<p class="hotel-label">COAST / CULTURE / LIGHT</p></section><section class="hotel-details"><ul>{kpis}</ul></section><section class="studies hotel-studies">{cards}</section>'
    if mode=='botanical':
        return f'<section class="botanical-top"><div class="botanical-number">PLATE / 01</div><div class="botanical-art">{graphics}</div>{intro}</section><section class="botanical-entries"><ul>{kpis}</ul><div class="studies">{cards}</div></section>'
    if mode=='type':
        return f'<section class="type-head"><div class="giant">Aa</div>{intro}</section><div class="type-rule">ГАРНИТУРА · КЕГЛЬ · РИТМ · ПРОСТРАНСТВО</div><section class="studies type-studies">{cards}</section>'
    if mode=='celestial':
        return f'<section class="sky-hero"><div class="sky-art">{graphics}</div>{intro}</section><section class="sky-stats"><ul>{kpis}</ul></section><section class="studies sky-studies">{cards}</section>'
    if mode=='trail':
        return f'<section class="trail-hero">{intro}<div class="topo">{graphics}</div></section><section class="trail-notes"><ul>{kpis}</ul><div class="studies">{cards}</div></section>'
    if mode=='archive':
        return f'<section class="archive-masthead"><p>ДЕЛО № 117 · ГОРОДСКИЕ НАБЛЮДЕНИЯ</p>{intro}</section><div class="archive-sheet"><div class="archive-art">{graphics}</div><ul>{kpis}</ul></div><section class="studies archive-studies">{cards}</section>'
    return f'<section class="workshop-hero"><div class="workshop-art">{graphics}</div>{intro}</section><ul class="workshop-facts">{kpis}</ul><section class="studies workshop-studies">{cards}</section>'


def _css(spec):
    bg, ink, accent, soft, font = PALETTES[spec.mode]
    common=f'''/* Signature theme {spec.name}: original, no remote resources. */
:root{{--bg:{bg};--ink:{ink};--accent:{accent};--soft:{soft};--heading:{font}}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--ink);font:16px/1.65 system-ui,-apple-system,sans-serif}}
a{{color:inherit}}a:focus-visible,summary:focus-visible{{outline:3px solid var(--accent);outline-offset:4px}}svg{{max-width:100%;height:auto}}.wrap{{max-width:1700px;margin:auto}}
.skip{{position:absolute;left:-9999px;top:5px;background:var(--accent);color:var(--bg);z-index:100;padding:11px}}.skip:focus{{left:10px}}
.mast{{display:flex;justify-content:space-between;align-items:center;padding:25px clamp(16px,5vw,85px);border-bottom:1px solid var(--soft);gap:28px}}
.logo{{font:700 1.45rem var(--heading);text-decoration:none;letter-spacing:-.03em}}.brand-icon{{display:inline-grid;place-items:center;background:var(--accent);color:var(--bg);width:40px;height:40px;margin-right:13px;border-radius:8px}}
nav{{display:flex;gap:clamp(12px,2.8vw,35px);flex-wrap:wrap}}nav a{{font-size:.88rem;letter-spacing:.035em;text-decoration:none;font-weight:700}}nav a:hover{{text-decoration:underline;text-underline-offset:6px}}
h1,h2,h3{{font-family:var(--heading);line-height:1.08;letter-spacing:-.05em}}h1{{font-size:clamp(2.6rem,5.9vw,6.6rem);margin:18px 0 27px}}h2{{font-size:clamp(2.2rem,3.8vw,4rem)}}h3{{font-size:clamp(1.35rem,2vw,2rem);margin:15px 0}}
.kicker,.n{{font-weight:750;font-size:.79rem;text-transform:uppercase;letter-spacing:.19em;color:var(--accent)}}.lead{{font-size:clamp(1.06rem,1.5vw,1.28rem);max-width:58ch}}.cta{{display:inline-flex;border:1px solid var(--accent);padding:13px 25px;margin-top:25px;text-decoration:none;font-weight:700;letter-spacing:.02em;border-radius:99px}}.cta:hover{{background:var(--accent);color:var(--bg)}}
.studies{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px;margin:0 clamp(17px,5vw,85px) 85px}}
.study{{min-width:0;padding:28px;border-top:2px solid var(--accent)}}.study p{{max-width:68ch}}ul,ol{{padding-left:18px}}li{{margin-bottom:13px}}.illustration{{display:block;color:var(--ink);width:100%;height:auto;max-height:600px}}
.inner-intro{{padding:95px clamp(17px,9vw,150px) 55px;max-width:1190px}}.inner-body{{max-width:1250px;margin:auto;padding:0 clamp(17px,6vw,80px) 100px}}
.longread{{padding:25px 0 35px;border-top:1px solid var(--soft)}}.longread p{{font-size:1.075rem;max-width:78ch}}.body-lead{{font-size:1.18rem;max-width:75ch}}.qa{{padding:22px 0;border-top:1px solid var(--soft)}}.qa summary{{font-size:1.2rem;font-weight:700;cursor:pointer}}.qa p{{max-width:70ch}}.foot{{padding:32px clamp(17px,5vw,85px);border-top:1px solid var(--soft);display:flex;gap:22px;justify-content:space-between;flex-wrap:wrap;font-size:.86rem;opacity:.85}}
@media(max-width:780px){{.mast{{align-items:flex-start;flex-direction:column}}.studies{{grid-template-columns:1fr;margin:0 17px 48px}}.inner-intro{{padding:50px 17px 26px}}.inner-body{{padding:15px 17px 60px}}.illustration{{max-height:420px}}}}
@media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}}}
'''
    specific={
     'workshop':'.workshop-hero{display:grid;grid-template-columns:.95fr 1.05fr;align-items:center;padding:60px 7%;gap:7%}.workshop-art{border:12px solid var(--soft);padding:20px}.workshop-facts{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:25px 7% 85px;padding:0;list-style:none;border-top:1px solid var(--ink)}.workshop-facts li{padding-top:30px}.workshop-facts strong,.workshop-facts span{display:block}',
     'hotel':'.hotel-hero{position:relative;min-height:710px;display:grid;grid-template-columns:1.2fr .8fr;align-items:center;background:var(--soft)}.hotel-poster{grid-row:1;padding:30px 4% 30px 10%}.hotel-hero .story{grid-column:2;grid-row:1;padding:60px 10% 60px 4%}.hotel-label{position:absolute;left:6%;bottom:30px;letter-spacing:.24em;font-size:.75rem}.hotel-details ul{display:flex;justify-content:space-around;gap:20px;list-style:none;padding:35px}.hotel-details strong,.hotel-details span{display:block}',
     'docs':'.mode-docs{font-family:ui-monospace,monospace}.docs-layout{display:grid;grid-template-columns:260px 1fr;min-height:700px}.toc{background:var(--soft);padding:75px 30px;display:flex;flex-direction:column;gap:20px}.toc a{text-decoration:none}.docs-content{padding:65px 7%}.docs-content h1{font-size:clamp(2.5rem,4.9vw,5.8rem)}.code{padding:30px;border-left:5px solid var(--accent);overflow-x:auto;background:var(--soft);font-size:1rem}.docs-content .studies{margin:55px 0 0}',
     'gallery':'.gallery-title{padding:90px 10%;max-width:1200px}.gallery-grid{display:grid;grid-template-columns:1.6fr .4fr;gap:35px;align-items:center;padding:20px 7% 80px}.gallery-image{min-width:0;border:32px solid var(--soft);padding:20px}.gallery-highlights li{margin-bottom:50px}.gallery-highlights strong,.gallery-highlights span{display:block}.gallery-studies .study:nth-child(2n){margin-top:60px}',
     'kitchen':'.kitchen-title{text-align:center;padding:95px 15% 50px}.kitchen-title .lead{margin:auto}.round-label{border:1px solid var(--accent);border-radius:50%;padding:22px;font-size:.7rem;letter-spacing:.13em}.kitchen-visual{display:grid;grid-template-columns:1.5fr 1fr;align-items:center;gap:10%;padding:0 10% 90px}.kitchen-visual ul{list-style:none}.kitchen-visual li{padding:20px 0;border-bottom:1px solid var(--accent)}.kitchen-studies{grid-template-columns:repeat(4,1fr);gap:12px}',
     'botanical':'.botanical-top{display:grid;grid-template-columns:1fr 1fr;grid-template-areas:"art text";gap:8%;align-items:center;padding:40px 7% 80px}.botanical-number{position:absolute;margin-top:-20px;letter-spacing:.2em}.botanical-art{grid-area:art;padding:50px;border:10px double var(--accent)}.botanical-top .story{grid-area:text}.botanical-entries{display:grid;grid-template-columns:200px 1fr;padding:30px 6%}.botanical-entries ul{list-style:none;padding:0}.botanical-entries .studies{margin:0 0 50px}',
     'library':'.library-top{padding:80px 9% 40px}.library-top .story{max-width:1000px}.library-top .lead{max-width:800px}.library-plate{display:grid;grid-template-columns:1.5fr .5fr;gap:35px;align-items:center;background:var(--soft);padding:25px 7% 70px;margin-bottom:65px}.library-plate ol{list-style:upper-roman}.shelf-cards .study{border:1px solid var(--ink)}',
     'vinyl':'.mode-vinyl .mast{border-bottom:2px solid var(--accent)}.record-stage{display:grid;grid-template-columns:1fr 1fr;align-items:center;gap:5%;min-height:720px;padding:55px 6%}.record-art{max-width:770px;filter:drop-shadow(20px 20px 0 #343037)}.record-stage h1{font-weight:850;text-transform:uppercase}.marquee{white-space:normal;font-size:clamp(1.4rem,3.4vw,3rem);letter-spacing:.08em;border-top:2px solid var(--accent);border-bottom:2px solid var(--accent);text-align:center;padding:22px 0;margin-bottom:55px}.track-list .study{border-left:4px solid var(--accent);border-top:0}',
     'archive':'.archive-masthead{padding:45px 9%;border-bottom:5px double var(--ink)}.archive-masthead .story{max-width:1100px}.archive-sheet{display:grid;grid-template-columns:1fr 1fr;gap:60px;padding:75px 9%;align-items:center}.archive-art{border:1px solid var(--ink);padding:25px;transform:rotate(-2deg)}.archive-sheet ul{columns:1;list-style:none}.archive-studies .study{border-top:1px solid var(--ink)}',
     'trail':'.trail-hero{display:grid;grid-template-columns:.8fr 1.2fr;align-items:center;min-height:650px;gap:3%;padding:65px 7%}.topo{background:var(--soft);border-radius:30% 5% 30% 5%;padding:35px}.trail-notes{padding:35px 6%}.trail-notes ul{list-style:none;display:flex;gap:30px;justify-content:space-around;margin-bottom:70px}.trail-notes strong,.trail-notes span{display:block}.trail-notes .studies{margin:0 0 60px}',
     'type':'.type-head{padding:30px 8% 90px}.type-head .giant{font:bold clamp(12rem,35vw,33rem)/.9 Georgia,serif;letter-spacing:-.2em;color:var(--accent);opacity:.85}.type-head .story{max-width:1200px}.type-head h1{font-weight:900}.type-rule{font-size:clamp(.8rem,2.4vw,1.8rem);letter-spacing:.19em;padding:25px 8%;border-top:2px solid var(--ink);border-bottom:2px solid var(--ink);margin-bottom:65px}',
     'celestial':'.sky-hero{position:relative;display:grid;grid-template-columns:1.4fr .6fr;align-items:center;gap:1%;padding:55px 6%}.sky-art{padding:10px}.sky-hero .story{margin-left:-60px;z-index:1}.sky-stats{padding:20px 8% 70px}.sky-stats ul{display:flex;gap:65px;list-style:none;justify-content:center}.sky-stats strong,.sky-stats span{display:block}.sky-studies .study{border-top:1px dotted var(--accent)}',
    }[spec.mode]
    responsive='''@media(max-width:920px){.workshop-hero,.hotel-hero,.docs-layout,.gallery-grid,.kitchen-visual,.botanical-top,.botanical-entries,.library-plate,.record-stage,.archive-sheet,.trail-hero,.sky-hero{display:flex;flex-direction:column;gap:20px;padding:42px 5%;min-height:0}.hotel-hero .story{padding:20px}.kitchen-title,.gallery-title{padding:60px 7% 20px}.kitchen-studies{grid-template-columns:1fr 1fr}.toc{width:100%;padding:22px;flex-direction:row;flex-wrap:wrap}.docs-content{padding:28px 5%}.docs-content .studies{margin:30px 0}.botanical-art{order:1}.botanical-top .story{order:0}.sky-hero .story{margin:0}.trail-notes ul,.sky-stats ul,.workshop-facts{display:flex;flex-direction:column;gap:16px;padding:20px}.gallery-studies .study:nth-child(2n){margin-top:0}.type-head .giant{font-size:clamp(10rem,30vw,22rem)}}@media(max-width:600px){.kitchen-studies{grid-template-columns:1fr}.gallery-highlights li{margin-bottom:15px}.hotel-details ul{flex-direction:column}.mast{padding:18px}.logo{font-size:1.1rem}}'''
    return (common+specific+'\n'+responsive+'\n').encode('utf-8')


def _shell(spec, heading, body, *, home=False, description=None):
    labels=LABELS[spec.language]
    descr=h(description or spec.description)
    nav=''.join(f'<a href="{p}">{h(l)}</a>' for p,l in zip(('index.html','journal.html','about.html','questions.html'),labels[:4]))
    top=f'''<!doctype html><html lang="{h(spec.language)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="{descr}"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'">
<title>{h(spec.title)} — {h(heading)}</title><link rel="stylesheet" href="style.css"><link rel="icon" href="favicon.svg" type="image/svg+xml"></head>
<body class="mode-{spec.mode} layout-signature-{spec.mode}"><div class="wrap"><a class="skip" href="#main">{h(labels[4])}</a><header class="mast"><a class="logo" href="index.html"><span class="brand-icon" aria-hidden="true">{h(spec.emblem)}</span>{h(spec.title)}</a><nav aria-label="Site navigation">{nav}</nav></header><main id="main">'''
    if not home:
        body=f'<section class="inner-intro"><p class="kicker">{h(spec.category)}</p><h1>{h(heading)}</h1><p class="body-lead">{descr}</p></section><div class="inner-body">{body}</div>'
    return (top+body+f'</main><footer class="foot"><span>{h(spec.title)} · 2026</span><span>{h(labels[5])}</span><a href="sitemap.xml">Sitemap</a></footer></div></body></html>\n').encode('utf-8')


def render_signature(name, domain):
    if name not in SIGNATURES:
        raise ValueError('unknown signature site')
    spec=SIGNATURES[name]
    names=LABELS[spec.language]
    articles=''.join('<article class="longread"><p class="kicker">0'+str(i+1)+'</p><h2>'+h(t)+'</h2><p>'+h(text)+'</p></article>' for i,(t,text) in enumerate(spec.cards))
    about=f'<article class="longread"><h2>{h(spec.headline)}</h2><p>{h(spec.intro)}</p><p>{h(spec.description)}</p><p>{h(names[5])}</p></article>' + ''.join(f'<div class="longread"><h3>{h(k)}</h3><p>{h(v)}</p></div>' for k,v in spec.highlights)
    questions=''.join(f'<details class="qa"><summary>{h(q)}</summary><p>{h(a)}</p></details>' for q,a in spec.questions)
    home=_shell(spec,spec.headline,_main_design(spec),home=True)
    favicon=(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect x="0" y="0" width="64" height="64" rx="15" fill="{PALETTES[spec.mode][2]}"/><text x="32" y="42" text-anchor="middle" font-family="sans-serif" font-size="25" fill="white">{h(spec.emblem)}</text></svg>\n').encode('utf-8')
    return {
        'index.html':home,
        'journal.html':_shell(spec,names[1],articles,description=spec.intro),
        'about.html':_shell(spec,names[2],about,description=spec.description),
        'questions.html':_shell(spec,names[3],questions,description=spec.description),
        '404.html':_shell(spec, 'Страница не найдена' if spec.language=='ru' else 'Page not found',f'<p>{h(names[4])}</p><p><a class="cta" href="index.html">{h(names[4])}</a></p>',description=spec.description),
        'style.css':_css(spec), 'favicon.svg':favicon,
        'robots.txt':f'User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n'.encode('ascii'),
        'sitemap.xml': ('<?xml version="1.0" encoding="utf-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(f'<url><loc>https://{domain}/{page}</loc></url>' for page in ('','journal.html','about.html','questions.html'))+'</urlset>\n').encode('utf-8'),
    }
