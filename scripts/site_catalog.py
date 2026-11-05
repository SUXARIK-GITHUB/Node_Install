#!/usr/bin/env python3
"""Curated independent static-site catalog for the staging selfsteal workflow.

96 original generator themes and 12 separate signature-design sites.
No scripts, external images, third-party endpoints, cookies, fake testimonials or
interactive forms. Only deterministic self-contained HTML, CSS and SVG.

This file is NOT executed automatically by install.sh. A site is served only
when explicitly selected with the existing staging deployment mechanism.
"""
from dataclasses import dataclass
import argparse
import hashlib
import html
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET
try:
    from signature_sites import SIGNATURES, render_signature
except ImportError:
    from scripts.signature_sites import SIGNATURES, render_signature

ROOT = Path(__file__).resolve().parents[1]
SITES = ROOT / 'site-catalog'
DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
PAGES = ('journal.html', 'about.html', 'questions.html')

# name | publication | category | lead statement | editorial description |
# four DISTINCT article topics | language | visual family | emblem.
# The material is fictional original editorial/demo material, not a real firm.
DATA = '''
13-cloud-ledger|Northbound Cloud|Technology|Infrastructure without the noise|Field notes on architecture, dependable infrastructure and thoughtful cloud operations|Reliability budget;Immutable releases;Regions and latency;Recovery drills|en|terminal|◇
14-edge-metrics|Edge Metrics|Technology|Observe the edge, understand the system|An illustrated technical notebook about requests, latency and operational telemetry|Tracing a request;Latency distributions;Quiet dashboards;Useful alerts|en|dashboard|◈
15-code-library|Библиотека кода|Технологии|Разработка как ремесло|Независимые заметки о читаемом коде, тестировании и сопровождении небольших систем|Чистый интерфейс;Полезные тесты;Границы модулей;Релизы без спешки|ru|terminal|⌘
16-data-vault|Cold Archive|Technology|Memory needs a recovery plan|An independent journal about backups, restoration and data integrity|A readable backup;Restoration day;Checksums in practice;Versioned archives|en|editorial|▤
17-aperture-docs|Aperture Docs|Technology|A clearer place for knowledge|A static documentation studio collecting short guides for technical projects|Documentation maps;API examples;Release notes;Accessible navigation|en|documentation|⌁
18-api-foundry|Interface Foundry|Technology|Small APIs, strong contracts|Original articles about designing straightforward interfaces and predictable responses|Request validation;Useful errors;Versioned endpoints;Idempotent calls|en|documentation|{ }
19-observation-lab|Лаборатория наблюдений|Технологии|Что видно по метрикам|Практические заметки о наблюдаемости, измерениях и понятных технических отчётах|Латентность и хвосты;Ошибки по классам;Пороговые значения;Сравнение измерений|ru|dashboard|◉
20-type-system|Линия интерфейса|Дизайн систем|Понятные цифровые инструменты|Заметки о типографике, дизайн-токенах и повторно используемых элементах интерфейса|Размер и ритм;Контраст текста;Состояния кнопок;Набор компонентов|ru|modern|◫
21-satellite-atlas|Signal Atlas|Science|Maps made from patient observation|A visual digest of satellite imagery, geospatial conventions and remote sensing|Reading a raster;Cloud coverage;Ground sampling;Map projections|en|research|✧
22-circuit-notes|Схема дня|Технологии|Электроника без лишних слов|Иллюстрированные материалы о простых электронных узлах и культуре макетирования|Дорожки платы;Работа с датчиком;Защита питания;Прототип на столе|ru|workshop|⌁
23-linen-studio|Льняная линия|Предметный дизайн|Материя, свет и привычки|Журнал о натуральных тканях, композиции и бережном отношении к вещам|Тактильность льна;Цвет натуральной нити;Плотность плетения;Вещь на каждый день|ru|editorial|❋
24-print-house|Типография север|Графический дизайн|Бумага задаёт настроение|Независимый каталог идей о печатной графике, бумаге и малых изданиях|Выбор бумаги;Монохромная печать;Поля и ритм;Тираж как эксперимент|ru|magazine|▦
25-clay-table|Стол керамиста|Ремесло|След руки на поверхности|Редакционные заметки о декоративной керамике, глазурях и ручной работе|Следы инструмента;Сушка формы;Палитра глазури;Простая тарелка|ru|workshop|◒
26-gallery-light|Light Room|Art|Shape the space with light|A gallery-like visual study of light, contrast and spatial compositions|Daylight studies;Gentle shadows;Surface detail;Framing a room|en|gallery|✳
27-architecture-folio|Модуль и масштаб|Архитектура|Пространство начинается с человека|Иллюстрированный сборник заметок о пропорциях, материалах и городском пространстве|Форма двора;Ритм фасада;Материал стен;Пропорции комнаты|ru|architecture|▱
28-typography-press|Шрифтовой лист|Типографика|Буква как архитектура|Мини-журнал о знаках, наборе текста и визуальной культуре чтения|Контраст гарнитуры;Длинная строка;Точки и паузы;Плакат без изображения|ru|magazine|Aa
29-oak-furniture|Тихое дерево|Мебель и интерьер|Простые вещи служат долго|Наблюдения о соединениях, древесине и рациональном предметном дизайне|Древесный рисунок;Шип и паз;Гладкая кромка;Ремонт и уход|ru|workshop|⌂
30-fragrance-index|Атлас ароматов|Ароматы|Память, собранная в нотах|Редакционные заметки о природе запахов, ботанике и культурных ассоциациях|Цитрусовый старт;Древесная база;Сезонные травы;Аромат и пространство|ru|luxury|❀
31-textile-library|Ткацкий архив|Текстиль|Истории, рассказанные нитями|Небольшой визуальный каталог узоров, традиций и способов работать с тканью|Узор на полотне;Натуральные красители;Тактильная фактура;Сохранение текстиля|ru|editorial|▥
32-visual-studio|Fourth Form|Design|Objects, systems and quiet ideas|A fictional independent creative journal with original design sketches and process notes|Color relationships;A useful grid;Prototype studies;Small exhibitions|en|modern|◆
33-coffee-roastery|Утро зерна|Кофейная культура|Вкус складывается из деталей|Справочный журнал о кофейном зерне, обжарке и домашних способах приготовления|Зёрна и регион;Температура воды;Мелкий или крупный помол;Разные способы заварки|ru|cafe|☕
34-slow-bakery|Тёплая корка|Домашняя выпечка|Тесто любит внимание|Редакционные заметки о хлебе, закваске и повседневной кухонной практике|Длинная ферментация;Вода и мука;Хрустящая корка;Остывание хлеба|ru|cafe|◕
35-citrus-studio|Цедра и вкус|Кулинария|Яркость в одной детали|Иллюстрированный блокнот о сезонных фруктах, кислых акцентах и простых блюдах|Цедра в выпечке;Кислое и сладкое;Цвет цитрусов;Аромат свежего сока|ru|food|◌
36-tea-library|Чайный зал|Чай и традиции|Лист раскрывается постепенно|Независимый гид по видам чая, посуде и спокойным ритуалам приготовления|Температура настоя;Форма чайника;Первый аромат;Время заваривания|ru|luxury|❖
37-olive-table|Зелёный стол|Сезонная кухня|Вкус в привычных продуктах|Небольшой журнал о маслах, овощах и сезонных домашних сочетаниях|Оливковое масло;Зелёные травы;Печёные овощи;Новая текстура|ru|food|❧
38-cocoa-atelier|Какао и форма|Кондитерское искусство|Десерт как маленький объект|Иллюстративные материалы о какао, шоколаде и сдержанной подаче десертов|Путь какао-боба;Текстура ганаша;Горечь и сладость;Геометрия плитки|ru|luxury|◈
39-fermentation-notes|Живая культура|Ферментация|Время меняет вкус|Справочный блокнот о пищевых культурах, чистоте процессов и наблюдении за изменениями|Время и температура;Кислотность;Чистая тара;Записи процесса|ru|research|✿
40-vineyard-journal|Виноградная карта|Виноградарство|Сезон на ладони|Редакционные заметки о виноградной лозе, климате и ландшафте виноградников|Форма грозди;Почвы и склоны;Уход за лозой;Сезон сбора|ru|editorial|♧
41-rooftop-garden|Городской огород|Городская экология|Немного зелени над улицей|Наблюдения о зелёных крышах, контейнерном садоводстве и световом режиме|Почва в контейнере;Вода на крыше;Городской ветер;Ритм посадок|ru|nature|❋
42-spice-atlas|Карта специй|Пряности|Новый вкус знакомой кухни|Иллюстрированная библиотека о происхождении специй и культуре их сочетания|Кардамон и тепло;Перец и аромат;Мягкие смеси;Хранение пряностей|ru|food|✣
43-island-guide|Островной журнал|Путешествия|Там, где суша встречает море|Авторские тексты о медленных поездках, береговой географии и островной культуре|Пешеходная тропа;Тихая бухта;Местная карта;Свет на причале|ru|coastal|≈
44-mountain-trails|Высотные тропы|Горы|Маршрут начинается с подготовки|Справочные материалы о горных прогулках, изменении погоды и чтении рельефа|Высотные отметки;Ветер на перевале;План маршрута;Безопасная дистанция|ru|nature|△
45-urban-walks|Город пешком|Городские прогулки|Замечать улицы иначе|Заметки о пешеходных маршрутах, городской среде и незаметных деталях фасадов|Арка во дворе;Схема квартала;Смена вывесок;Свет на перекрёстке|ru|architecture|⌖
46-railway-journal|Маршрут поезда|Железнодорожные путешествия|Впереди новая станция|Иллюстрированный журнал о путешествиях по железной дороге, окнах и городах|Вокзал как площадь;Вид из окна;Ритм пути;Путевой блокнот|ru|magazine|⇄
47-coastal-science|Прибрежные исследования|Морская экология|Наблюдать берег бережно|Популярные материалы о волнении моря, береговых формах и природных изменениях|Приливная зона;Песок и волна;Морские птицы;Следы шторма|ru|coastal|≋
48-stargazing-club|Night Sky Notes|Astronomy|Look up, write it down|A visual journal for amateur skywatchers and patient nighttime observation|Moon sketches;A sky map;Darkness and light;Observing seasons|en|research|✦
49-forest-class|Лесная школа|Природа|Учиться видеть живое|Небольшой ботанический и природоведческий журнал о прогулках без вреда для леса|Следы животных;Грибы на древесине;Мхи и влажность;Листья осенью|ru|nature|♣
50-sailing-guide|Windward Journal|Sailing|A notebook shaped by the wind|Editorial guides to coastal navigation, knots and careful voyage planning|Reading the wind;Chart basics;A simple knot;Weather windows|en|coastal|⚑
51-birdwatch|Птичий календарь|Орнитология|Небо рядом с домом|Наблюдения о городских птицах, сезонных миграциях и звуках на рассвете|Силуэт птицы;Голоса утром;Зимняя кормушка;Тихое наблюдение|ru|nature|❋
52-lake-stories|Озёрные истории|Водоёмы|Отражение меняется каждый час|Авторские заметки о пресных водоёмах, камышах и наблюдении за поверхностью воды|Рябь от ветра;Растения у берега;Озеро зимой;Карта глубин|ru|coastal|◒
53-vinyl-label|Сторона А|Музыкальная культура|У музыки есть поверхность|Редакционный журнал о виниловых пластинках, оформлении обложек и культуре слушания|Обложка альбома;Чистая игла;Звук комнаты;Последняя дорожка|ru|gallery|♫
54-short-film|Малый экран|Короткий метр|История умещается в кадре|Авторские наблюдения о коротком кино, монтаже и минимальном визуальном рассказе|Ритм монтажа;Свет в кадре;Крупный план;Тишина после титров|ru|gallery|▣
55-poetry-room|Комната стихов|Поэзия|Пауза между строк|Небольшое независимое издание о ритме речи, поэтических образах и чтении вслух|Белое пространство;Строка и дыхание;Городской образ;Слова на слух|ru|editorial|❞
56-museum-index|Кабинет экспоната|История и музей|Вещь как свидетель времени|Справочная подборка о каталогах коллекций, сохранении предметов и музейных этикетках|Описание предмета;Хранение бумаги;Форма каталога;История витрины|ru|museum|▤
57-photography-archive|Frame Archive|Photography|Every image carries context|An independent photo essay journal about composition, contact sheets and visual memory|Contact sheets;Quiet portraits;Light direction;Archiving negatives|en|gallery|▧
58-book-society|Клуб на полке|Книжное сообщество|Читать вместе, думать отдельно|Редакционные заметки о читательских встречах, эссе и литературных наблюдениях|Обсуждение главы;Книжная закладка;Тема месяца;Читательский дневник|ru|editorial|✎
59-audio-stories|Звуковая полка|Звуковые истории|У каждого места своё звучание|Тематические тексты о полевых записях, слуховом внимании и звуковых ландшафтах|Городское утро;Шум дождя;Запись шагов;Пространство и эхо|ru|modern|◉
60-stage-notes|За кулисами|Театр|Сцена начинается до реплики|Иллюстрированный журнал о сценографии, сценическом свете и культуре репетиций|План сцены;Работа со светом;Предмет на сцене;Ритм репетиции|ru|museum|◇
61-history-pages|Документ эпохи|Исторические заметки|Прошлое хранится в мелочах|Небольшой редакционный архив о старых документах, письмах и повседневной истории|Печать на письме;Городская открытка;Домашняя хроника;Даты на полях|ru|museum|✥
62-vintage-objects|Старая вещь|Предметная культура|Время оставляет фактуру|Журнал о восстановлении бытовых вещей, их истории и бережном использовании|Металл и патина;Заводская маркировка;Форма ручки;Следы ремонта|ru|workshop|⌑
63-editorial-desk|Редакторский стол|Редакторские практики|Хорошая история ясна читателю|Заметки о создании текстов, проверке источников и структуре небольшого издания|План материала;Честный заголовок;Работа с фактом;Редакторский календарь|ru|magazine|¶
64-civic-guide|Городские правила|Гражданская грамотность|Сложное объясняется простыми словами|Образовательный проект о документах, обращениях и понятном языке официальной переписки|Как читать документ;Проверка источника;Структура обращения;Словарь терминов|ru|documentation|§
65-library-project|Общественная библиотека|Библиотечное дело|Знания должны быть доступны|Редакционные заметки о библиотечных пространствах, каталогизации и доступной навигации|Организация полок;Понятная карточка;Тихая зона;Книги для всех|ru|museum|▦
66-learning-studio|Мастерская знаний|Образование|Новые навыки строятся постепенно|Справочные материалы о самостоятельном обучении, заметках и практических упражнениях|План на неделю;Проверка понимания;Конспект без лишнего;Учимся на примере|ru|modern|✳
67-project-maps|Карты проектов|Управление проектами|План помогает видеть решение|Практические заметки о задачах, рисках и понятной организации небольшой команды|План этапов;Критерии готовности;Зависимости задач;Простая ретроспектива|ru|dashboard|▰
68-shipments-notes|Логистика вещей|Логистика|У каждого маршрута есть детали|Небольшой независимый справочник о складах, упаковке и перемещении товаров|Маркировка коробки;Схема склада;Планирование пути;Упаковка без отходов|ru|architecture|↗
69-ecology-brief|Зелёные заметки|Экология|Большое начинается с наблюдения|Популярные материалы о городской среде, ресурсах и устойчивых бытовых привычках|Учёт отходов;Вода в доме;Повторное использование;Зелёный двор|ru|nature|♧
70-weather-lab|Климатический блокнот|Метеорология|Погоду лучше понимать, чем угадывать|Иллюстрированные объяснения погодных явлений и наблюдений без прогнозов в реальном времени|Воздушный фронт;Ветер у берега;Типы облаков;Температурный график|ru|research|☼
71-energy-notes|Энергия дома|Энергосбережение|Потребление можно понять|Образовательные материалы о бытовой энергии, теплопотерях и полезных измерениях|Теплоизоляция;Счётчик энергии;Светодиодный свет;План измерений|ru|dashboard|⚡
72-workshop-careers|Путь профессии|Карьера и навыки|Практика делает навыки видимыми|Редакционная серия об обучении, портфолио и понятной оценке собственных проектов|История проекта;Навык на практике;Обратная связь;План развития|ru|modern|✦
73-quiet-storage|Quiet Storage|Technology|Trust the restore, not the checkbox|A compact technical journal about storage, backup design and verification practice|Backup rotation;Cold storage;Recovery points;Hash verification|en|terminal|⬡
74-network-patterns|Сетевая азбука|Сетевые технологии|Сеть становится понятнее с наблюдением|Оригинальные справочные статьи о пакетах, задержке, маршрутизации и границах сетевых систем|Жизнь TCP-пакета;Маршрут без загадок;Задержка и джиттер;Проверка MTU|ru|documentation|⌁
75-digital-safety|Цифровая гигиена|Безопасность|Простые привычки помогают защите|Образовательный журнал о надёжных паролях, обновлениях и защите личных данных|Длинный пароль;Резервные коды;Обновления ПО;Приватность браузера|ru|dashboard|⊛
76-source-control|Commit Journal|Technology|Build a story of changes|Independent notes on version control, maintainable projects and thoughtful code review|Clear history;Review notes;Tagged releases;Reliable branches|en|terminal|⌘
77-data-visualization|Данные в форме|Аналитика|График должен объяснять, а не украшать|Редакционные заметки о понятных диаграммах, источниках и честном масштабе данных|Ось и масштаб;Выбор диаграммы;Подписи и контекст;Проверка источников|ru|dashboard|▥
78-open-standards|Open Methods|Technology|Interfaces worth documenting|A visual notebook about interoperability, clear specifications and open technical formats|Useful schemas;Version compatibility;Readable formats;Reference examples|en|documentation|⚙
79-glass-workshop|Прозрачная форма|Художественное стекло|Свет меняет восприятие предмета|Тематические заметки о прозрачных материалах, отражениях и простых формах|Преломление света;Кромка изделия;Цветное стекло;Форма в интерьере|ru|gallery|◇
80-botanical-scent|Травяной кабинет|Ботаника и ароматы|Аромат начинается с растения|Справочный журнал о пахучих травах, листьях и культурных ассоциациях запаха|Мята в саду;Лаванда и сезон;Сушка листьев;Составление гербария|ru|nature|❀
81-poster-gallery|Poster Study|Graphic Design|A strong image can be simple|An independent collection of typographic posters, spacing experiments and color studies|Bold hierarchy;A two-color poster;Letter spacing;Printed texture|en|gallery|▧
82-light-atelier|Световая мастерская|Световой дизайн|Тени делают пространство живым|Заметки о естественном освещении, рассеивании и композиции предметов|Тёплый вечер;Отражённый луч;Теневая граница;Белая поверхность|ru|architecture|☼
83-bookbinding|Переплётная|Книжное ремесло|Корешок хранит историю книги|Иллюстрированный журнал о бумаге, нитях и традициях переплёта|Бумажная тетрадь;Склейка корешка;Тканевая обложка;Бережный ремонт|ru|workshop|▤
84-product-sketch|Чертёж вещи|Промышленный дизайн|Прототип помогает проверить идею|Редакционный каталог о набросках, макетах и оценке удобства предмета|Первый эскиз;Габариты изделия;Проверка хватки;Сборка модели|ru|modern|✎
85-bread-journal|Daily Loaf|Food|Every dough has a rhythm|A small home baking journal about ingredients, proofing and practical observation|Flour and hydration;A patient dough;Steam and crust;The cooling rack|en|cafe|◕
86-herbal-tea|Листовой чай|Травяные напитки|Чашка сезонных растений|Оригинальные заметки о травах, безопасном хранении и культуре домашних напитков|Липовый цвет;Мята и аромат;Сушка сырья;Температура воды|ru|nature|❧
87-gelato-notes|Little Gelato|Food|Texture makes the memory|An illustrated editorial notebook about frozen desserts, fruit and thoughtful preparation|Fruit and ice;Creamy balance;A simple cone;Seasonal flavor|en|food|◌
88-small-bistro|Тихое бистро|Гастрономия|Меню начинается с сезона|Журнал о повседневной кухне, небольших меню и сочетании местных продуктов|Овощи на столе;Суп дня;Лёгкий гарнир;Подача без спешки|ru|cafe|✣
89-culinary-archive|Рецептная картотека|История еды|Память иногда пахнет выпечкой|Редакционные истории о домашних кулинарных тетрадях и традиционных техниках|Записная книга;Мера на глаз;Семейный рецепт;Сезонная заготовка|ru|editorial|▦
90-beekeeping-notes|Пчелиный календарь|Пчеловодство|Внимание к маленькому миру|Популярные наблюдения о медоносных растениях, сезонах и жизни пчёл|Весенний лёт;Цветение липы;Танец пчелы;Зимний покой|ru|nature|⬡
91-bike-trails|Веломаршрут|Велопрогулки|Дорога лучше в своём темпе|Иллюстрированные заметки о городских и загородных велопрогулках|Подготовка велосипеда;Безопасный поворот;Карта покрытия;Остановка у реки|ru|coastal|↗
92-coastal-cities|Морские города|Городская география|Город отражается в воде|Редакционный атлас причалов, набережных и городской жизни у моря|Линия причала;Старый маяк;Карта залива;Окна на море|ru|architecture|⚓
93-nordic-cabins|Cabin Atlas|Travel|Simple shelter, wider landscape|An illustrated journal about modest cabins, outdoor materials and quiet nature|A timber roof;Morning frost;A warm interior;Paths through pine|en|nature|⌂
94-mountain-weather|Погода перевала|Метеорология гор|Небо меняется быстрее карты|Справочные заметки о ветре, облаках и безопасном чтении погоды в горах|Облака на хребте;Ветер у седловины;Дневной прогрев;План на случай грозы|ru|research|△
95-maritime-maps|Sea Chart Notes|Sailing|A coast is made of detail|A visual notebook about maritime chart symbols, coastal routes and patient navigation|Soundings and depth;Reading a buoy;The harbor plan;A compass line|en|coastal|⌖
96-garden-paths|Садовые дорожки|Ландшафт|Сад открывается медленному шагу|Авторские наблюдения о небольших садах, растениях и связности пространств|Маршрут во дворе;Тень от дерева;Камень и трава;План цветника|ru|nature|❋
97-design-museum|Form Museum|Culture|A collection of everyday decisions|An independent exhibition-style site about design history, objects and ways of seeing|Objects as evidence;Typography in time;Material samples;A small catalogue|en|museum|◆
98-film-reels|Кинолента|История кино|У каждого плана свой ритм|Иллюстрированные заметки о монтаже, плёнке и визуальной памяти кино|Первая катушка;Звук за кадром;Переход между сценами;Последний стоп-кадр|ru|gallery|▣
99-analog-camera|Плёночный кадр|Фотография|Свет оставляет след|Справочные материалы о плёночной фотографии, экспозиции и хранении негативов|Выдержка и свет;Плёнка и зерно;Контактный лист;Архив негативов|ru|editorial|◉
100-piano-notes|Piano Room|Music|Every pause belongs to the phrase|An independent music education notebook about rhythm, listening and keyboard technique|A quiet scale;Listening to resonance;Hands and posture;A patient practice|en|luxury|♫
101-zine-press|Самиздат и форма|Малые издания|Лист бумаги может стать журналом|Редакционный журнал о независимой печати, зинах и ручной вёрстке|Четыре разворота;Печатный коллаж;Тираж дома;Обложка из бумаги|ru|magazine|✎
102-folklore-notes|Устные истории|Фольклор|Голоса сохраняют память|Образовательные материалы о сказках, устной традиции и бережной записи рассказов|Структура сказки;Повтор и ритм;Региональные образы;Запись рассказа|ru|museum|❞
103-makers-school|Школа мастерства|Ремесленное образование|Навык растёт через повторение|Справочный мини-сайт об освоении ручных техник и ведении рабочего дневника|Первый инструмент;Порядок мастерской;Работа по образцу;Безопасная практика|ru|workshop|⚒
104-typography-school|Type Workshop|Learning|Readability is a design choice|An independent teaching notebook about typography, layout and accessible text|Line length;Hierarchy and scale;Pairing type;Reading on mobile|en|documentation|Aa
105-city-planning|План квартала|Городская среда|Хорошее пространство работает для всех|Редакционные материалы о доступной городской среде и внимании к деталям улиц|Пешеходный переход;Ширина тротуара;Зелёный карман;Навигация района|ru|architecture|▱
106-material-science|Материаловедческий лист|Материалы|Свойства важнее названия|Популярные технические заметки о структуре материалов и методах их сравнения|Твёрдость и износ;Влага и древесина;Металл и тепло;Текстура композита|ru|research|◈
107-astronomy-reference|Celestial Index|Science|Measure the night carefully|An independent primer on sky maps, observation notes and everyday astronomy|A star chart;The lunar cycle;Light pollution;Simple observation logs|en|research|✧
108-volunteer-journal|Дела рядом|Городские инициативы|Маленькие действия имеют значение|Редакционные заметки об организации полезных городских инициатив и взаимной помощи|План встречи;Бережная сортировка;Понятное объявление;Отчёт без лишнего|ru|modern|♧
'''


@dataclass(frozen=True)
class Theme:
    name: str
    title: str
    category: str
    headline: str
    description: str
    subjects: tuple[str, str, str, str]
    language: str
    layout: str
    emblem: str


def _parse():
    entries = {}
    for row in DATA.strip().splitlines():
        parts = row.strip().split('|')
        if len(parts) != 9:
            raise ValueError('invalid catalog data row')
        name, title, category, headline, description, subjects, lang, layout, emblem = parts
        items = tuple(subjects.split(';'))
        if len(items) != 4 or not name.isascii() or name in entries:
            raise ValueError('invalid or duplicate catalog name')
        if lang not in ('ru', 'en') or layout not in {
            'terminal', 'dashboard', 'documentation', 'editorial', 'modern',
            'research', 'workshop', 'magazine', 'gallery', 'architecture',
            'luxury', 'cafe', 'food', 'nature', 'coastal', 'museum'}:
            raise ValueError('invalid theme flags')
        entries[name] = Theme(name, title, category, headline, description,
                              items, lang, layout, emblem)
    return entries


THEMES = _parse()
BASE_NAMES = tuple(THEMES)
if len(BASE_NAMES) != 96:
    raise RuntimeError('r21 catalog cardinality mismatch')
for name, signature in SIGNATURES.items():
    if name in THEMES:
        raise RuntimeError('duplicate signature theme')
    THEMES[name] = Theme(name, signature.title, signature.category,
                         signature.headline, signature.description,
                         tuple(item[0] for item in signature.cards),
                         signature.language, 'signature-' + signature.mode,
                         signature.emblem)
NAMES = tuple(THEMES)
if len(NAMES) != 108:
    raise RuntimeError('r22 catalog cardinality mismatch')


def valid_domain(domain):
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain) or re.fullmatch(r'[0-9.]+', domain):
        raise ValueError('invalid public domain')
    return domain


def e(value):
    return html.escape(value, quote=True)


def ui(theme):
    return ({'home': 'Главная', 'journal': 'Материалы', 'about': 'О проекте',
             'questions': 'Вопросы', 'latest': 'В этом выпуске', 'more': 'Открыть материалы',
             'description': 'Редакционные заметки', 'read': 'Подробнее',
             'independent': 'Независимый редакционный проект. Содержимое носит ознакомительный характер.',
             'not_a_service': 'Это авторский справочный макет, а не коммерческая услуга. Мы не запрашиваем данные пользователей.',
             'privacy': 'Здесь нет регистрации, внешних сценариев и сторонней аналитики.',
             'how': 'Как устроены материалы?', 'how_answer': 'Все страницы содержат локальные тексты и иллюстрации; темы сгруппированы по разделам.',
             'data': 'Собираются ли данные посетителей?', 'data_answer': 'Форм, личных кабинетов и пользовательских трекеров здесь нет.',
             'fresh': 'Есть ли актуальные данные?', 'fresh_answer': 'Это статический редакционный каталог; динамические сведения не публикуются.',
             'back': 'Вернуться на главную', 'sitemap': 'Карта сайта', 'not_found': 'Страница не найдена'}
            if theme.language == 'ru' else
            {'home': 'Home', 'journal': 'Stories', 'about': 'About',
             'questions': 'Questions', 'latest': 'In this issue', 'more': 'Explore stories',
             'description': 'Independent editorial notes', 'read': 'Discover more',
             'independent': 'An independent editorial project with original illustrative content.',
             'not_a_service': 'This is a small editorial demonstration, not a commercial service. No customer details are requested.',
             'privacy': 'No sign-in, external scripts or third-party analytics.',
             'how': 'How are articles organized?', 'how_answer': 'The static editorial pages group original notes by topic and theme.',
             'data': 'Do you track visitors?', 'data_answer': 'There are no forms, user accounts or analytics scripts.',
             'fresh': 'Is this real-time information?', 'fresh_answer': 'This is a static editorial collection, not a live data feed.',
             'back': 'Back to home', 'sitemap': 'Sitemap', 'not_found': 'Page not found'})


def art(theme):
    """Self-contained vector art with substantially different family silhouettes."""
    seed = hashlib.sha256(theme.name.encode('ascii')).digest()
    sx = 45 + seed[0] % 40
    # Numeric values only; no external image or URL references.
    grid = ''.join(f'<line x1="{v}" y1="0" x2="{v}" y2="470" stroke="currentColor" opacity=".07"/>' for v in range(70, 700, 65))
    base = {
      'terminal': '<rect x="95" y="66" width="560" height="340" rx="22" fill="var(--art-light)" stroke="currentColor" stroke-width="3"/><circle cx="135" cy="105" r="9" fill="var(--highlight)"/><path d="M135 166L190 208L135 250M220 251H375M220 292H510M220 332H460" fill="none" stroke="currentColor" stroke-width="12" stroke-linecap="round"/>',
      'dashboard': '<rect x="80" y="70" width="570" height="330" rx="20" fill="var(--art-light)"/><path d="M120 319L220 259L320 288L405 155L525 197L607 103" stroke="var(--highlight)" stroke-width="18" fill="none" stroke-linejoin="round"/><path d="M120 365H607M120 117H300" stroke="currentColor" opacity=".4" stroke-width="5"/>',
      'documentation': '<path d="M130 72H575V419H130Z" fill="var(--art-light)"/><path d="M174 139H540M174 201H365M174 258H535M174 302H500M174 348H412" stroke="currentColor" stroke-width="12" stroke-linecap="round"/><path d="M150 93V392" stroke="var(--highlight)" stroke-width="13"/>',
      'editorial': '<circle cx="376" cy="235" r="195" fill="var(--art-light)"/><path d="M180 329L374 70L571 334" fill="none" stroke="var(--highlight)" stroke-width="29"/><path d="M237 384H516M287 106V360" stroke="currentColor" stroke-width="5"/>',
      'modern': '<rect x="100" y="85" width="250" height="250" rx="45" fill="var(--highlight)"/><circle cx="487" cy="227" r="145" fill="var(--art-light)"/><path d="M130 381H628M365 66V407" stroke="currentColor" stroke-width="8"/>',
      'research': '<circle cx="369" cy="229" r="160" fill="none" stroke="var(--highlight)" stroke-width="19"/><ellipse cx="369" cy="229" rx="272" ry="81" fill="none" stroke="currentColor" stroke-width="7" transform="rotate(-24 369 229)"/><circle cx="369" cy="229" r="77" fill="var(--art-light)"/><circle cx="156" cy="348" r="18" fill="var(--highlight)"/>',
      'workshop': '<path d="M110 332L300 77L558 285L365 441Z" fill="var(--art-light)" stroke="currentColor" stroke-width="8"/><circle cx="353" cy="280" r="106" fill="none" stroke="var(--highlight)" stroke-width="33"/><circle cx="353" cy="280" r="26" fill="currentColor"/>',
      'magazine': '<rect x="151" y="40" width="470" height="390" fill="var(--art-light)" transform="rotate(8 380 225)"/><path d="M150 95H520M150 165H485M150 240H550M150 314H450" stroke="currentColor" stroke-width="12"/><circle cx="493" cy="311" r="83" fill="var(--highlight)"/>',
      'gallery': '<circle cx="366" cy="218" r="170" fill="var(--highlight)"/><path d="M108 381L580 90M160 93L590 372" stroke="var(--art-light)" stroke-width="24"/><circle cx="370" cy="219" r="72" fill="none" stroke="currentColor" stroke-width="9"/>',
      'architecture': '<rect x="100" y="170" width="450" height="270" fill="var(--art-light)"/><path d="M87 171L317 52L563 171M154 207V435M253 207V435M352 207V435M451 207V435" stroke="currentColor" stroke-width="12" fill="none"/><path d="M108 170H542" stroke="var(--highlight)" stroke-width="27"/>',
      'luxury': '<ellipse cx="369" cy="235" rx="205" ry="155" fill="var(--art-light)"/><path d="M369 85L520 240L369 393L217 240Z" fill="var(--highlight)" opacity=".8"/><circle cx="369" cy="237" r="71" fill="none" stroke="currentColor" stroke-width="8"/>',
      'cafe': '<path d="M190 148H532V275Q525 399 361 395Q201 390 190 275Z" fill="var(--art-light)"/><path d="M520 160Q663 153 631 270Q610 322 532 311" fill="none" stroke="var(--highlight)" stroke-width="33"/><path d="M241 105Q208 57 246 28M353 105Q318 57 356 28M462 105Q427 57 465 28" fill="none" stroke="currentColor" stroke-width="9"/>',
      'food': '<circle cx="367" cy="240" r="195" fill="var(--art-light)" stroke="var(--highlight)" stroke-width="18"/><circle cx="367" cy="240" r="130" fill="none" stroke="currentColor" stroke-width="4"/><path d="M266 230Q370 120 472 230T266 230M285 315L465 174" stroke="var(--highlight)" stroke-width="12" fill="none"/>',
      'nature': '<path d="M347 423V72" stroke="currentColor" stroke-width="12"/><path d="M335 300C174 316 158 215 200 115C292 130 353 227 335 300M357 261C503 271 563 179 522 86C430 103 365 173 357 261M352 388C496 394 539 329 512 268C428 281 359 333 352 388" fill="var(--highlight)"/><path d="M233 155L340 285M490 124L360 250" stroke="var(--art-light)" stroke-width="8"/>',
      'coastal': '<circle cx="520" cy="112" r="83" fill="var(--art-light)"/><path d="M40 265Q130 198 220 265T400 265T580 265T760 265V470H40Z" fill="var(--highlight)"/><path d="M40 334Q130 279 220 334T400 334T580 334T760 334M40 394Q130 339 220 394T400 394T580 394T760 394" fill="none" stroke="var(--art-light)" stroke-width="12"/>',
      'museum': '<rect x="170" y="85" width="390" height="305" fill="var(--art-light)" stroke="currentColor" stroke-width="8"/><circle cx="365" cy="230" r="113" fill="var(--highlight)"/><rect x="207" y="334" width="310" height="18" fill="currentColor"/><path d="M180 410H560" stroke="currentColor" stroke-width="4"/>',
    }[theme.layout]
    marks = ''.join(f'<circle cx="{90+seed[i]*2}" cy="{80+seed[i+1]}" r="{3+seed[i+2]%7}" fill="var(--highlight)" opacity=".35"/>' for i in (2, 6, 10, 14, 18))
    return f'<svg xmlns="http://www.w3.org/2000/svg" class="hero-art" viewBox="0 0 740 470" role="img" aria-label="Original abstract illustration">{grid}<g transform="rotate({(sx-65)//5} 370 235)">{base}</g>{marks}</svg>'


def css(theme):
    seed = hashlib.sha256(theme.name.encode('ascii')).digest()
    hue = (seed[0] + seed[1] // 2) % 360
    dark = theme.layout in ('terminal', 'dashboard', 'gallery', 'luxury', 'museum')
    paper = '#101a25' if dark else '#fcfaf5'
    ink = '#e8eef7' if dark else '#20252a'
    card = '#18283b' if dark else '#ffffff'
    muted = '#a6b2c3' if dark else '#677078'
    light = '#334960' if dark else '#e5e9ea'
    highlight = f'hsl({hue} {72 if dark else 58}% {65 if dark else 47}%)'
    serif = theme.layout in ('editorial', 'magazine', 'luxury', 'cafe', 'museum')
    font = 'Georgia,"Times New Roman",serif' if serif else 'system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif'
    family = theme.layout
    return f'''/* Original site {theme.name}; entirely local, no external CSS/images. */
:root{{--paper:{paper};--ink:{ink};--card:{card};--muted:{muted};--art-light:{light};--highlight:{highlight};--line:{'#405063' if dark else '#d7dfe2'};--font:{font}}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,-apple-system,sans-serif}}
a{{color:inherit}}a:focus-visible,summary:focus-visible{{outline:3px solid var(--highlight);outline-offset:4px}}img,svg{{max-width:100%}}.page{{max-width:1720px;margin:auto;overflow:hidden}}
.skip{{position:absolute;left:-999px;top:10px;background:var(--highlight);color:var(--paper);padding:12px;z-index:10}}.skip:focus{{left:10px}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:24px;padding:26px clamp(20px,5vw,90px);border-bottom:1px solid var(--line)}}
.brand{{font:700 1.35rem var(--font);text-decoration:none;letter-spacing:-.04em;display:flex;align-items:center;gap:13px}}.mark{{display:grid;place-items:center;background:var(--highlight);color:var(--paper);width:42px;height:42px;border-radius:12px;font-size:21px}}
nav{{display:flex;gap:clamp(12px,3vw,31px);flex-wrap:wrap}}nav a{{text-decoration:none;font-weight:600;font-size:.91rem}}nav a:hover{{text-decoration:underline;text-underline-offset:6px}}
.hero{{display:grid;grid-template-columns:1fr 1fr;min-height:570px;align-items:center;gap:20px;padding:70px clamp(20px,5vw,90px)}}
.hero-copy{{max-width:740px}}.eyebrow,.index{{font-weight:750;font-size:.8rem;letter-spacing:.14em;text-transform:uppercase;color:var(--highlight)}}
h1,h2,h3{{font-family:var(--font);letter-spacing:-.055em;line-height:1.08}}h1{{font-size:clamp(2.85rem,6.1vw,6.7rem);margin:25px 0 28px}}h2{{font-size:clamp(2.2rem,4vw,3.6rem)}}h3{{font-size:clamp(1.5rem,2.1vw,2rem)}}
.lead{{font-size:clamp(1.05rem,1.4vw,1.3rem);max-width:60ch;color:var(--muted)}}.cta{{display:inline-block;margin-top:27px;padding:13px 25px;border:2px solid var(--highlight);border-radius:999px;color:var(--ink);font-weight:750;text-decoration:none}}.cta:hover{{background:var(--highlight);color:var(--paper)}}
.hero-art{{width:100%;height:auto;color:var(--ink)}}.visual{{border-radius:25px;background:var(--card);padding:10px;min-height:330px;display:grid;place-items:center}}
.strip{{background:var(--highlight);color:var(--paper);padding:16px clamp(20px,5vw,90px);display:flex;justify-content:space-between;gap:20px;font-weight:700;letter-spacing:.06em}}
.section{{padding:65px clamp(20px,5vw,90px)}}.section-heading{{max-width:680px}}.section-heading p{{color:var(--muted)}}.cards{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;margin-top:36px}}
.card{{border:1px solid var(--line);background:var(--card);padding:clamp(23px,3.4vw,49px);border-radius:14px;min-height:220px}}.card p{{max-width:50ch;color:var(--muted)}}.card a{{font-size:.93rem;font-weight:700;text-underline-offset:4px}}
.about{{background:var(--card);padding:70px clamp(20px,5vw,90px);border-top:1px solid var(--line)}}.about p{{max-width:65ch;color:var(--muted)}}.foot{{padding:34px clamp(20px,5vw,90px);display:flex;justify-content:space-between;gap:22px;flex-wrap:wrap;border-top:1px solid var(--line);color:var(--muted);font-size:.86rem}}
.inner-head{{padding:75px clamp(20px,5vw,90px);background:var(--card);border-bottom:1px solid var(--line)}}.inner-head h1{{max-width:13ch}}.inner-head p{{max-width:65ch}}.inner-body{{padding:55px clamp(20px,5vw,90px) 95px;max-width:1100px}}.article{{padding:27px 0;border-top:1px solid var(--line)}}.article p{{max-width:74ch;color:var(--muted)}}.qa{{padding:19px 0;border-bottom:1px solid var(--line)}}.qa summary{{cursor:pointer;font-weight:750}}.qa p{{max-width:65ch;color:var(--muted)}}
/* 16 genuinely distinct visual grammars: hierarchy, composition and grid, not just palette. */
.layout-terminal .hero,.layout-documentation .hero{{grid-template-columns:1.12fr .88fr}}.layout-terminal .hero{{background:linear-gradient(130deg,var(--paper),var(--card))}}.layout-terminal .card{{border-radius:2px;border-left:4px solid var(--highlight)}}
.layout-dashboard .hero{{min-height:480px}}.layout-dashboard .cards{{grid-template-columns:repeat(4,minmax(0,1fr))}}.layout-dashboard .card{{padding:25px;min-height:255px}}
.layout-documentation .hero{{grid-template-columns:.8fr 1.2fr;min-height:480px}}.layout-documentation .card{{border-left:5px solid var(--highlight);border-radius:0}}
.layout-editorial h1{{font-size:clamp(3.8rem,7.6vw,8.5rem)}}.layout-editorial .hero{{grid-template-columns:1.3fr .7fr}}.layout-editorial .cards{{grid-template-columns:1fr 1fr}}
.layout-modern .hero{{min-height:620px;grid-template-columns:1fr 1.08fr}}.layout-modern .visual{{border-radius:60px 20px 70px 20px}}.layout-modern .card:nth-child(2n){{transform:translateY(22px)}}
.layout-research .cards{{grid-template-columns:1fr 1fr}}.layout-research .card{{border-radius:0;border-top:4px solid var(--highlight)}}
.layout-workshop .hero{{grid-template-columns:1fr 1fr}}.layout-workshop .visual{{background:linear-gradient(155deg,var(--card),var(--art-light))}}.layout-workshop .card{{border-radius:0}}
.layout-magazine .hero{{display:flex;flex-direction:column;text-align:center}}.layout-magazine .hero-copy{{max-width:970px}}.layout-magazine .visual{{width:min(100%,930px)}}.layout-magazine .cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.layout-gallery .hero{{min-height:670px;grid-template-columns:1fr 1.25fr}}.layout-gallery .cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}.layout-gallery .card{{border-radius:0}}
.layout-architecture .hero{{grid-template-columns:.75fr 1.25fr}}.layout-architecture .card{{border-radius:0;border-left:8px solid var(--highlight)}}
.layout-luxury .hero{{display:flex;flex-direction:column;text-align:center;gap:5px}}.layout-luxury .hero-copy{{max-width:950px}}.layout-luxury .visual{{width:min(90%,860px);border-radius:50%}}.layout-luxury .cards{{grid-template-columns:1fr 1fr}}
.layout-cafe .hero{{grid-template-columns:1.2fr .8fr}}.layout-cafe .card{{border-radius:32px}}.layout-cafe .visual{{border-radius:50%}}
.layout-food .cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}.layout-food .card:nth-child(3n){{background:var(--art-light)}}
.layout-nature .hero{{grid-template-columns:1.15fr .85fr}}.layout-nature .visual{{border-radius:80px 8px 80px 8px}}.layout-nature .cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}
.layout-coastal .hero{{grid-template-columns:1fr 1.15fr}}.layout-coastal .visual{{border-radius:90px 90px 15px 15px}}.layout-coastal .cards{{grid-template-columns:1fr 1fr}}
.layout-museum .hero{{grid-template-columns:1fr 1fr}}.layout-museum .visual{{border:22px solid var(--line);border-radius:0}}.layout-museum .card{{border-radius:0;border-bottom:4px solid var(--highlight)}}
@media(max-width:1100px){{.layout-dashboard .cards{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}
@media(max-width:760px){{.top{{align-items:flex-start;flex-direction:column}}.hero,.layout-terminal .hero,.layout-documentation .hero,.layout-editorial .hero,.layout-modern .hero,.layout-dashboard .hero,.layout-research .hero,.layout-workshop .hero,.layout-gallery .hero,.layout-architecture .hero,.layout-cafe .hero,.layout-food .hero,.layout-nature .hero,.layout-coastal .hero,.layout-museum .hero{{grid-template-columns:1fr;min-height:0;padding:42px 22px}}.layout-modern .card:nth-child(2n){{transform:none}}.hero h1{{font-size:clamp(2.6rem,10vw,4.7rem)}}.cards,.layout-dashboard .cards{{grid-template-columns:1fr}}.section,.about,.inner-body,.inner-head{{padding:40px 22px}}.strip{{padding:12px 22px;flex-wrap:wrap}}.visual{{min-height:0}}}}
@media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}}}
'''.encode('utf-8')


def _nav(spec):
    words = ui(spec)
    return ''.join(f'<a href="{dest}">{e(words[label])}</a>' for dest, label in
                   (('index.html', 'home'), ('journal.html', 'journal'), ('about.html', 'about'), ('questions.html', 'questions')))


# Each subject gets its own short editorial lead. Editorial tone varies by
# discipline (technical, craft, cuisine, travel, arts, learning) and by article.
# These are explanatory briefs, not invented customer stories or reviews.
TOPIC_CONTEXT_RU = (
    ('Отправная точка — наблюдаемые свойства системы и проверяемый результат.',
     'Разбираем, какие детали делают техническое решение понятным и воспроизводимым.',
     'Сравниваем поведение компонентов в разных условиях без громких обещаний.',
     'Фиксируем критерии качества и вопросы для следующей проверки.'),
    ('Начинаем с фактуры, формы и того, как материал ведёт себя в работе.',
     'Смотрим на композицию через пропорции, цвет и контраст деталей.',
     'Исследуем небольшие изменения, которые делают предмет выразительнее.',
     'Отмечаем особенности ручной работы и бережного обращения с материалом.'),
    ('Обращаем внимание на происхождение продуктов и порядок приготовления.',
     'Изучаем сочетания вкусов и роль температуры в привычной кухне.',
     'Записываем, как меняются аромат, текстура и цвет во времени.',
     'Собираем повседневные наблюдения, которые легко повторить дома.'),
    ('Смотрим на ландшафт через погоду, сезон и ритм маршрута.',
     'Отмечаем ориентиры и особенности местности без претензии на путеводитель.',
     'Обсуждаем, как наблюдать природу и не мешать её обитателям.',
     'Подводим итог прогулки в коротком дневнике впечатлений.'),
    ('Изучаем форму произведения, его контекст и историю восприятия.',
     'Обращаем внимание на незаметные детали, которые создают атмосферу.',
     'Сопоставляем материал, ритм и выразительные приёмы.',
     'Предлагаем новый ракурс для самостоятельного наблюдения.'),
    ('Разбиваем сложный процесс на понятные небольшие этапы.',
     'Выделяем основные определения, примеры и практические ограничения.',
     'Проверяем, какие наблюдения действительно помогут принять решение.',
     'Собираем короткий перечень вопросов для следующего шага.'),
)
TOPIC_CONTEXT_EN = (
    ('We look for observable behavior and a result that can be checked.',
     'A short study of details that make a technical decision explainable.',
     'Comparing components in different conditions without sweeping promises.',
     'A practical checklist of questions for the next review.'),
    ('Starting with material, surface and the shape of everyday objects.',
     'A closer look at proportion, light and the quiet details of composition.',
     'Small shifts in craft and presentation can change the whole impression.',
     'A note about process, materials and careful handling.'),
    ('Following ingredients, origin and the steps of preparation.',
     'Examining the relationship between heat, texture and flavor.',
     'A short note on changing color, aroma and consistency.',
     'Observations that can be repeated at a home table.'),
    ('Reading the landscape through weather, season and route.',
     'Considering landmarks and the shape of a journey.',
     'Observing nature carefully without disturbing its rhythms.',
     'Recording what stood out during a slow walk.'),
    ('Understanding form, context and the experience of an artwork.',
     'Following overlooked details that create atmosphere.',
     'Comparing rhythm, material and expressive technique.',
     'A fresh way to look, listen and take notes.'),
    ('Breaking a complicated process into understandable steps.',
     'Defining examples, terms and practical boundaries.',
     'Identifying which observations matter before choosing a direction.',
     'Collecting a concise set of next questions.'),
)


def article_copy(spec, index):
    number = int(spec.name.split('-', 1)[0])
    group = min(5, max(0, (number - 13) // 10)) if number <= 72 else min(5, (number - 73) // 6)
    context = (TOPIC_CONTEXT_EN if spec.language == 'en' else TOPIC_CONTEXT_RU)[group][index]
    subject = spec.subjects[index]
    if spec.language == 'en':
        return f'{subject}. {context} {spec.description}'
    return f'{subject}. {context} {spec.description}'


def shell(spec, page, heading, body, description):
    words=ui(spec)
    seed=hashlib.sha256((spec.name+page).encode()).digest()
    # Metadata never contains a made-up address or links to a third-party.
    title=e(spec.title + ' — ' + heading)
    description=e(description)
    logo=e(spec.emblem)
    stylesheet='style.css'  # relative for offline previews and valid at /journal.html
    art_html = art(spec)
    head=(f'<!doctype html>\n<html lang="{spec.language}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
          f'<meta name="description" content="{description}"><meta name="color-scheme" content="{'dark' if spec.layout in ('terminal','dashboard','gallery','luxury','museum') else 'light'}">'
          f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'">'
          f'<title>{title}</title><link rel="stylesheet" href="{stylesheet}"><link rel="icon" href="favicon.svg" type="image/svg+xml"></head><body class="layout-{spec.layout}"><div class="page">'
          f'<a class="skip" href="#main">{e(words["read"])}</a><header class="top"><a class="brand" href="index.html"><span class="mark" aria-hidden="true">{logo}</span>{e(spec.title)}</a>'
          f'<nav aria-label="{e(words["journal"])}">{_nav(spec)}</nav></header>')
    if page == 'index':
        hero=f'<section class="hero"><div class="hero-copy"><p class="eyebrow">{e(spec.category)} / {e(spec.layout.replace("-"," "))}</p><h1>{e(spec.headline)}</h1><p class="lead">{e(spec.description)}</p><a class="cta" href="journal.html">{e(words["more"])}</a></div><div class="visual">{art_html}</div></section>'
        blocks=''.join(f'<article class="card"><span class="index">0{i+1}</span><h3>{e(t)}</h3><p>{e(spec.description)}</p><a href="journal.html">{e(words["read"])}</a></article>' for i,t in enumerate(spec.subjects))
        main=f'<main id="main">{hero}<div class="strip"><span>{e(spec.category)}</span><span>{e(words["description"])}</span></div><section class="section"><div class="section-heading"><p class="eyebrow">{e(words["latest"])}</p><h2>{e(words["journal"])}</h2><p>{e(spec.description)}</p></div><div class="cards">{blocks}</div></section><section class="about"><h2>{e(words["about"])}</h2><p>{e(words["independent"])}</p><a class="cta" href="about.html">{e(words["read"])}</a></section></main>'
    else:
        main=f'<main id="main"><section class="inner-head"><p class="eyebrow">{e(spec.category)} / {e(words["journal"])}</p><h1>{e(heading)}</h1><p class="lead">{description}</p></section><div class="inner-body">{body}</div></main>'
    foot=f'<footer class="foot"><span>{e(spec.title)} · 2026 · {e(words["independent"])}</span><a href="sitemap.xml">{e(words["sitemap"])}</a></footer></div></body></html>\n'
    return (head+main+foot).encode('utf-8')


def favicon(spec):
    seed=hashlib.sha256(spec.name.encode('ascii')).digest()
    hue=(seed[0]+seed[1]//2)%360
    glyph=e(spec.emblem)
    # color is numeric and deterministic.
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="16" fill="hsl({hue} 58% 38%)"/>'
            f'<text x="32" y="41" font-size="26" text-anchor="middle" fill="white">{glyph}</text></svg>\n').encode()


def render(name, domain='preview.example.test', rich=True):
    valid_domain(domain)
    if name not in THEMES:
        raise ValueError('unknown catalog theme')
    if name in SIGNATURES:
        return render_signature(name, domain)
    spec=THEMES[name]
    labels=ui(spec)
    items=''.join(f'<article class="article"><span class="index">0{i+1} / {e(spec.category)}</span><h2>{e(title)}</h2>'
                  f'<p>{e(article_copy(spec, i))}</p><p>{e(labels["independent"])}</p></article>' for i, title in enumerate(spec.subjects))
    about=(f'<h2>{e(spec.title)}</h2><p>{e(spec.description)}</p><p>{e(labels["not_a_service"])}</p><p>{e(labels["privacy"])}</p>')
    qas=((labels['how'],labels['how_answer']),(labels['data'],labels['data_answer']),(labels['fresh'],labels['fresh_answer']))
    qa=''.join(f'<details class="qa"><summary>{e(q)}</summary><p>{e(answer)}</p></details>' for q,answer in qas)
    # All pages have same stable local links, no extra assets or dynamic backend.
    result={
      'index.html':shell(spec,'index',spec.headline,'',spec.description),
      'style.css':css(spec),
      '404.html':shell(spec,'404',labels['not_found'],f'<p>{e(labels["not_found"])}</p><p><a href="index.html">{e(labels["back"])}</a></p>',spec.description),
      'favicon.svg':favicon(spec),
    }
    if rich:
        result.update({
          'journal.html':shell(spec,'journal',labels['journal'],items,spec.description),
          'about.html':shell(spec,'about',labels['about'],about,spec.description),
          'questions.html':shell(spec,'questions',labels['questions'],qa,spec.description),
          'robots.txt':f'User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n'.encode('ascii'),
          'sitemap.xml':('<?xml version="1.0" encoding="utf-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+
                         ''.join(f'<url><loc>https://{domain}/{p}</loc></url>' for p in ('',)+PAGES)+'</urlset>\n').encode('utf-8')
        })
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list',action='store_true')
    parser.add_argument('--name',choices=NAMES)
    parser.add_argument('--domain',default='preview.example.test')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--rich',action='store_true')
    args=parser.parse_args(argv)
    if args.list and args.name is None and args.output is None:
        for spec in THEMES.values():
            print(f'{spec.name}\t{spec.category}\t{spec.title}\t{spec.layout}\t{spec.language}')
        return 0
    if args.name is None or args.output is None:
        parser.error('use --list OR --name NAME --output NEW_DIR')
    if args.output.exists() or not args.output.parent.is_dir():
        parser.error('output directory exists or parent missing')
    content=render(args.name,args.domain,args.rich)
    args.output.mkdir(mode=0o755)
    for path,data in content.items():
        dest=args.output/path
        with dest.open('xb') as f:
            f.write(data)
        dest.chmod(0o644)
    print(f'SITE_CATALOG=PASS name={args.name} pages={sum(k.endswith(".html") for k in content)}')
    return 0


if __name__=='__main__':
    sys.exit(main())
