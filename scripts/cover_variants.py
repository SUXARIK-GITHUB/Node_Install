#!/usr/bin/env python3
"""Twelve independent, offline editorial microsites.

Only local HTML/CSS/SVG. The domain is validated, then used exclusively to
select deterministic editorial/layout/art variations; no network or data collection.
The original six theme names are preserved for existing operators.
"""
import argparse
import hashlib
import html
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SITES = ROOT / 'cover-variants'
NAMES = (
    '01-atelier', '02-archive', '03-observatory', '04-fieldnotes',
    '05-readingroom', '06-foundry', '07-botanica', '08-nocturne',
    '09-kitchen', '10-atlas', '11-tides', '12-cinema',
)
DOMAIN = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?')
# Four distinct editorial names, alternative headlines, and original short articles
# per theme. They are fictional editorial samples, not claims about real institutions.
THEMES = {
 '01-atelier': dict(emoji='🏺', label='Ателье формы', names=('Контур и глина','Студия линии','Тихие формы','Ручная работа'), section='Мастерская предметов', headlines=('Материал тоже рассказывает историю','Форма рождается в деталях','Малые вещи, большие смыслы'), intro='Заметки о керамике, текстурах и спокойном предметном дизайне.', nav=('Коллекция','Материалы','Изнутри','Вопросы'), items=(('Эскиз без спешки','Как наблюдение превращается в предмет, а идея — в прототип.'),('Палитра земли','Песок, мел и терракота в домашнем пространстве.'),('Работа с фактурой','Почему поверхность предмета важна не меньше формы.'),('Происхождение цвета','Смотрим на минералы и обжиг в авторских пробах.'),('Тихий объект','Композиция из света, тени и одного предмета.')), faq=(('Как выбираются материалы?','По тактильности, долговечности и соответствию задуманной форме.'),('Можно увидеть процесс?','В заметках собраны этапы от эскиза до экспериментального образца.'),('Есть ли магазин?','Это редакционный каталог идей и наблюдений, без заказов и платежей.'))),
 '02-archive': dict(emoji='🗂️',label='Архив городских историй',names=('Лист за листом','Дело №','Память улиц','Городской индекс'),section='Каталог воспоминаний',headlines=('У каждого предмета есть дата','Город как документ','Истории живут в деталях'),intro='Небольшие редакционные материалы о бытовой истории, письмах и предметах прошлого.',nav=('Хронология','Документы','Фонды','Справка'),items=(('Старое письмо','Что можно узнать из бумажного конверта без адресата.'),('Карточки улиц','Как меняются названия, вывески и повседневные маршруты.'),('Домашний архив','Правила сохранения семейных фотографий и заметок.'),('Знаки на стенах','История оформления домов через детали фасада.'),('Память вещей','Предметы, за которыми скрываются будничные сюжеты.')),faq=(('Откуда материалы?','Здесь представлены авторские тематические эссе и примеры каталогизации.'),('Как устроен каталог?','Темы сгруппированы по времени, материалу и сюжету.'),('Есть ли поиск по фамилиям?','Персональные архивы и данные людей здесь не размещаются.'))),
 '03-observatory': dict(emoji='🔭',label='Небесный дневник',names=('Тихая орбита','Северный купол','Время звёзд','Поле зрения'),section='Наблюдения неба',headlines=('Ночь начинается с вопроса','Смотрим дальше горизонта','Небо открывается терпеливым'),intro='Популярные заметки о созвездиях, фазах Луны и способах вести журнал наблюдений.',nav=('Сегодня','Атлас','Заметки','FAQ'),items=(('Фазы Луны','Как удобно отмечать изменения лунного диска в дневнике.'),('Красная звезда','Почему звёзды кажутся разных цветов.'),('Тёмное небо','Как выбирать место для наблюдений вдали от фонарей.'),('Карта созвездий','Пять шагов к самостоятельной небесной карте.'),('Первый телескоп','На что обратить внимание начинающему наблюдателю.')),faq=(('Нужен ли телескоп?','Нет, некоторые наблюдения можно делать невооружённым глазом.'),('Есть ли реальные измерения?','Страница — редакционный пример; текущие астроданные здесь не публикуются.'),('Как сохранить заметки?','Начните с даты, места, погоды и схематичного рисунка.'))),
 '04-fieldnotes': dict(emoji='🥾',label='Полевые заметки',names=('Тропа рядом','Между сосен','Зелёный компас','Пешком на рассвете'),section='Малые путешествия',headlines=('Лучшие маршруты начинаются рядом','Идти медленно — видеть больше','Открой свою карту местности'),intro='Заметки о лесных прогулках, наблюдении за природой и подготовке к коротким маршрутам.',nav=('Маршруты','Снаряжение','Дневник','Ответы'),items=(('Собираем рюкзак','Вода, слои одежды и простой план маршрута.'),('Следы в лесу','Учимся замечать признаки жизни без вмешательства.'),('Место на карте','Как записывать ориентиры для обратного пути.'),('Ритм похода','Удобная дистанция важнее скорости.'),('После дождя','Почему меняется цвет и запах лесных троп.')),faq=(('Можно использовать как путеводитель?','Нет, маршруты в макете иллюстративны; актуальные условия проверяйте локально.'),('Как относиться к дикой природе?','Не оставляйте мусор и не повреждайте растения.'),('Нужен ли опыт?','Для простых прогулок достаточно подготовки и понимания погоды.'))),
 '05-readingroom': dict(emoji='📖',label='Читальный зал',names=('Между строк','Полка у окна','Комната историй','Бумажный свет'),section='Эссе и чтение',headlines=('Книга может изменить угол зрения','Истории, к которым возвращаются','Время для одной страницы'),intro='Небольшой литературный журнал о чтении, заметках на полях и медленных вечерах.',nav=('Эссе','Библиотека','Цитатник','Частые вопросы'),items=(('Тишина читальни','Как обстановка влияет на внимание к тексту.'),('Закладка на полях','Наблюдения, которые хочется сохранить после главы.'),('Книжная полка','О разных способах собирать домашнюю библиотеку.'),('Ритм рассказа','Зачем писатели меняют длину предложений.'),('Письмо самому себе','О дневниках читателя и личных впечатлениях.')),faq=(('Есть ли книги для скачивания?','Нет. Это самостоятельные редакционные материалы о чтении.'),('Как вести читательский дневник?','Записывайте дату, вопрос и один неожиданный образ.'),('Можно читать на телефоне?','Макет адаптирован для небольших экранов и увеличенного текста.'))),
 '06-foundry': dict(emoji='⚙️',label='Индустриальная мастерская',names=('Цех идей','Сталь и свет','Форма производства','Инженерный лист'),section='Материалы и производство',headlines=('Красота точного соединения','Индустриальная эстетика деталей','Проект начинается с чертежа'),intro='Заметки о промышленном дизайне, простых механизмах и материальной культуре.',nav=('Объекты','Методы','Каталог','Вопросы'),items=(('Линия реза','Почему точность начинается с правильной разметки.'),('Металл в интерьере','Фактура и цвет металлов в повседневных предметах.'),('Модульный подход','Отдельные детали как части большой системы.'),('Прототип на столе','Как проверять форму на малом масштабе.'),('Сборка и разборка','Что делает устройство удобным для обслуживания.')),faq=(('Это производственная компания?','Нет, страница содержит тематические материалы и демонстрационные эскизы.'),('Есть ли инженерные расчёты?','Здесь описаны концепции, а не проектная документация.'),('Можно повторять конструкции?','Любая реальная сборка требует отдельной проверки безопасности.'))),
 '07-botanica': dict(emoji='🌿',label='Ботанический дневник',names=('Лист и свет','Дом растений','Зелёный гербарий','Малый сад'),section='Коллекция растений',headlines=('Зелень меняет пространство','Каждый лист — маленькая система','Свет, вода и терпение'),intro='Справочные карточки о домашних растениях, сезонных наблюдениях и зелёном интерьере.',nav=('Гербарий','Уход','Сезоны','Подсказки'),items=(('Новый лист','Как растение реагирует на освещение в комнате.'),('Тихое утро','Наблюдаем за влажностью почвы и светом.'),('Структура кроны','Формы листьев и их декоративная роль.'),('Малый сад','Как составить простую композицию из горшечных растений.'),('Сезонные ритмы','Почему рост зависит от длины светового дня.')),faq=(('Какие растения подойдут новичку?','Выбирайте виды с понятными требованиями к свету и поливу.'),('Есть ли продажа растений?','Нет, это иллюстрированный справочный макет.'),('Как избежать перелива?','Проверяйте влажность почвы и особенности выбранного вида.'))),
 '08-nocturne': dict(emoji='🎧',label='Звуковые заметки',names=('Ночной кассетник','Частота города','Другая сторона','Мягкий шум'),section='Лаборатория звука',headlines=('У каждого места есть свой ритм','Звук — архитектура момента','Между тишиной и мелодией'),intro='Оригинальные тексты о звуковых ландшафтах, плейлистах и культуре внимательного слушания.',nav=('Сессии','Плейлист','Атмосфера','FAQ'),items=(('Шум дождя','Почему монотонные звуки помогают замечать детали.'),('Тёплый винил','Как ностальгия меняет впечатление от музыки.'),('Пауза в мелодии','Тишина как равноправный музыкальный приём.'),('Ночной город','Автобусы, шаги, шорохи и их ритмический рисунок.'),('Комната звука','Что влияет на звучание небольшого пространства.')),faq=(('Можно слушать треки на сайте?','Здесь опубликованы только авторские тексты, без аудиоплеера.'),('Какие жанры обсуждаются?','Эмбиент, экспериментальные композиции и городская акустика.'),('Как начать слушательский дневник?','Запишите место, настроение и звуки вокруг.'))),
 '09-kitchen': dict(emoji='🍋',label='Кухонный блокнот',names=('Соль и цедра','Утро на кухне','Пять ингредиентов','Вкус выходного'),section='Домашняя кухня',headlines=('Хороший вкус начинается с простого','Рецепты для спокойного утра','Маленькие блюда, большие открытия'),intro='Идеи домашних блюд, заметки о сезонных продуктах и простых кухонных техниках.',nav=('Рецепты','Продукты','Сезон','Советы'),items=(('Цитрусовый завтрак','Лёгкий салат с йогуртом, мёдом и свежими фруктами.'),('Суп без суеты','Как собрать ароматный овощной бульон.'),('Идеальный тост','Хрустящая основа, мягкая начинка и свежая зелень.'),('Пряности по вкусу','Несколько способов сочетать травы и специи.'),('Простая выпечка','Как отмерять ингредиенты и следить за температурой.')),faq=(('Есть ли точные рецептуры?','Материалы служат идеями для домашней кухни, не профессиональными технологическими картами.'),('Можно заменить ингредиенты?','Да, учитывайте аллергию, сочетаемость и доступность продуктов.'),('Как хранить продукты?','Ориентируйтесь на безопасные сроки и рекомендации упаковки.'))),
 '10-atlas': dict(emoji='🧭',label='Городской атлас',names=('Переулки и площади','Город в деталях','Маршрут выходного','За углом'),section='Прогулки по городу',headlines=('Сверни за следующий угол','Улицы рассказывают истории','Открываем привычные маршруты'),intro='Редакционные идеи для неспешных прогулок, наблюдения за архитектурой и городскими мелочами.',nav=('Переулки','Маршруты','Места','Справка'),items=(('Улица в полдень','Смотрим на игру теней на фасадах.'),('Маленькая площадь','Почему небольшие пространства становятся точками встречи.'),('Необычный подъезд','Качество деталей в городской архитектуре.'),('Память вывесок','Графика и типографика на старых улицах.'),('Прогулка с блокнотом','Как записывать интересные места и открытия.')),faq=(('Есть ли GPS-навигация?','Нет, маршруты здесь — редакционные примеры без живого местоположения.'),('Можно полагаться на адреса?','Проверяйте фактическую доступность и часы работы мест отдельно.'),('Как составить свою прогулку?','Начните с небольшой петли и нескольких остановок для наблюдений.'))),
 '11-tides': dict(emoji='🌊',label='Прибрежная лаборатория',names=('По линии прибоя','Голубая глубина','Береговой дневник','Ветер и вода'),section='Истории воды',headlines=('У моря тысячи оттенков','Волна никогда не повторяется','Заметки с линии горизонта'),intro='Небольшие материалы о море, ветре, береговых экосистемах и наблюдении за природой.',nav=('Прилив','Берег','Наука','Ответы'),items=(('Цвет воды','Как освещение меняет оттенок поверхности.'),('След волны','Рисунок пены и песка как дневник движения.'),('Берег после шторма','Наблюдения за камнями, раковинами и водорослями.'),('Ветер над водой','Как образуются небольшие волны и рябь.'),('Тихая бухта','Почему разные участки побережья так не похожи.')),faq=(('Это прогноз приливов?','Нет, иллюстрации не являются актуальными измерениями.'),('Безопасно ли выходить к воде?','Всегда сверяйтесь с местным прогнозом и предупреждениями.'),('Как наблюдать природу берега?','Не тревожьте животных и сохраняйте чистоту.'))),
 '12-cinema': dict(emoji='🎞️',label='Кадры и истории',names=('Третий кадр','Кино после полуночи','Свет в объективе','Тихий экран'),section='Очерки о кино',headlines=('Каждый кадр выбирает свой свет','Кино — искусство внимания','За пределами экрана'),intro='Независимые тексты о кинематографическом языке, цвете, монтаже и памяти зрителя.',nav=('Кадры','Рецензии','Техники','Диалог'),items=(('Свет из окна','Как освещение создаёт настроение сцены.'),('Долгий план','Почему камера иногда остаётся неподвижной.'),('Цвет в кадре','Палитра как способ рассказывать историю.'),('Тишина в фильме','Когда отсутствие музыки говорит сильнее слов.'),('Начало титров','Почему оформление влияет на восприятие.')),faq=(('Есть ли здесь фильмы?','Нет, это редакционные заметки без видеохостинга и загрузок.'),('Публикуются ли рейтинги?','Материалы посвящены визуальному языку, а не рейтингам.'),('Как читать кино?','Обращайте внимание на свет, монтаж, звук и точку зрения.'))),
}

# Each theme has a different layout category and art direction. Colors are
# adjusted from a bounded, deterministic domain-derived palette at render time.
LAYOUTS = ('studio','ledger','space','outdoors','library','industry',
           'garden','music','food','city','water','film')
HUES = (23, 36, 48, 82, 124, 157, 182, 206, 235, 268, 295, 332)
DARK = {'03-observatory','06-foundry','08-nocturne','12-cinema'}


def valid_domain(value):
    if not isinstance(value,str) or len(value)>253 or not DOMAIN.fullmatch(value):
        raise ValueError('invalid site domain')
    # IDNA in upstream DNS; reject ambiguous Unicode and numeric-only hosts.
    if re.fullmatch(r'[.0-9]+',value):
        raise ValueError('numeric domain is not a site')
    return value


def _color(hue, saturation, light):
    # Explicit CSS hsl() avoids allowing untrusted text in stylesheet.
    return f'hsl({hue} {saturation}% {light}%)'


def art(theme, seed):
    """Small, original inline vector for each field, no external URL or JS."""
    shift=seed[7] % 27
    core={
    '01-atelier': f'<ellipse cx="350" cy="460" rx="210" ry="27" fill="var(--mist)"/><path d="M245 114 Q260 164 226 217 L220 357 Q219 419 351 429 Q478 420 479 357 L468 217 Q440 171 456 114Z" fill="var(--accent)" opacity=".84"/><path d="M245 114Q350 146 456 114M220 318Q353 366 479 319M249 216Q352 240 468 217" fill="none" stroke="var(--ink)" stroke-width="3" opacity=".28"/><ellipse cx="350" cy="114" rx="105" ry="19" fill="var(--paper)" stroke="var(--ink)" stroke-width="7"/><path d="M350 155V401" stroke="var(--paper)" stroke-width="3" opacity=".36"/>',
    '02-archive': '<rect x="100" y="60" width="450" height="365" rx="2" fill="var(--accent)" opacity=".3" transform="rotate(-8 320 260)"/><rect x="160" y="84" width="400" height="360" fill="var(--paper)" stroke="var(--ink)" stroke-width="3"/><path d="M210 145H505M210 173H505M210 204H435M210 250H508M210 279H470M210 309H500" stroke="var(--ink)" stroke-width="6" opacity=".4"/><circle cx="474" cy="368" r="45" fill="var(--accent)" opacity=".8"/><path d="M474 336V399M443 367H507" stroke="var(--paper)" stroke-width="6" opacity=".8"/>',
    '03-observatory': '<circle cx="342" cy="245" r="147" fill="none" stroke="var(--accent)" stroke-width="2" opacity=".8"/><ellipse cx="342" cy="245" rx="269" ry="108" fill="none" stroke="var(--ink)" stroke-width="5" transform="rotate(-25 342 245)"/><circle cx="342" cy="245" r="86" fill="var(--accent)"/><circle cx="302" cy="225" r="72" fill="var(--paper)" opacity=".2"/><circle cx="135" cy="337" r="18" fill="var(--ink)"/><circle cx="564" cy="129" r="10" fill="var(--accent)"/><path d="M62 76H640M62 417H640" stroke="var(--ink)" stroke-dasharray="4 18" opacity=".3"/>',
    '04-fieldnotes': '<path d="M30 415L205 180L295 292L421 100L658 416Z" fill="var(--accent)" opacity=".8"/><path d="M188 201L205 180L295 292L421 100L535 257" fill="none" stroke="var(--paper)" stroke-width="12" opacity=".72"/><path d="M40 475C120 350 240 490 342 405S515 340 650 430" fill="none" stroke="var(--ink)" stroke-width="7" stroke-dasharray="14 12"/><circle cx="342" cy="405" r="18" fill="var(--paper)" stroke="var(--ink)" stroke-width="5"/>',
    '05-readingroom': '<rect x="90" y="100" width="520" height="330" rx="10" fill="var(--mist)"/><path d="M350 120C258 83 174 110 132 128V401C228 375 292 375 350 410C406 374 479 375 571 400V128C497 107 414 85 350 120Z" fill="var(--paper)" stroke="var(--ink)" stroke-width="5"/><path d="M350 120V411M178 172H310M179 215H308M180 256H308M390 171H520M390 214H519M391 256H522" stroke="var(--accent)" stroke-width="7" stroke-linecap="round"/><path d="M145 395C222 371 281 382 350 412C418 382 491 375 561 394" fill="none" stroke="var(--ink)" stroke-width="4"/>',
    '06-foundry': '<path d="M117 329L335 86L584 306L363 463Z" fill="var(--accent)"/><path d="M117 329L117 391L363 505V463M584 306V376L363 505" fill="var(--mist)" stroke="var(--ink)" stroke-width="4"/><path d="M335 86L335 170L420 244" fill="none" stroke="var(--paper)" stroke-width="12"/><circle cx="357" cy="329" r="88" fill="var(--ink)"/><circle cx="357" cy="329" r="42" fill="var(--paper)"/><path d="M93 90H230M93 113H190M478 102H606M498 122H606" stroke="var(--ink)" stroke-width="8" opacity=".5"/>',
    '07-botanica': '<path d="M348 470C347 376 347 262 348 120" stroke="var(--ink)" stroke-width="9" fill="none"/><path d="M340 326C201 327 159 266 171 184C288 172 331 239 340 326ZM359 251C470 250 535 167 501 85C385 105 356 166 359 251ZM351 424C452 409 515 332 492 279C404 281 361 348 351 424Z" fill="var(--accent)"/><path d="M217 210L340 326M471 130L359 251M460 319L351 424" stroke="var(--paper)" stroke-width="5" fill="none" opacity=".72"/><rect x="290" y="450" width="120" height="17" rx="8" fill="var(--mist)"/>',
    '08-nocturne': '<circle cx="350" cy="260" r="190" fill="var(--mist)"/><circle cx="350" cy="260" r="158" fill="var(--ink)"/><circle cx="350" cy="260" r="131" fill="none" stroke="var(--paper)" stroke-width="3" opacity=".27"/><circle cx="350" cy="260" r="93" fill="none" stroke="var(--accent)" stroke-width="18"/><circle cx="350" cy="260" r="35" fill="var(--paper)"/><path d="M70 120Q125 20 181 120T296 120T410 120T524 120T638 120" fill="none" stroke="var(--accent)" stroke-width="11"/>',
    '09-kitchen': '<ellipse cx="350" cy="275" rx="226" ry="188" fill="var(--paper)" stroke="var(--ink)" stroke-width="14"/><ellipse cx="350" cy="275" rx="182" ry="145" fill="var(--mist)"/><circle cx="290" cy="233" r="64" fill="var(--accent)"/><circle cx="388" cy="321" r="64" fill="var(--ink)" opacity=".8"/><path d="M280 147Q350 60 430 140" fill="none" stroke="var(--ink)" stroke-width="12"/><path d="M310 217L280 251M420 304L390 344" stroke="var(--paper)" stroke-width="6"/><circle cx="440" cy="230" r="17" fill="var(--accent)"/>',
    '10-atlas': '<rect x="85" y="90" width="510" height="330" rx="22" fill="var(--paper)" stroke="var(--ink)" stroke-width="5"/><path d="M125 145L230 172L333 134L451 210L558 180M130 277L240 243L335 304L465 272L559 307" fill="none" stroke="var(--accent)" stroke-width="20" opacity=".65"/><path d="M230 125L244 389M331 125L340 390M450 132L465 380" stroke="var(--ink)" stroke-width="5" stroke-dasharray="8 12" opacity=".5"/><circle cx="355" cy="241" r="31" fill="var(--ink)"/><path d="M355 289L331 254H380Z" fill="var(--ink)"/>',
    '11-tides': '<circle cx="514" cy="131" r="75" fill="var(--accent)" opacity=".6"/><path d="M40 290Q120 215 200 290T360 290T520 290T680 290V520H40Z" fill="var(--accent)" opacity=".75"/><path d="M40 338Q120 273 200 338T360 338T520 338T680 338" stroke="var(--paper)" stroke-width="13" fill="none"/><path d="M40 399Q120 340 200 399T360 399T520 399T680 399" stroke="var(--ink)" stroke-width="9" fill="none" opacity=".6"/><path d="M70 150H237M90 180H200" stroke="var(--ink)" stroke-width="7" opacity=".5"/>',
    '12-cinema': '<rect x="118" y="60" width="462" height="380" rx="13" fill="var(--ink)"/><rect x="178" y="92" width="344" height="315" fill="var(--accent)"/><path d="M260 360L342 166L454 360Z" fill="var(--paper)" opacity=".85"/><path d="M135 84V424M561 85V424" stroke="var(--paper)" stroke-width="12" stroke-dasharray="20 28"/><circle cx="419" cy="190" r="39" fill="var(--ink)" opacity=".8"/><path d="M164 464H550" stroke="var(--ink)" stroke-width="9"/>',
    }[theme]
    # Unique site-specific graphic registration mark, small and decorative.
    stars=''.join(f'<circle cx="{75+(seed[i]*2)%540}" cy="{75+(seed[i+1]*2)%320}" r="{2+seed[i+2]%3}" fill="var(--ink)" opacity=".28"/>' for i in (0,3,6,9,12))
    return f'<svg class="hero-art" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 520" role="img" aria-label="Авторская векторная иллюстрация"><g transform="rotate({(shift-13)//2} 350 260)">{core}</g>{stars}</svg>'


def _favicon(theme, seed):
    n=NAMES.index(theme)
    glyph=('◆','▤','✦','▲','▰','⬡','❧','♫','●','⌖','≈','▣')[n]
    # XML special characters are never emitted from domain input.
    dark=theme in DARK
    paper='#111822' if dark else '#fff8ef'
    hue=(HUES[n]+seed[2]%37-18)%360
    fg=f'hsl({hue} 62% {73 if dark else 43}%)'
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            f'<rect width="64" height="64" rx="17" fill="{paper}"/>'
            f'<circle cx="32" cy="32" r="25" fill="none" stroke="{fg}" stroke-width="2"/>'
            f'<circle cx="{8+seed[0]%15}" cy="{8+seed[1]%15}" r="2" fill="{fg}"/>'
            f'<text x="32" y="43" font-size="30" text-anchor="middle" fill="{fg}">{html.escape(glyph)}</text></svg>\n').encode('utf-8')


def _shell(theme, domain, seed):
    spec=THEMES[theme]
    n=NAMES.index(theme)
    style=LAYOUTS[n]
    variant=seed[0]%8
    name=spec['names'][int.from_bytes(seed[1:3],'big')%4]
    headline=spec['headlines'][seed[3]%3]
    datecode=(seed[4]%11)+1
    quarter=('Весна','Лето','Осень','Зима')[seed[6]%4]
    issue=f'{quarter} · выпуск {datecode:02d}'
    items=list(spec['items'])
    offset=seed[5]%len(items)
    items=items[offset:]+items[:offset]
    index=seed[8]%3
    blocks=[]
    for i,(heading,body) in enumerate(items[:4]):
        blocks.append(f'<article class="item item-{i+1}"><span class="kicker">{i+1:02d} / {html.escape(spec["nav"][i%4])}</span>'
                      f'<h3>{html.escape(heading)}</h3><p>{html.escape(body)}</p>'
                      f'<a href="#notes" aria-label="К материалам">Читать заметку <span aria-hidden="true">↗</span></a></article>')
    articles='\n'.join(blocks)
    nav_ids=('features','notes','about','faq')
    links=''.join(f'<a href="#{id_}">{html.escape(label)}</a>' for id_,label in zip(nav_ids,spec['nav']))
    faq=''.join(f'<details><summary>{html.escape(q)}</summary><p>{html.escape(a)}</p></details>' for q,a in spec['faq'])
    # Semantic DOM composition differs across families, and is further varied
    # per domain through the ordering of editorial pieces and layout switches.
    hero=f'<section class="hero" id="start"><div class="hero-copy"><p class="eyebrow">{html.escape(spec["emoji"])} {html.escape(spec["section"])} — {issue}</p><h1>{html.escape(headline)}</h1><p class="lead">{html.escape(spec["intro"])}</p><a class="cta" href="#features">Открыть выпуск <span aria-hidden="true">↗</span></a></div><figure>{art(theme,seed)}<figcaption>Иллюстрация редакции · {issue}</figcaption></figure></section>'
    deck=f'<section class="sections" id="features"><div class="section-heading"><span>0{(n%9)+1} / ТЕМЫ</span><h2>{html.escape(spec["section"])}</h2><p>{html.escape(spec["intro"])}</p></div><div class="items">{articles}</div></section>'
    notes=f'<section class="notes" id="notes"><p class="eyebrow">{html.escape(spec["emoji"])} Редакторская колонка</p><blockquote>«{html.escape(spec["headlines"][(index+1)%3])}.»</blockquote><p>Небольшой самостоятельный выпуск: идеи, наблюдения и материалы для вдумчивого чтения. Без рекламы, регистраций и внешних ресурсов.</p><a href="#faq">Перейти к вопросам <span aria-hidden="true">↓</span></a></section>'
    about=f'<section class="about" id="about"><div><span class="eyebrow">Об издании</span><h2>Место для внимательных идей</h2></div><p>Это независимая тематическая страница с оригинальными текстами и векторными иллюстрациями. Содержимое представлено в демонстрационных и справочных целях.</p></section>'
    questions=f'<section class="questions" id="faq"><div><span class="eyebrow">Больше информации</span><h2>Частые вопросы</h2></div><div class="details">{faq}</div></section>'
    orders=(('hero','deck','notes','about','questions'),('hero','notes','deck','questions','about'),('hero','deck','about','notes','questions'))
    pieces={'hero':hero,'deck':deck,'notes':notes,'about':about,'questions':questions}
    order=orders[(n+seed[9]%3)%3]
    main=''.join(pieces[p] for p in order)
    safe_name=html.escape(name)
    description=html.escape(spec['intro'],quote=True)
    header=f'<header class="top"><a class="brand" href="#start"><span class="brand-icon" aria-hidden="true">{spec["emoji"]}</span><span>{safe_name}</span></a><nav aria-label="Навигация по странице">{links}</nav><span class="issue">{issue}</span></header>'
    return (f'<!doctype html>\n<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="description" content="{description}"><meta name="color-scheme" content="light dark">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'">'
            f'<title>{safe_name} — {html.escape(spec["section"])}</title><link rel="stylesheet" href="style.css">'
            f'<link rel="icon" href="favicon.svg" type="image/svg+xml"></head>'
            f'<body class="theme theme-{style} variant-{variant}"><div class="page">{header}<main>{main}</main>'
            f'<footer class="foot"><span>{safe_name} © 2026 · авторский тематический журнал</span><a href="#start">Наверх ↑</a></footer></div></body></html>\n').encode('utf-8')


def render(theme, domain):
    """Return deterministic, fully standalone (HTML,CSS,404,SVG) bytes.

    No user-provided path or HTML is interpolated into generated assets.
    This does NOT aim to make server technologies unidentifiable.
    """
    if theme not in THEMES: raise ValueError('unknown theme')
    valid_domain(domain)
    src=SITES/theme/'style.css'
    if src.is_symlink() or not src.is_file(): raise ValueError('missing stylesheet')
    base=src.read_bytes()
    if len(base)>96*1024 or b'@import' in base or b'url(' in base or b'<script' in base:
        raise ValueError('unsafe stylesheet')
    seed=hashlib.sha256((theme+'\n'+domain).encode('ascii')).digest()
    n=NAMES.index(theme)
    accent_hue=(HUES[n]+seed[2]%37-18)%360
    light=73 if theme in DARK else 43
    vars_css=(f':root{{--accent:{_color(accent_hue,62,light)};'
              f'--mist:{_color((accent_hue+24)%360,27,26 if theme in DARK else 86)};'
              f'--site-tilt:{seed[10]%17-8}deg;}}\n').encode()
    css=base+vars_css
    page=_shell(theme,domain,seed)
    # Keep 404 as 404 (nginx internal error_page), but provide an accessible,
    # visually coherent explanation and a working link to /.
    name=THEMES[theme]['names'][int.from_bytes(seed[1:3],'big')%4]
    error=(f'<!doctype html><html lang="ru"><head><meta charset="utf-8">'
           f'<meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'self\'; img-src \'self\'; base-uri \'none\'; form-action \'none\'">'
           f'<title>Страница не найдена · {html.escape(name)}</title><link rel="stylesheet" href="style.css"></head>'
           f'<body class="theme theme-{LAYOUTS[n]} error-page"><main class="error-wrap"><span class="error-code">404 / Страница не найдена · выпуск {int.from_bytes(seed[:4],"big")%9999999:07d}</span>'
           f'<h1>Похоже, этого адреса здесь нет.</h1><p>Проверьте ссылку или вернитесь к публикациям и разделам.</p>'
           f'<a class="cta" href="/">Вернуться на главную ↗</a></main></body></html>\n').encode('utf-8')
    icon=_favicon(theme,seed)
    if any(len(x)>128*1024 for x in (page,css,error,icon)):
        raise ValueError('theme exceeds publish limit')
    return {'index.html':page,'style.css':css,'404.html':error,'favicon.svg':icon}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--list',action='store_true')
    p.add_argument('--name',choices=NAMES)
    p.add_argument('--domain',default='preview.example.test')
    p.add_argument('--output',type=Path)
    ns=p.parse_args(argv)
    if ns.list and not ns.name and ns.output is None:
        print('\n'.join(NAMES));return 0
    if not ns.name or ns.output is None or ns.list:
        p.error('use --list OR --name NAME --domain DOMAIN --output NEW_DIR')
    dest=ns.output
    if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
        print('COVER=FAIL DESTINATION_MUST_NOT_EXIST',file=sys.stderr);return 1
    try: content=render(ns.name,ns.domain)
    except (OSError,ValueError) as exc:
        print('COVER=FAIL SOURCE_OR_INPUT',type(exc).__name__,file=sys.stderr);return 1
    try:
        dest.mkdir(mode=0o755)
        for name,data in content.items():
            path=dest/name
            with path.open('xb') as f:f.write(data)
            path.chmod(0o644)
    except OSError:
        for name in content: (dest/name).unlink(missing_ok=True)
        if dest.exists():dest.rmdir()
        print('COVER=FAIL CREATE_ABORTED',file=sys.stderr);return 1
    print('COVER=PREPARED_OFFLINE',ns.name,'OUTPUT='+str(dest),'DOMAIN='+ns.domain)
    print('LIVE_NGINX=UNTOUCHED')
    return 0


if __name__=='__main__':sys.exit(main())
