#!/usr/bin/env python3
"""Topical reading companions for the existing 120 static publications.

Content is drawn from 120 distinct, hand-written focus notes and the existing
per-site reviewed workbook. No dynamic fetches, templates with random copy,
external assets, accounts or claims of actually performed field observations.
Preserve all existing article text, URLs and navigation.
"""

from html import escape

try:
    from site_focus_notes import FOCUS_NOTES
    from site_workbooks import WORKBOOKS, Workbook
    from site_identity import EXHIBITS
except ImportError:
    from scripts.site_focus_notes import FOCUS_NOTES
    from scripts.site_workbooks import WORKBOOKS, Workbook
    from scripts.site_identity import EXHIBITS


def _e(s):
    return escape(s, quote=True)



def _workbook(name):
    if name in WORKBOOKS:
        return WORKBOOKS[name]
    # Sixteen r51 in-depth exhibits predate the workbook series. Use their
    # own three fully authored paragraphs without inventing a new exercise.
    exhibit = EXHIBITS[name]
    title, first, second, third = exhibit
    labels = (('Первое наблюдение', 'Второе наблюдение', 'Границы вывода')
              if any('а' <= ch.lower() <= 'я' for ch in FOCUS_NOTES[name])
              else ('First observation', 'Second observation', 'Further reading'))
    return Workbook(title, first, (first, second, third),
                    tuple((label, text) for label, text in zip(labels, (first, second, third))),
                    FOCUS_NOTES[name])

def home_panel(name, language, extended=False):
    """A useful, topic-specific starting point, not another generic link list."""
    w = _workbook(name)
    ru = language == 'ru'
    if name in EXHIBITS and name not in WORKBOOKS:
        # This publication has an existing bespoke essay, not a workbook.
        # Avoid printing the same essay fragments multiple times on the home page.
        title, *paragraphs = EXHIBITS[name]
        heading = ('В центре выпуска: ' if ru else 'In this edition: ') + title
        link = 'Открыть подробный разбор' if ru else 'Read the detailed study'
        return (f'<section class="section editorial-start"><h2>{_e(heading)}</h2>'
                + ''.join(f'<p>{_e(text)}</p>' for text in paragraphs)
                + f'<p><a class="next-link" href="journal.html#special-study">{_e(link)}</a></p></section>')
    heading = 'С чего начать: ' + w.title if ru else 'Start here: ' + w.title
    label = 'Следующий шаг' if ru else 'Next step'
    comparison_label = 'Что отмечать' if ru else 'What to notice'
    # Three concrete, authored actions. They lead to the unabridged workbook.
    steps = ''.join('<li><p>' + _e(text) + '</p></li>' for text in w.steps[:3 if extended else 2])
    checks = '; '.join(label + ': ' + detail for label, detail in w.comparisons)
    anchor = 'practical-guide' if name in WORKBOOKS else 'special-study'
    extended_note = ('<p>' + _e(FOCUS_NOTES[name]) + '</p>') if extended else ''
    return (f'<section class="section editorial-start" aria-label="{_e(heading)}">'
            f'<div class="section-heading"><h2>{_e(heading)}</h2>'
            f'<p>{_e(w.introduction)}</p></div><ol>{steps}</ol>'
            f'<p><strong>{_e(comparison_label)}:</strong> {_e(checks)}</p>' + extended_note
            + f'<p><a class="next-link" href="journal.html#{anchor}">{_e(label)}</a></p>'
            '</section>')


def journal_companion(name, language, topics):
    """Reading prompts connecting four articles to the independent case study."""
    w = _workbook(name)
    ru = language == 'ru'
    label = 'На что обратить внимание' if ru else 'What to look for'
    subtitle = 'Вопросы для чтения' if ru else 'Reading questions'
    prompts = []
    for i, ((part, detail), topic) in enumerate(zip(w.comparisons, topics[:3])):
        next_topic = topics[i + 1]
        if ru:
            line = (f'В тексте «{topic}» найдите наблюдаемые признаки для пункта «{part}». '
                    f'{detail} Сопоставьте это с соседней темой «{next_topic}»: '
                    'какое условие следует записать отдельно, прежде чем делать общий вывод? '
                    'Что в этом сравнении вы действительно видите, а что пока предполагаете?')
        else:
            line = (f'While reading “{topic}”, look for observable evidence related to “{part}”. '
                    f'{detail} Compare it with “{next_topic}”: '
                    'which condition needs its own note before a conclusion is justified? '
                    'What is directly visible, and what remains an interpretation?')
        prompts.append(f'<li><p>{_e(line)}</p></li>')
    return (f'<section class="article editorial-companion" id="reading-companion">'
            f'<h2>{_e(label)}: {_e(w.title)}</h2><p>{_e(FOCUS_NOTES[name])}</p>'
            f'<h3>{_e(subtitle)}</h3><ol>' + ''.join(prompts) + '</ol>'
            '</section>')


def about_panel(name, language):
    """Explain publication scope with a specific example and honest boundaries."""
    w = _workbook(name)
    ru = language == 'ru'
    title = 'Метод и границы материалов' if ru else 'Method and limits'
    qualifier = ('Ниже приведён пример самостоятельной работы по теме издания; '
                 'он не является отчётом о проведённом исследовании.' if ru else
                 'The following is an independent reading exercise, not a report of fieldwork.')
    return (f'<section class="article editorial-scope"><h2>{_e(title)}</h2>'
            f'<p>{_e(qualifier)}</p><p>{_e(w.introduction)}</p>'
            f'<p>{_e(w.steps[2])}</p><p>{_e(w.limitations)}</p></section>')


def questions_panel(name, language):
    """Three original checkable questions grounded in this publication's workbook."""
    w = _workbook(name)
    ru = language == 'ru'
    result = []
    for i, (label, detail) in enumerate(w.comparisons):
        question = ('Что проверить в этом материале: ' + label + '?' if ru else 'What should I check in this material: ' + label + '?')
        # Every answer carries a concrete, separately authored step as well as
        # the shorter comparison label; preserve the r47 substantive FAQ gate.
        answer = detail + (' Пример: ' if ru else ' Example: ') + w.steps[i]
        result.append('<details class="qa rich-detail"><summary>' + _e(question) + '</summary><p>' + _e(answer) + '</p></details>')
    limitations = 'Какие есть ограничения?' if ru else 'What are the limits of this exercise?'
    result.append('<details class="qa rich-detail"><summary>' + _e(limitations) + '</summary><p>' + _e(w.limitations) + '</p></details>')
    return ''.join(result)


def audit_data_integrity(all_names, language_by_name):
    names = set(all_names)
    if names != set(FOCUS_NOTES) or names != (set(WORKBOOKS) | set(EXHIBITS)):
        raise ValueError('editorial expansion coverage differs from full site catalog')
    for name, lang in language_by_name.items():
        text = FOCUS_NOTES[name]
        cyr = sum('\u0400' <= ch <= '\u04ff' for ch in text)
        lat = sum(('a' <= ch.lower() <= 'z') for ch in text)
        if (lang == 'ru' and cyr < lat) or (lang == 'en' and lat < cyr):
            raise ValueError('editorial language mismatch: ' + name)
    return True
