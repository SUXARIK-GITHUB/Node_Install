#!/usr/bin/env python3
"""Single, reviewed entry point for the bundled 120-site staging catalog.

This CLI is a thin adapter over the original transactional NodeWeb engine.
No new service, arbitrary file serving, migration, or installation on an
already-running node is implied. The 443 listener and REALITY keys are not
modified. `menu` is interactive, but the operation needs an explicit typed
staging confirmation and a domain confirmation before any file is changed.
"""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

try:
    from staging_web_deploy import main as deploy_main, NodeWeb, DeployError
    from cover_variants import NAMES as ORIGINAL
    from site_catalog import NAMES as CATALOG
except ImportError:
    from scripts.staging_web_deploy import main as deploy_main, NodeWeb, DeployError
    from scripts.cover_variants import NAMES as ORIGINAL
    from scripts.site_catalog import NAMES as CATALOG

THEMES = tuple(ORIGINAL) + tuple(CATALOG)


@contextmanager
def installer_lock():
    """Exclude concurrent host installation, maintenance or site mutations."""
    path = Path('/run/lock/vkarmani-node-installer.lock')
    if path.is_symlink() or not path.parent.is_dir():
        raise RuntimeError('UNSAFE_INSTALLER_LOCK_PATH')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
            raise RuntimeError('UNSAFE_INSTALLER_LOCK_OWNER_OR_MODE')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('NODE_INSTALLER_OR_MAINTENANCE_BUSY') from exc
        yield
    finally:
        os.close(fd)


def translated(action, *, theme=None, domain=None, output=None, confirm=False):
    """Map user-facing commands onto the existing reviewed staging operations."""
    if action == 'list':
        return ['site-catalog']
    if action == 'status':
        return ['status']
    if action == 'preview':
        if theme not in THEMES or not output:
            raise ValueError('PREVIEW_REQUIRES_THEME_AND_OUTPUT')
        return ['site-preview', '--theme', theme, '--output', output, '--domain', domain or 'preview.example.test']
    if action in ('deploy', 'change'):
        if theme not in THEMES or not domain:
            raise ValueError('DEPLOY_REQUIRES_REVIEWED_THEME_AND_EXPECTED_DOMAIN')
        argv = ['site-deploy' if action == 'deploy' else 'site-change', '--theme', theme,
                '--expected-domain', domain]
        if action == 'deploy':
            argv.append('--rich-pages')
    elif action == 'rollback':
        argv = ['site-rollback']
    else:
        raise ValueError('UNSUPPORTED_SITE_ACTION')
    if confirm:
        argv.append('--confirm-staging')
    return argv


def _read(prompt, input_fn):
    try:
        return input_fn(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ''


def menu(input_fn=input, output_fn=print):
    """No implicit mutation: a full phrase and current node FQDN are required."""
    output_fn('VKarmani site manager (staging only; password SSH policy unchanged)')
    while True:
        output_fn('1 — Каталог 120 тем  2 — Статус  3 — Сменить/установить  4 — Откат  0 — Выход')
        choice = _read('Выбор: ', input_fn)
        if choice in ('0', ''):
            return 0
        if choice == '1':
            deploy_main(['site-catalog'])
            continue
        if choice == '2':
            deploy_main(['status'])
            continue
        if choice not in ('3', '4'):
            output_fn('Некорректный выбор.')
            continue
        if choice == '3':
            theme = _read('ID темы из каталога (например, 111-atlas-docs): ', input_fn)
            if theme not in THEMES:
                output_fn('Неизвестная тема. Ничего не изменено.')
                continue
        else:
            theme = None
        # `ready()` validates the owned installation and never prints credentials.
        try:
            node = NodeWeb()
            config = node.ready()
            active = node.receipt('site')
            domain = config['domain']
        except (DeployError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            output_fn('STOP: завершённая staging-нода не подтверждена; изменений нет.')
            continue
        if choice == '3':
            action = 'change' if active and active.get('stage') == 'active' else 'deploy'
            if active and active.get('stage') == 'pending':
                output_fn('STOP: незавершённая транзакция; сначала диагностика/откат.')
                continue
        else:
            action = 'rollback'
        output_fn('Режим: ' + action + ('; тема: ' + theme if theme else ''))
        if _read('Напиши STAGING для подтверждения тестовой среды: ', input_fn) != 'STAGING':
            output_fn('Отмена без изменений.')
            continue
        if _read('Повтори точный домен ноды для подтверждения: ', input_fn) != domain:
            output_fn('Домен не совпадает. Отмена без изменений.')
            continue
        try:
            with installer_lock():
                result = deploy_main(translated(action, theme=theme, domain=domain, confirm=True))
        except (OSError, RuntimeError):
            output_fn('STOP: installer lock unavailable or operation in progress')
            continue
        output_fn('Результат: ' + ('PASS' if result == 0 else 'STOP — проверь журнал и восстановление'))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('list', 'status', 'preview', 'deploy', 'change', 'rollback', 'menu'))
    p.add_argument('--theme', help='exact catalog ID; see list')
    p.add_argument('--expected-domain')
    p.add_argument('--output')
    p.add_argument('--confirm-staging', action='store_true')
    opts = p.parse_args(argv)
    if opts.action == 'menu':
        if any((opts.theme, opts.expected_domain, opts.output, opts.confirm_staging)):
            p.error('interactive menu takes no additional flags')
        return menu()
    if opts.action in ('deploy', 'change', 'rollback') and not opts.confirm_staging:
        p.error('mutating operation requires --confirm-staging')
    try:
        target = translated(opts.action, theme=opts.theme, domain=opts.expected_domain,
                            output=opts.output, confirm=opts.confirm_staging)
    except ValueError as exc:
        p.error(str(exc))
    if opts.action in ('deploy', 'change', 'rollback'):
        try:
            with installer_lock():
                return deploy_main(target)
        except (OSError, RuntimeError) as exc:
            print('SITE_MANAGER=STOP ' + str(exc), file=sys.stderr)
            return 2
    return deploy_main(target)


if __name__ == '__main__':
    raise SystemExit(main())
