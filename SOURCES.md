# Основания и внешние источники

Изменения 1.2.0 выполнены на базе предыдущей пользовательской node-only поставки.
Из неё сохранены механика установки, проверки и Selfsteal TCP-target. Прежние IP-пресеты
и рабочие пользовательские credentials не включены в публичный репозиторий.
Другие установщики не встраиваются и не запускаются; пример eGamesAPI использован
как образец способа запуска по raw-ссылке, не как источник исполняемого кода.

Внешние страницы, просмотренные 25 сентября 2026:

- Remnawave Node: назначение Node Port, создание карточки, выбор профиля, ограничение доступа панели:
  https://docs.rw/install/remnawave-node/
- Пример запуска, указанный пользователем:
  https://raw.githubusercontent.com/eGamesAPI/remnawave-reverse-proxy/refs/heads/main/install_remnawave.sh
- curl: флаги fail/show-error/location и ограничения кодов возврата:
  https://curl.se/docs/manpage.html
- Создание GitHub repository:
  https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository
- Загрузка файлов; при web upload .gitattributes не применяется:
  https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository
- Let's Encrypt HTTP-01: требование внешнего порта 80:
  https://letsencrypt.org/docs/challenge-types/
- Закреплённый checkout action (v4.2.2; не утверждается, что это последняя версия):
  https://github.com/actions/checkout/releases/tag/v4.2.2

Перечень источников не означает проверку развёртывания на реальной VPS. Запуск по GitHub URL
проверялся на локальном HTTP-сервере только для безопасных сценариев --help/ошибок загрузки.
Сборщик ввода и дальнейшая передача проверялись отдельно с синтетическими credentials.
