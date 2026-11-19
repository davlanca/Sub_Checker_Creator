# Sub Checker Creator

[Русский](#русский) | [English](#english)

Автоматическая проверка живых конфигов VLESS / VMess / Trojan / Shadowsocks / Hysteria2 из публичных подписок - с проверкой из России.

Сайт со списком и замерами:

```
https://davlanca.github.io/Sub_Checker_Creator/
```

---

<a id="русский"></a>
## Русский

### Что это

Sub Checker Creator собирает конфиги из подписок, проверяет каждый настоящим подключением и отдаёт только живые. Проверка идёт в два этапа: сначала подключение через Xray из дата-центра, потом проверка доступности из России. Живые конфиги попадают в файлы, которые можно подключить как подписку в v2box, v2rayNG или другом клиенте.

### Как это работает

1. Ссылки на подписки берутся из `LINK_PATH` в `cl.py`.
2. Дедуп: один конфиг на связку (протокол, хост, порт) - дубли не попадают в списки.
3. Connection-тест: полное рукопожатие через Xray и запрос к тестовому адресу. Это честная проверка: просто открытый порт (TCP) доказывает только порт, а не рабочий туннель.
4. Проверка из России: check-host.net, узлы Москва и Санкт-Петербург (TCP-connect). Проверка идёт сразу после замера, без кэша, поэтому `final.txt` наполняется с первых минут прогона.
5. Постепенное обновление: старый сервер остаётся в списке, пока прогон его не перепроверит. Один неудачный замер не удаляет сервер сразу.

Пример воронки одного из прогонов: около 310 уникальных конфигов - около 52 живых через прокси - 14-15 в строгом `final.txt`. Прогон 40: 7 мин 53 сек, `final` 110, `final_all` 197.

### Файлы на выходе

| Файл | Что внутри |
| --- | --- |
| `final.txt` | Строгий список: живые через прокси и доступные из России |
| `final_NoRus.txt` | Живые через прокси, но недоступные из России |
| `final_all.txt` | Все живые из дата-центра |
| `results.json` | Полный аудит: пинг, скорость, вердикт по России |
| `vless.txt`, `vmess.txt`, `trojan.txt`, `ss.txt`, `hy2.txt` | Живые конфиги по протоколам |
| `*_b64.txt` | Те же списки в base64, для подписки |
| `ru_check_cache.json` | Кэш проверки из России |

### Сайт

```
https://davlanca.github.io/Sub_Checker_Creator/
```

Таблица из `final.txt` и замеры из `results.json`. Перед проверкой с телефона выключи VPN. Живые конфиги можно скачать прямо с сайта.

### Как пользоваться

1. Возьми `final.txt` как подписку в v2box (или скачай конфиги с сайта).
2. Проверь с телефона: тест в v2box - истина, серверный список - только предфильтр.
3. Один таймаут - не значит мёртвый сервер: серверы мигают между прогонами и тестами на телефоне.

### Честные оговорки

- Бесплатные списки живут часами: толпы подключаются, ключи меняются, серверы умирают и блокируются. Выживаемость 20-60 из 100 в дата-центре - норма для такого источника, а не баг чекера.
- Проверка из России (Москва, Санкт-Петербург) не предсказывает мобильный Билайн: Билайн на тетеринге режет VLESS-хендшейк через DPI. Сервер может быть живым в прогоне и не подключаться с телефона - и наоборот.
- Прогон занимает не больше часа, обычно 45-55 минут.

### Свой форк

1. Сделай Fork репозитория.
2. Включи Actions в своём форке.
3. Добавь свои ссылки в `LINK_PATH` в `cl.py`.
4. Настройки теста - в `config.json`: URL теста, Fragment, Warp-on-Warp и другое.
5. Запуск - внешним триггером с cron-job.org (`repository_dispatch`, тип `external_cron_trigger`). Встроенный крон GitHub не используется.
6. Не пушь `cl.py`, пока идёт прогон.
7. Файлы workflow (`.github/workflows/`) через API не правятся - только в веб-интерфейсе GitHub.

### Разработка

- PowerShell: UTF-8 без BOM, скрипты `.ps1` - только inline через `-Command`.
- Дедуп: один конфиг на (протокол, хост, порт).
- Постепенное обновление списков: сервер уходит из списка только после перепроверки.

### Происхождение

Форк upstream-проекта Sub Checker. Идея: [M-logique/Proxies](https://github.com/M-logique/Proxies). Лицензия: GPL-3.0.

---

<a id="english"></a>
## English

### What it is

Sub Checker Creator collects configs from subscription links, checks each one with a real connection, and publishes only the live ones. Checks run in two stages: first a connection through Xray from the datacenter, then an availability check from Russia. Live configs go into files you can use as a subscription in v2box, v2rayNG or any other client.

### How it works

1. Subscription links come from `LINK_PATH` in `cl.py`.
2. Dedup: one config per (protocol, host, port) - no duplicates in the lists.
3. Connection test: a full handshake through Xray plus a request to a test address. This is an honest check: an open port (TCP) only proves the port, not a working tunnel.
4. Russia check: check-host.net, Moscow and Saint Petersburg nodes (TCP-connect). It runs right after each measurement, with no cache, so `final.txt` starts filling from the first minutes of a run.
5. Gradual updates: an old server stays in the list until a run rechecks it. One failed measurement does not remove a server at once.

Example funnel from one run: about 310 unique configs - about 52 alive through the proxy - 14-15 in the strict `final.txt`. Run 40: 7m 53s, `final` 110, `final_all` 197.

### Output files

| File | Contents |
| --- | --- |
| `final.txt` | Strict list: alive through the proxy and reachable from Russia |
| `final_NoRus.txt` | Alive through the proxy, but not reachable from Russia |
| `final_all.txt` | All live configs from the datacenter |
| `results.json` | Full audit: ping, speed, Russia verdict |
| `vless.txt`, `vmess.txt`, `trojan.txt`, `ss.txt`, `hy2.txt` | Live configs per protocol |
| `*_b64.txt` | Same lists in base64, for subscription |
| `ru_check_cache.json` | Russia check cache |

### Website

```
https://davlanca.github.io/Sub_Checker_Creator/
```

A table from `final.txt` and measurements from `results.json`. Turn off your VPN before checking from your phone. Live configs can be downloaded right from the site.

### How to use

1. Use `final.txt` as a subscription in v2box (or download configs from the site).
2. Check from your phone: the v2box test is the truth, the server list is only a prefilter.
3. One timeout does not mean a dead server: servers flap between runs and phone tests.

### Honest caveats

- Free lists live for hours: crowds join, keys change, servers die and get blocked. A 20-60 out of 100 survival rate in the datacenter is normal for this kind of source, not a checker bug.
- The Russia check (Moscow, Saint Petersburg) does not predict mobile Beeline: Beeline on tethering cuts the VLESS handshake with DPI. A server can be alive in a run and fail on the phone - and vice versa.
- A run takes at most an hour, usually 45-55 minutes.

### Your own fork

1. Fork the repository.
2. Enable Actions in your fork.
3. Add your links to `LINK_PATH` in `cl.py`.
4. Test settings live in `config.json`: test URL, Fragment, Warp-on-Warp, and more.
5. Runs are triggered externally from cron-job.org (`repository_dispatch`, type `external_cron_trigger`). GitHub's built-in cron is not used.
6. Do not push `cl.py` while a run is in progress.
7. Workflow files (`.github/workflows/`) cannot be edited through the API - only in the GitHub web interface.

### Development

- PowerShell: UTF-8 without BOM, `.ps1` scripts only inline via `-Command`.
- Dedup: one config per (protocol, host, port).
- Gradual list updates: a server leaves a list only after being rechecked.

### Credits

A fork of the upstream Sub Checker project. Idea: [M-logique/Proxies](https://github.com/M-logique/Proxies). License: GPL-3.0.
