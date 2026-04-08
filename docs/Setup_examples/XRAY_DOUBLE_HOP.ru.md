<img src="https://gist.githubusercontent.com/avbor/1f8a128e628f47249aae6e058a57610b/raw/19013276c035e91058e0a9799ab145f8e70e3ff5/scheme.svg">

## Концепция
- **Сервер A** (_РФ_):\
  Точка входа, принимает трафик пользователей Telegram-прокси через **HAProxy** (порт `443\tcp`)\
  и отправляет его через локальный клиент **Xray** (порт `10443\tcp`) на Сервер **B**.\
  Порт для клиентов HAProxy — `443\tcp`
- **Сервер B** (_условно Нидерланды_):\
  Точка выхода, на нем работает **Xray-сервер** (принимает подключения точки входа) и **telemt**.\
  На сервере должен быть неограниченный доступ до серверов Telegram.\
  Порт для VLESS/REALITY (вход) — `443\tcp`\
  Внутренний порт telemt (куда пробрасывается трафик) — `8443\tcp`

Туннель работает по протоколу VLESS-XTLS-Reality (или VLESS/xhttp/reality). Оригинальный IP-адрес клиента сохраняется благодаря протоколу PROXYv2, который HAProxy добавляет перед отправкой в Xray, и который прозрачно доходит до telemt.

---

## Шаг 1. Настройка туннеля Xray (A <-> B)

На обоих серверах необходимо установить **Xray-core** (рекомендуется версия 1.8.4 или новее).
Официальный скрипт установки (выполнить на обоих серверах):
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

### Генерация ключей и параметров (выполнить один раз)
Для конфигурации потребуются уникальные ID и ключи Xray Reality. Выполните на любом сервере с установленным Xray:
1. **UUID клиента:**
```bash
xray uuid
# Сохраните вывод (например: 12345678-abcd-1234-abcd-1234567890ab) — это <XRAY_UUID>
```
2. **Пара ключей X25519 (Private & Public) для Reality:**
```bash
xray x25519
# Сохраните Private key (<SERVER_B_PRIVATE_KEY>) и Public key (<SERVER_B_PUBLIC_KEY>)
```
3. **Short ID (идентификатор Reality):**
```bash
openssl rand -hex 16
# Сохраните вывод (например: 0123456789abcdef0123456789abcdef) — это <SHORT_ID>
```

---

### Конфигурация Сервера B (_Нидерланды_):

Создаем или редактируем файл `/usr/local/etc/xray/config.json`.
Этот Xray-сервер будет слушать порт `443` и прозрачно пропускать валидный Reality трафик дальше, а "замаскированный" трафик (например, если кто-то стучится в лоб веб-браузером) пойдет на `yahoo.com`.

```bash
nano /usr/local/etc/xray/config.json
```

Содержимое файла:
```json
{
  "log": {
    "loglevel": "error",
    "access": "none"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "<XRAY_UUID>"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "dest": "yahoo.com:443",
          "serverNames": [
            "yahoo.com"
          ],
          "privateKey": "<SERVER_B_PRIVATE_KEY>",
          "shortIds": [
            "<SHORT_ID>"
          ]
        },
        "xhttpSettings": {
          "mode": "auto",
          "path": "/api/v3/sync"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
```

Открываем порт на фаерволе (если включен):
```bash
sudo ufw allow 443/tcp
```
Перезапускаем Xray:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

### Конфигурация Сервера A (_РФ_):

Аналогично, редактируем `/usr/local/etc/xray/config.json`.
Здесь Xray выступает клиентом: он локально принимает трафик на порту `10443\tcp` (от HAProxy) и упаковывает его в Reality до Сервера B, прося тот доставить данные на *свой локальный* порт `127.0.0.1:8443` (именно там будет слушать telemt).

```bash
nano /usr/local/etc/xray/config.json
```

Содержимое файла:
```json
{
  "log": {
    "loglevel": "error",
    "access": "none"
  },
  "inbounds": [
    {
      "port": 10443,
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 8443,
        "network": "tcp"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "<PUBLIC_IP_SERVER_B>",
            "port": 443,
            "users": [
              {
                "id": "<XRAY_UUID>",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "serverName": "yahoo.com",
          "publicKey": "<SERVER_B_PUBLIC_KEY>",
          "shortId": "<SHORT_ID>",
          "spiderX": "",
          "fingerprint": "chrome"
        },
        "xhttpSettings": {
          "mode": "auto",
          "path": "/api/v3/sync",
          "xmux": {
            "maxConcurrency": 256
          }
        }
      }
    }
  ]
}
```
*Замените `<PUBLIC_IP_SERVER_B>` на внешний IP-адрес Сервера B.*

Перезапускаем Xray:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

## Шаг 2. Настройка HAProxy на Сервере A (_РФ_)

HAProxy будет висеть на публичном порту `443` Сервера A, принимать подключения от Telegram-клиентов, добавлять заголовок `PROXYv2` (чтобы пробросить реальный IP пользователя) и отправлять в локальный клиент Xray.
Установка Docker аналогична [инструкции AmneziaWG варианта](./VPS_DOUBLE_HOP.ru.md).

> [!WARNING]
> Если запускаете не под `root` или возникают проблемы с правами на `443` порт:
> ```bash
> echo "net.ipv4.ip_unprivileged_port_start = 0" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
> ```

#### Создаем папку для HAProxy:
```bash
mkdir -p /opt/docker-compose/haproxy && cd $_
```

#### Создаем файл `docker-compose.yaml`
```yaml
services:
  haproxy:
    image: haproxy:latest
    container_name: haproxy
    restart: unless-stopped
    # user: "root"
    network_mode: "host"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "1"
```

#### Создаем файл конфигурации `haproxy.cfg`
```haproxy
global
    # Отключить детальные логи соединений под нагрузкой
    log stdout format raw local0 err
    maxconn 250000
    # Использовать все ядра CPU
    nbthread 2
    # Тюнинг буферов и приема сокетов
    tune.bufsize 16384
    tune.maxaccept 64

defaults
    log     global
    mode    tcp
    option  clitcpka
    option  srvtcpka
    timeout connect 5s
    timeout client  1h
    timeout server  1h
    # Быстрая очистка мертвых пиров
    timeout client-fin 10s
    timeout server-fin 10s

frontend proxy_in
    bind *:443
    maxconn 250000
    option tcp-smart-accept
    default_backend telemt_backend

backend telemt_backend
    option tcp-smart-connect
    # Send-Proxy-V2 обязателен для сохранения IP клиента внутри внутренней логики Telemt
    server telemt_core 127.0.0.1:10443 maxconn 250000 send-proxy-v2 check inter 5s

```
>[!WARNING]
>**Файл должен заканчиваться пустой строкой, иначе HAProxy не запустится!**

#### Разрешаем порт `443\tcp` в фаерволе и запускаем контейнер
```bash
sudo ufw allow 443/tcp
docker compose up -d
```

---

## Шаг 3. Установка и настройка telemt на Сервере B (_Нидерланды_)

Установка telemt описана [в основной инструкции](../QUICK_START_GUIDE.ru.md).
Отличие в том, что telemt должен слушать *внутренний* порт (так как 443 занят Xray-сервером), а также ожидать `PROXY` протокол из Xray туннеля.

В конфиге `config.toml` прокси (на Сервере B) укажите:
```toml
[server]
port = 8443
listen_addr_ipv4 = "127.0.0.1"
proxy_protocol = true

[general.links]
show = "*"
public_host = "<FQDN_OR_IP_SERVER_A>"
public_port = 443
```

- `port = 8443` и `listen_addr_ipv4 = "127.0.0.1"` означают, что telemt принимает подключения только изнутри (приходящие от локального Xray-процесса).
- `proxy_protocol = true` заставляет telemt парсить PROXYv2-заголовок (который добавил HAProxy на Сервере A и протащил Xray), восстанавливая IP-адрес конечного пользователя (РФ).
- В `public_host` укажите публичный IP-адрес или домен Сервера A, чтобы ссылки на подключение генерировались корректно.

Перезапустите `telemt`, и клиенты смогут подключаться по выданным ссылкам.

