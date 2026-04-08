<img src="https://gist.githubusercontent.com/avbor/1f8a128e628f47249aae6e058a57610b/raw/19013276c035e91058e0a9799ab145f8e70e3ff5/scheme.svg">

## Concept
- **Server A** (_e.g., RU_):\
  Entry point, accepts Telegram proxy user traffic via **HAProxy** (port `443\tcp`)\
  and sends it through the local **Xray** client (port `10443\tcp`) to Server **B**.\
  Public port for HAProxy clients — `443\tcp`
- **Server B** (_e.g., NL_):\
  Exit point, runs the **Xray server** (to terminate the tunnel entry point) and **telemt**.\
  The server must have unrestricted access to Telegram Data Centers.\
  Public port for VLESS/REALITY (incoming) — `443\tcp`\
  Internal telemt port (where decrypted Xray traffic ends up) — `8443\tcp`

The tunnel works over the `VLESS-XTLS-Reality` (or `VLESS/xhttp/reality`) protocol. The original client IP address is preserved thanks to the PROXYv2 protocol, which HAProxy prepends before passing to Xray, and which transparently reaches telemt.

---

## Step 1. Setup Xray Tunnel (A <-> B)

You must install **Xray-core** (version 1.8.4 or newer recommended) on both servers.
Official installation script (run on both servers):
```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
```

### Key and Parameter Generation (Run Once)
For configuration, you need a unique UUID and Xray Reality keys. Run on any server with Xray installed:
1. **Client UUID:**
```bash
xray uuid
# Save the output (e.g.: 12345678-abcd-1234-abcd-1234567890ab) — this is <XRAY_UUID>
```
2. **X25519 Keypair (Private & Public) for Reality:**
```bash
xray x25519
# Save the Private key (<SERVER_B_PRIVATE_KEY>) and Public key (<SERVER_B_PUBLIC_KEY>)
```
3. **Short ID (Reality identifier):**
```bash
openssl rand -hex 16
# Save the output (e.g.: 0123456789abcdef0123456789abcdef) — this is <SHORT_ID>
```

---

### Configuration for Server B (_EU_):

Create or edit the file `/usr/local/etc/xray/config.json`.
This Xray instance will listen on the public `443` port and proxy valid Reality traffic, while routing "disguised" traffic (e.g., direct web browser scans) to `yahoo.com`.

```bash
nano /usr/local/etc/xray/config.json
```

File content:
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

Open the firewall port (if enabled):
```bash
sudo ufw allow 443/tcp
```
Restart and setup Xray to run at boot:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

### Configuration for Server A (_RU_):

Similarly, edit `/usr/local/etc/xray/config.json`.
Here Xray acts as a local client: it listens on `10443\tcp` (for traffic from HAProxy), encapsulates it via Reality to Server B, and instructs Server B to deliver it to its *local* `127.0.0.1:8443` port (where telemt will listen).

```bash
nano /usr/local/etc/xray/config.json
```

File content:
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
*Replace `<PUBLIC_IP_SERVER_B>` with the public IP address of Server B.*

Restart and setup Xray to run at boot:
```bash
sudo systemctl restart xray
sudo systemctl enable xray
```

---

## Step 2. Setup HAProxy on Server A (_RU_)

HAProxy will run on the public port `443` of Server A, receive incoming connections from Telegram users, attach a `PROXYv2` header (to forward the true user IP) and send the stream to the local Xray client.
Docker installation is like the [AmneziaWG instructions](./VPS_DOUBLE_HOP.en.md).

> [!WARNING]
> If you don't run as `root` or have issues with binding to port `443` (`cannot bind socket`), allow unprivileged usage:
> ```bash
> echo "net.ipv4.ip_unprivileged_port_start = 0" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
> ```

#### Create HAProxy Directory:
```bash
mkdir -p /opt/docker-compose/haproxy && cd $_
```

#### Create `docker-compose.yaml`
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

#### Create HAProxy Config `haproxy.cfg`
```haproxy
global
    # Disable connection logs under high load
    log stdout format raw local0 err
    maxconn 250000
    # Use all CPU threads
    nbthread 2
    # Tune buffers and socket limits
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
    # Fast drop dead peers
    timeout client-fin 10s
    timeout server-fin 10s

frontend proxy_in
    bind *:443
    maxconn 250000
    option tcp-smart-accept
    default_backend telemt_backend

backend telemt_backend
    option tcp-smart-connect
    # Send-Proxy-V2 is strictly required for telemt IP masking to function over Xray correctly!
    server telemt_core 127.0.0.1:10443 maxconn 250000 send-proxy-v2 check inter 5s

```
>[!WARNING]
>**The configuration file must end with an empty newline, otherwise HAProxy fails to start!**

#### Start the HAProxy Container
Allow port `443\tcp` in your firewall and launch Docker compose:
```bash
sudo ufw allow 443/tcp
docker compose up -d
```

---

## Step 3. Install telemt on Server B (_EU_)

telemt installation is heavily covered in the [Quick Start Guide](../QUICK_START_GUIDE.en.md).
By contrast to standard setups, telemt must listen strictly _locally_ (since Xray occupies the public `443` interface) and must expect `PROXYv2` packets.

Edit the configuration file (`config.toml`) on Server B accordingly:

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

- Address `127.0.0.1` and `port = 8443` instructs the core proxy router to process connections unpacked locally via Xray-server.
- `proxy_protocol = true` commands telemt to parse the injected PROXY header (from Server A's HAProxy) and log genuine end-user IPs.
- Under `public_host`, place Server A's public IP address or FQDN to ensure working links are generated for Telegram users.

Restart `telemt`. Your server is now robust against DPI scanners, passing traffic optimally.

