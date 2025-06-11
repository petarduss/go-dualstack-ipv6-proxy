# 🌐 go-dualstack-ipv6-proxy

**go-dualstack-ipv6-proxy** is a high-performance HTTP/HTTPS proxy server written in Go, designed to handle incoming IPv4 and IPv6 requests and forward them through **randomized IPv6 addresses** from a user-defined pool. This makes it especially useful for applications that benefit from IP rotation over IPv6 networks.

---

## 🚀 Features

- 🔁 **Dual-stack support**: Accepts both IPv4 and IPv6 connections
- 🧠 **IPv6 randomization**: Routes traffic through randomly chosen IPv6 addresses from defined subnets
- 🔐 **HTTPS support**: Easily enable TLS with your own certs
- 🛡️ **IP filtering**: Simple allowlist-based access control
- ⚙️ **Highly configurable**: All major settings controlled via `config.toml`
- 📈 **High throughput**: Supports thousands of concurrent connections

---

## 🛠️ Configuration

Create a configuration file in `TOML` format (e.g., `config.toml`) as shown below:

```toml
[server]
listen_port = "8080"                # HTTP port
listen_port_https = "9999"          # HTTPS port
max_connections = 10000             # Maximum number of simultaneous connections
idle_timeout_seconds = 90           # Idle connection timeout
read_timeout_seconds = 30           # Read timeout for each connection

[ssl]
enabled = true                      # Enable HTTPS
cert_path = "/root/ipv6-proxy/cert/cert.pem"
key_path = "/root/ipv6-proxy/cert/key.pem"

[authorization]
allowed_ips = [
    "*"                             # Allow all incoming IPs (use specific IPs or CIDRs to restrict)
]

[ipv6_pools]
subnets = [
    "2a14:7584:44b3:0::/118"        # IPv6 subnet to use for outgoing connections
]
addresses_per_subnet = 1000        # Number of random addresses to generate per subnet

exclude = [
    "::1"                           # IPv6 addresses to exclude from the pool
]
```

---

## 📦 Installation

```bash
git clone https://github.com/petarduss/go-dualstack-ipv6-proxy.git
cd go-dualstack-ipv6-proxy
go build -o ipv6-proxy main.go
```

Or with Go modules:

```bash
go install github.com/petarduss/go-dualstack-ipv6-proxy@latest
```

---

## ▶️ Usage

After building, run the proxy server:

```bash
./ipv6-proxy
```

---

## 🔧 Requirements

- Go 1.21
- Properly configured IPv6 addresses on your system
- A valid SSL certificate and private key (if HTTPS is enabled)

---

## 📋 License

MIT License. See [LICENSE](./LICENSE) for details.

---

## 🙌 Contributing

Pull requests are welcome! If you encounter issues or have suggestions, feel free to open an issue or contribute directly.

---

## 📣 Disclaimer

⚠️ Use this tool responsibly. Ensure compliance with your hosting provider's policies and all applicable laws regarding IP rotation and proxy usage.

---

Made with 💻 by petarduss
