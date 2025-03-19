# Rust Implementation of WireGuard

## Usage

Create your configuration file wg.conf

```conf
[Interface]
PrivateKey = <your private key>
Address = 10.0.0.1/24
DNS = 8.8.8.8

[Peer]
PublicKey = <peer public key>
AllowedIPs = 0.0.0.0/1,128.0.0.0/1
Endpoint = <peer endpoint>
PersistentKeepalive = 25
```

If you are using Windows, please copy [wintun.dll](https://www.wintun.net) to the executable file directory. Then specify the configuration file to start under administrator privileges.

```bash
wireguard -c wg.conf
```
