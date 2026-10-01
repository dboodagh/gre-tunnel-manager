# GRE Tunnel Manager

Manage multiple IPv4 GRE tunnels and TCP/UDP port forwarding on Ubuntu 24.04 or higher. Connect one main entry server to several remote VPN servers, with editable addresses, ports, and persistent settings.

The launcher is one Bash file, `GRETUN.sh`, containing a Python 3 standard-library core. No Python packages are needed. This configures GRE and iptables;

## Features

- Add, edit, inspect, and remove individual tunnels from a terminal menu.
- Choose local and remote outer IPv4 addresses and a separate inner /30 subnet per tunnel.
- Forward TCP, UDP, or both, with optional port translation.
- Forward to the **remote GRE address**, correcting the original script's local-address DNAT error.
- Save profiles as JSON and restore them at boot through systemd.
- Preserve other firewall chains, and reject conflicting port mappings.
- Import the original `/etc/gre-tunnel.conf` and reuse its matching `gre1` interface.
- Back up edited configuration and installed files.

The chosen local outer IP must already belong to the server's selected network interface. This tool does not change the provider-assigned address.

## Install on Ubuntu

Run these commands on each Ubuntu server. Servers require systemd, root access, and provider support for GRE (IP protocol 47).

```bash
sudo apt-get update &&
sudo apt-get install -y curl python3 iproute2 iptables
```

Download to a regular file:

```bash
curl -fL --retry 3 \
  https://raw.githubusercontent.com/dboodagh/gre-tunnel-manager/main/GRETUN.sh \
  -o GRETUN.sh
```

After the download succeeds, for a **fresh installation**:

```bash
sudo bash GRETUN.sh --install &&
sudo /usr/local/bin/gre.sh
```

Choose **1) Add tunnel**, fill in the settings, and confirm Save and apply. After adding your profiles:

```bash
sudo systemctl restart gre-tunnel.service
sudo /usr/local/bin/gre.sh --status
```

**Already using the original script?** Follow [migration instructions](docs/INSTALL.md#migrate-from-the-original-single-tunnel-script) before creating a new profile over the existing tunnel.

Do not use `curl | bash` or `bash <(curl ...)`: installation copies the saved script to `/usr/local/bin/gre.sh`, so it needs a regular source file.

## Forwarding ports

Enter this to forward both TCP and UDP without changing their ports:

```text
1402,4567
```

Or choose protocol and translate an external port:

```text
tcp:1402,udp:1533:1402
```

Here, external UDP 1533 forwards to remote UDP 1402. Use `none` to disable forwarding for a profile.

On the remote VPN server, set public forwarding to `none` and allow the local VPN listener using **Local service ports to allow over GRE**, for example `1402`.

The OpenVPN client's `remote` must use the Iran server's public IP and external port. The client protocol must match the actual server listener. Forwarding both protocols does not enable a missing listener or repair SoftEther's DHCP/NAT settings.

## Multiple remote servers

Create one profile per remote server on Iran and a reverse profile on each remote server:

- First remote: inner addresses `10.10.10.1/30` and `10.10.10.2`.
- Second remote: inner addresses `10.10.20.1/30` and `10.10.20.2`.
- Third remote: inner addresses `10.10.30.1/30` and `10.10.30.2`.

Reverse the local/remote addresses at the other endpoint. Each connection needs a unique subnet and interface on the Iran server. Each external port/protocol on the same public IP can point to only one destination; port translation lets different remote servers use the same internal VPN port.

See the [full setup guide](docs/INSTALL.md#connect-multiple-remote-servers-to-one-iran-server) for both endpoints, saved JSON, migration, verification, and troubleshooting details. Public IP addresses in the guide are placeholders.

## Manage saved settings

```bash
sudo /usr/local/bin/gre.sh           # Menu: add/edit/remove
sudo /usr/local/bin/gre.sh --check   # Validate saved configuration
sudo /usr/local/bin/gre.sh --apply   # Apply all profiles
sudo /usr/local/bin/gre.sh --status  # Inspect current state
```

- Profiles: `/etc/gre-manager/tunnels/<name>.json`
- Backups: `/etc/gre-manager/backups/`
- Startup service: `gre-tunnel.service`

Use the menu to change addresses or ports. Changing endpoints can interrupt sessions; reconnect clients afterward. Configure corresponding settings at both endpoints. Stopping the service leaves live networking in place; remove a profile through the menu to remove its tunnel and managed rules.

## Update

Download the new `GRETUN.sh` using the command above. After a successful download:

```bash
sudo bash GRETUN.sh --install &&
sudo /usr/local/bin/gre.sh --check &&
sudo systemctl restart gre-tunnel.service
```

Saved profiles are retained. Review changes before updating a working server. For a fixed version, replace `main` in the download URL with a published tag or commit SHA.

## Development and checks

```bash
bash -n GRETUN.sh
bash GRETUN.sh --help
python3 -m unittest discover -s tests -v
```

GitHub Actions runs these checks on Ubuntu 24.04. Tests extract the embedded Python from the shipped script and mock network commands; they do not alter the host firewall. They cover multiple tunnels, repeat application, port conflicts, migration, editing, removal, and installation.

Live Linux packet forwarding, reboot behavior, and SoftEther interoperability have not been verified by this test suite. GRE provides encapsulation without encryption; the VPN protocol supplies encryption.

## Background

This manager was developed to replace the single-tunnel workflow in [diyakou/GRE-TUN](https://github.com/diyakou/GRE-TUN), adding per-tunnel configuration and correcting the forwarding destination.
