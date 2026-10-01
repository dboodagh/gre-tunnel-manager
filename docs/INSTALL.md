# GRE multi-server manager

This replaces the original single-tunnel menu with a manager for multiple named GRE tunnels. It is delivered as one executable Bash `.sh` file with an embedded Python 3 standard-library core. It requires no Python packages. It targets Ubuntu 24.04 with systemd, iproute2 and iptables (including Ubuntu's iptables-nft backend).

## Features

- Add and edit both outer IPv4 endpoints and both inner GRE IPv4 addresses.
- Choose a public network interface and a separate /30 subnet and GRE interface per connection.
- Forward TCP, UDP, or both; optionally translate the external port to a different remote port.
- Allow selected local services on the receiving server's GRE interface.
- Save each profile separately as root-readable JSON, with configuration backups.
- Check for conflicting configured ports, overlapping subnets, unowned interfaces, and reachable external DNAT/REDIRECT rules such as XRayMesh mappings.
- Reuse a matching tunnel; changing its configured endpoints uses `ip tunnel change`, not deletion/recreation. Address or port edits can still interrupt that tunnel's sessions.
- Rebuild only the manager's `GREMGR_*` firewall chains using `iptables-restore --noflush`. Other chains and policies are retained. Check-before-insert keeps hook rules from accumulating.
- Import the original `/etc/gre-tunnel.conf` and adopt its existing `gre1` interface.
- Install atomically from a regular saved file. Reinstalling from the installed path works. Empty files and process-substitution pipes are rejected.

## Install dependencies if needed

Run on the Ubuntu server, not on macOS:

```bash
sudo apt-get update
sudo apt-get install -y python3 iproute2 iptables
```

The manager does not download or install packages automatically.

## Fresh installation

Follow the download and installation commands in [README.md](../README.md#install-on-ubuntu).
Configure both endpoints. Installing the service enables startup; adding a profile through the menu saves and applies it immediately. After configuring profiles, run:

```bash
sudo systemctl restart gre-tunnel.service
sudo systemctl status gre-tunnel.service --no-pager -l
```

## Migrate from the original single-tunnel script

Use this path when the server already has `/etc/gre-tunnel.conf` and an existing `gre1`. Download `GRETUN.sh` as shown in the README, then import before installing:

```bash
sudo bash GRETUN.sh --import-legacy turkey &&
sudo bash GRETUN.sh --check &&
sudo bash GRETUN.sh --install &&
sudo systemctl restart gre-tunnel.service
```

Replace `turkey` with the desired profile name. If already imported, use the menu's Edit action instead of importing twice. On the receiving server, import its own original configuration if present; otherwise create the reverse profile as described below. Configure its local service ports using Edit after the first successful Apply.

Import keeps the original configuration file. The first successful Apply adopts the matching existing interface and removes exact legacy forwarding rules for that profile after replacement rules are active. This includes the old local-IP DNAT bug. Other XRayMesh mappings remain. Legacy general GRE allow rules and global TCP tuning are not removed.

The manager uses the existing `gre-tunnel.service` name, with no tunnel-deleting ExecStop. Check Apply and VPN connectivity before rebooting.

## Open the menu

```bash
sudo /usr/local/bin/gre.sh
```

The menu supports Add, Edit, Status, Apply, Remove one tunnel, Import legacy, Install/update startup service, and Show saved JSON. Edits and removal ask for confirmation because they can interrupt the selected connection. Running `--apply` restores all saved profiles without prompting.

The local outer/public IP must already be assigned to the chosen interface. The manager selects that IP as the tunnel source; it does not reconfigure the server's physical NIC or provider-assigned address.

## Port syntax

Enter comma-separated mappings:

```text
1402,4567
```

This forwards both TCP and UDP on each port without changing its number.

```text
tcp:1402,udp:1533:1402
```

This forwards external TCP 1402 to peer TCP 1402, and external UDP 1533 to peer UDP 1402. Enter `none` to clear forwarding.

Each `(public interface, local outer IP, protocol, external port)` can have only one destination. Two remote OpenVPN servers can both listen on 1402, but their entry ports on the same Iran IP must differ. For example, one can use `tcp:1402:1402`, and another `tcp:1533:1402`.

This only configures GRE, routing, and iptables. SoftEther/OpenVPN must already be installed, enabled, and listening on the target port and GRE address (or all addresses). The client's `remote` uses Iran's public IP and the external port; its `proto` must match. SoftEther DHCP gateway/NAT configuration is separate.

## Connect multiple remote servers to one Iran server

Use one profile and a unique /30 subnet for each remote server. Add profiles through menu option 1; keep any existing profiles. For example, on Iran:

- Name: `germany`.
- Interface: `gre-germany` (the suggested default).
- Public interface: `eth0`.
- Local outer IP: `198.51.100.10`.
- Remote outer IP: the new Germany server's actual public IPv4.
- Local GRE: `10.10.20.1/30`.
- Remote GRE: `10.10.20.2`.
- MTU: 1400.
- Forwarded ports: `tcp:1533:1402,udp:1533:1402`, provided 1533 is not already used by XRayMesh or another forwarding rule.
- Local services to allow from GRE: `none`.

On the Germany server, save/install the same manager and add the reverse connection:

- Name: `iran`.
- Interface: `gre-iran`.
- Public interface: its actual public NIC.
- Local outer IP: Germany's actual public IPv4.
- Remote outer IP: `198.51.100.10`.
- Local GRE: `10.10.20.2/30`.
- Remote GRE: `10.10.20.1`.
- MTU: 1400.
- Forwarded public ports: `none`.
- Local services to allow from GRE: `1402` (allows both protocols).

The inner addresses must be reversed on the two endpoints. A third server needs another unique /30, such as `10.10.30.1/30` and `10.10.30.2`. Interface names need not be the same on both machines.

The receiving server does not need public-to-GRE forwarding back to Iran. It needs its VPN listener and its own VPN internet routing/NAT. Upstream/provider firewalls must allow GRE, IP protocol 47, between the outer endpoints; GRE is not TCP or UDP port 47. GRE itself does not encrypt traffic; OpenVPN supplies VPN encryption.

## Configuration and persistence

- Executable: `/usr/local/bin/gre.sh`.
- Profiles: `/etc/gre-manager/tunnels/<name>.json`.
- Backups: `/etc/gre-manager/backups/`.
- Service: `/etc/systemd/system/gre-tunnel.service`.
- Forwarding sysctl: `/etc/sysctl.d/90-gre-manager.conf`.

A profile uses these fields (example only):

```json
{
  "name": "germany",
  "interface": "gre-germany",
  "wan_interface": "eth0",
  "local_public_ip": "198.51.100.10",
  "remote_public_ip": "192.0.2.20",
  "local_gre_cidr": "10.10.20.1/30",
  "remote_gre_ip": "10.10.20.2",
  "mtu": 1400,
  "ttl": 255,
  "forwards": [
    {"protocol": "tcp", "listen_port": 1533, "target_port": 1402},
    {"protocol": "udp", "listen_port": 1533, "target_port": 1402}
  ],
  "accept_ports": [],
  "adopt_existing": false
}
```

All public IPs in this guide are documentation examples. Replace them with your actual server IPs. Prefer the menu to edit profiles. If editing JSON manually, keep its filename and `name` aligned, do not rename the managed interface, and run:

```bash
sudo /usr/local/bin/gre.sh --check
sudo /usr/local/bin/gre.sh --apply
```

`--check` validates configuration only; `--apply` also checks live addresses, routes, ownership and firewall conflicts. Apply tests generated firewall syntax before changing tunnels. Each firewall table commits separately; this is not a global transactional change across all Linux networking. The interactive editor attempts to restore the prior profile if applying a change fails. Inspect errors before rebooting.

External firewall tools can still replace or reorder rules later. This manager does not take ownership of XRayMesh, UFW, or provider firewalls. It does not flush their chains, replace default routes, or apply the old script's global BBR/buffer tuning. TCP MSS clamping is limited to managed GRE interfaces.

Removing a profile through the menu deletes only its marked interface, removes its managed rules, and saves a configuration backup. Stopping the systemd oneshot service intentionally leaves active networking in place; use the menu to remove a connection.

## Verification

```bash
sudo /usr/local/bin/gre.sh --status
sudo ip -d tunnel show
sudo iptables -t nat -S GREMGR_DNAT
sudo journalctl -u gre-tunnel.service -n 50 --no-pager
ping -c 4 10.10.10.2
```

An UP interface is not a reachability test. Check GRE ping, then reconnect OpenVPN and test internet access. Rules for existing conntrack sessions can continue using their previous translation until those sessions close; reconnect after changing ports or endpoints.

Validation performed before delivery: Bash syntax, embedded Python compilation, CLI help, and mocked network tests covering import, two-server startup, repeat application, conflict rejection, edited endpoints/subnets/ports, old-rule migration, targeted removal, and same-file installation. These are mocked tests, not live Linux forwarding, reboot, throughput, or SoftEther interoperability tests.

References: [ip-tunnel](https://man7.org/linux/man-pages/man8/ip-tunnel.8.html), [iptables-restore](https://man7.org/linux/man-pages/man8/iptables-restore.8.html).
