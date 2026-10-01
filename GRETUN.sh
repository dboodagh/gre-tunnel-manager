#!/bin/bash
# GRE_MULTI_MANAGER_V1
# Requires Ubuntu/Linux, Bash, Python 3, iproute2, iptables and systemd.
# Save to a regular file before --install; never pipe this into bash.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
command -v python3 >/dev/null || { echo 'Install python3 first.' >&2; exit 1; }
IFS= read -r -d '' GRE_MANAGER_CODE <<'GRE_MANAGER_PYTHON' || true
"""GRE manager core, embedded in GRETUN.sh. Python standard library only."""
import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path('/etc/gre-manager')
PROFILES = ROOT / 'tunnels'
BACKUPS = ROOT / 'backups'
INSTALLED = Path('/usr/local/bin/gre.sh')
UNIT = Path('/etc/systemd/system/gre-tunnel.service')
LEGACY = Path('/etc/gre-tunnel.conf')
MARKER = 'gre-manager:'
SERVICE = 'gre-tunnel.service'
SOURCE = None

class Error(Exception):
    pass

def run(args, check=True, data=None):
    p = subprocess.run([str(x) for x in args], input=data, text=True, capture_output=True)
    if check and p.returncode:
        raise Error(f"Command failed: {shlex.join([str(x) for x in args])}\n{p.stderr.strip() or p.stdout.strip()}")
    return p

def ip_json(*args):
    return json.loads(run(['ip', '-j', *args]).stdout or '[]')

def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def backup(path):
    if path.exists():
        BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
        dest = BACKUPS / (path.name + '.' + str(time.time_ns()))
        shutil.copy2(path, dest)
        os.chmod(dest, 0o600)
        return dest

def ipv4(value):
    try:
        addr = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise Error(f'Invalid IPv4 address: {value}')
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback or int(addr) == 0xffffffff:
        raise Error(f'Unusable tunnel address: {value}')
    return str(addr)

def port(value):
    if isinstance(value, bool) or not re.fullmatch(r'[0-9]{1,5}', str(value)) or not 1 <= int(value) <= 65535:
        raise Error(f'Invalid port: {value}')
    return int(value)

def parse_ports(text):
    """1402 => both protocols; tcp:1402 or udp:1533:1402."""
    result = []
    if not text.strip() or text.strip().lower() in ('none', '-'):
        return result
    for token in text.split(','):
        parts = token.strip().split(':')
        if len(parts) == 1:
            proto, ext, dest = 'both', parts[0], parts[0]
        elif len(parts) == 2:
            proto, ext = parts; dest = ext
        elif len(parts) == 3:
            proto, ext, dest = parts
        else:
            raise Error(f'Invalid port mapping: {token}')
        if proto not in ('tcp', 'udp', 'both'):
            raise Error('Protocol must be tcp, udp, or both.')
        for protocol in (('tcp', 'udp') if proto == 'both' else (proto,)):
            mapping = {'protocol': protocol, 'listen_port': port(ext), 'target_port': port(dest)}
            if mapping in result:
                continue
            if any(m['protocol'] == protocol and m['listen_port'] == mapping['listen_port'] for m in result):
                raise Error(f'Conflicting mapping: {token}')
            result.append(mapping)
    return result

def validate(p):
    if not isinstance(p, dict):
        raise Error('Profile must be a JSON object.')
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,9}', str(p.get('name', ''))):
        raise Error('Name: 1-10 lowercase letters/digits/_/-, starting with a letter.')
    for field in ('interface', 'wan_interface'):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', str(p.get(field, ''))):
            raise Error(f'Invalid {field}. Linux interface names may have at most 15 characters.')
    if p['interface'] in ('lo', 'gre0', 'gretap0', 'erspan0', p['wan_interface']):
        raise Error('Choose a dedicated GRE interface, not a physical or fallback interface.')
    p['local_public_ip'] = ipv4(p.get('local_public_ip'))
    p['remote_public_ip'] = ipv4(p.get('remote_public_ip'))
    if p['local_public_ip'] == p['remote_public_ip']:
        raise Error('Outer local and remote addresses must differ.')
    try:
        local = ipaddress.IPv4Interface(p['local_gre_cidr'])
        remote = ipaddress.IPv4Address(p['remote_gre_ip'])
    except (KeyError, ValueError, TypeError):
        raise Error('Invalid GRE address. Use local CIDR such as 10.10.10.1/30.')
    if local.network.prefixlen != 30:
        raise Error('Use a separate /30 subnet for each GRE tunnel.')
    if any(ipaddress.IPv4Address(p[k]) in local.network for k in ('local_public_ip','remote_public_ip')):
        raise Error('Outer endpoints must not be inside the GRE /30 subnet.')
    hosts = list(local.network.hosts())
    if local.ip not in hosts or remote not in hosts or local.ip == remote:
        raise Error('Local and remote GRE addresses must be the two usable hosts in the same /30.')
    ipv4(str(local.ip)); ipv4(str(remote))
    if local.network.overlaps(ipaddress.IPv4Network('127.0.0.0/8')):
        raise Error('GRE subnet must not be loopback.')
    p['local_gre_cidr'], p['remote_gre_ip'] = str(local), str(remote)
    if not isinstance(p.get('mtu'), int) or isinstance(p['mtu'], bool) or not 576 <= p['mtu'] <= 1476:
        raise Error('MTU must be 576-1476; default 1400.')
    if not isinstance(p.get('ttl'), int) or isinstance(p['ttl'], bool) or not 1 <= p['ttl'] <= 255:
        raise Error('TTL must be 1-255.')
    mappings = p.get('forwards')
    if not isinstance(mappings, list):
        raise Error('forwards must be a list.')
    seen = set()
    for m in mappings:
        if not isinstance(m, dict) or m.get('protocol') not in ('tcp', 'udp'):
            raise Error('Invalid forwarding protocol.')
        m['listen_port'], m['target_port'] = port(m.get('listen_port')), port(m.get('target_port'))
        key = (m['protocol'], m['listen_port'])
        if key in seen:
            raise Error(f'Duplicate port mapping: {key}')
        seen.add(key)
    accepts = p.setdefault('accept_ports', [])
    if not isinstance(accepts, list):
        raise Error('accept_ports must be a list.')
    for m in accepts:
        if not isinstance(m, dict) or m.get('protocol') not in ('tcp', 'udp'):
            raise Error('Invalid local service protocol.')
        m['listen_port'], m['target_port'] = port(m.get('listen_port')), port(m.get('target_port'))
        if m['listen_port'] != m['target_port']:
            raise Error('Local service allow-list takes same-port entries, e.g. udp:1402, not translations.')
    if type(p.get('adopt_existing', False)) is not bool:
        raise Error('adopt_existing must be a boolean.')
    if p.get('legacy_cleanup'):
        if p['interface'] != 'gre1' or any(m['listen_port'] != m['target_port'] for m in mappings):
            raise Error('Import cleanup is only valid for original gre1 same-port mappings.')
    return p

def validate_all(profiles):
    names, ifaces, pairs, maps = set(), set(), set(), set()
    nets = []
    for p in profiles:
        validate(p)
        if p['name'] in names or p['interface'] in ifaces:
            raise Error('Each profile needs a unique name and GRE interface.')
        names.add(p['name']); ifaces.add(p['interface'])
        pair = (p['local_public_ip'], p['remote_public_ip'])
        if pair in pairs:
            raise Error('Only one unkeyed GRE tunnel per outer endpoint pair is supported.')
        pairs.add(pair)
        net = ipaddress.IPv4Interface(p['local_gre_cidr']).network
        if any(net.overlaps(other) for other in nets):
            raise Error(f'GRE subnets overlap: {net}')
        nets.append(net)
        for m in p['forwards']:
            key = (p['wan_interface'], p['local_public_ip'], m['protocol'], m['listen_port'])
            if key in maps:
                raise Error(f'External port is already assigned: {key}')
            maps.add(key)
    return profiles

def load_profiles():
    result = []
    for path in sorted(PROFILES.glob('*.json')):
        try:
            p = json.loads(path.read_text())
            validate(p)
            if path.stem != p['name']:
                raise Error(f'Filename/name mismatch in {path}')
            result.append(p)
        except (ValueError, OSError) as exc:
            raise Error(f'Cannot read {path}: {exc}')
    return validate_all(result)

def profile_path(p):
    return PROFILES / (p['name']+'.json')

def save_profile(p):
    validate(p)
    path = profile_path(p)
    backup(path)
    atomic_write(path, json.dumps(p, indent=2)+'\n')

def get_link(name):
    r = run(['ip', '-j', '-d', 'link', 'show', 'dev', name], check=False)
    if r.returncode:
        return None
    return json.loads(r.stdout)[0]

def check_external_port_conflicts(profiles):
    """Reject reachable DNAT/REDIRECT rules outside this manager for the same port."""
    chains = {}
    for line in run(['iptables-save', '-t', 'nat']).stdout.splitlines():
        if line.startswith('-A '):
            words = shlex.split(line)
            chains.setdefault(words[1], []).append(words[2:])
    pending, visited, relevant = ['PREROUTING'], set(), []
    while pending:
        chain = pending.pop()
        if chain in visited or chain.startswith('GREMGR_'):
            continue
        visited.add(chain)
        for rule in chains.get(chain, []):
            if '-j' not in rule:
                continue
            target = rule[rule.index('-j')+1]
            if target in ('DNAT', 'REDIRECT'):
                relevant.append(rule)
            elif target in chains:
                pending.append(target)
    def option(rule, key, default=None):
        return rule[rule.index(key)+1] if key in rule else default
    for p in profiles:
        for m in p['forwards']:
            for rule in relevant:
                if option(rule, '-i', p['wan_interface']) != p['wan_interface']:
                    continue
                if option(rule, '-p') not in (None, m['protocol']):
                    continue
                dst = option(rule, '-d')
                if dst and ipaddress.IPv4Address(p['local_public_ip']) not in ipaddress.IPv4Network(dst, strict=False):
                    continue
                match_ports = option(rule, '--dport', option(rule, '--dports'))
                if match_ports:
                    covered = False
                    for item in match_ports.split(','):
                        ends = item.split(':')
                        low = int(ends[0] or 0); high = int(ends[-1] or 65535)
                        if low <= m['listen_port'] <= high:
                            covered = True
                    if not covered:
                        continue
                target = option(rule, '--to-destination')
                legacy_targets = {f"{p['remote_gre_ip']}:{m['target_port']}",
                                  f"{ipaddress.IPv4Interface(p['local_gre_cidr']).ip}:{m['target_port']}"}
                if p.get('legacy_cleanup') and target in legacy_targets:
                    continue
                raise Error(f"{m['protocol']} port {m['listen_port']} conflicts with an existing external NAT rule: {' '.join(rule)}")

def preflight(profiles):
    """Read-only checks before touching any tunnel or firewall."""
    check_external_port_conflicts(profiles)
    routes = ip_json('-4', 'route', 'show', 'table', 'main')
    gre_ifaces = {p['interface'] for p in profiles}
    for p in profiles:
        info = ip_json('-4', 'addr', 'show', 'dev', p['wan_interface'])
        assigned = {a['local'] for link in info for a in link.get('addr_info', []) if a.get('family') == 'inet'}
        if p['local_public_ip'] not in assigned:
            raise Error(f"{p['local_public_ip']} is not assigned to {p['wan_interface']}. Enter the actual local outer IPv4.")
        net = ipaddress.IPv4Interface(p['local_gre_cidr']).network
        for route in routes:
            dst = route.get('dst', 'default')
            if dst == 'default' or route.get('dev') == p['interface']:
                continue
            if net.overlaps(ipaddress.IPv4Network(dst, strict=False)):
                raise Error(f"{net} overlaps existing route {dst} on {route.get('dev')}; choose another /30.")
        route = ip_json('-4', 'route', 'get', p['remote_public_ip'])
        if not route or route[0].get('dev') in gre_ifaces:
            raise Error('The remote outer address must be reachable outside the managed GRE tunnels.')
        link = get_link(p['interface'])
        if link:
            li = link.get('linkinfo', {})
            if li.get('info_kind') != 'gre':
                raise Error(f"{p['interface']} exists and is not GRE.")
            d = li.get('info_data', {})
            if any(d.get(k) not in (None, 0, '0', '0.0.0.0') for k in ('ikey', 'okey')):
                raise Error('Keyed GRE tunnels are not supported by this manager.')
            if link.get('ifalias') != MARKER+p['name']:
                matching = d.get('local') == p['local_public_ip'] and d.get('remote') == p['remote_public_ip']
                if not p.get('adopt_existing') or not matching:
                    raise Error(f"{p['interface']} is not owned by this profile. Import it, or choose a new interface.")

def ensure_tunnel(p):
    link = get_link(p['interface'])
    args = ['mode', 'gre', 'local', p['local_public_ip'], 'remote', p['remote_public_ip'], 'ttl', str(p['ttl'])]
    if link is None:
        run(['ip', 'tunnel', 'add', p['interface'], *args])
    else:
        d = link.get('linkinfo', {}).get('info_data', {})
        if (d.get('local'), d.get('remote'), d.get('ttl')) != (p['local_public_ip'], p['remote_public_ip'], p['ttl']):
            run(['ip', 'tunnel', 'change', p['interface'], *args])
    run(['ip', 'link', 'set', 'dev', p['interface'], 'alias', MARKER+p['name']])
    current = ip_json('-4', 'addr', 'show', 'dev', p['interface'])
    for entry in current:
        for addr in entry.get('addr_info', []):
            cidr = f"{addr['local']}/{addr['prefixlen']}"
            if addr.get('family') == 'inet' and cidr != p['local_gre_cidr']:
                run(['ip', 'addr', 'del', cidr, 'dev', p['interface']])
    run(['ip', 'addr', 'replace', p['local_gre_cidr'], 'dev', p['interface']])
    run(['ip', 'link', 'set', 'dev', p['interface'], 'mtu', str(p['mtu']), 'txqueuelen', '1000', 'up'])

CHAINS = {'filter': ('GREMGR_IN', 'GREMGR_OUT', 'GREMGR_FWD'),
          'mangle': ('GREMGR_MSS',), 'nat': ('GREMGR_DNAT', 'GREMGR_SNAT')}
HOOKS = [('filter','INPUT','GREMGR_IN'), ('filter','OUTPUT','GREMGR_OUT'),
         ('filter','FORWARD','GREMGR_FWD'), ('mangle','FORWARD','GREMGR_MSS'),
         ('nat','PREROUTING','GREMGR_DNAT'), ('nat','POSTROUTING','GREMGR_SNAT')]

def firewall_text(profiles):
    rules = {t: [] for t in CHAINS}
    def add(table, chain, *args):
        line = '-A '+chain+' '+' '.join(str(a) for a in args)
        if line not in rules[table]:
            rules[table].append(line)
    for p in profiles:
        iface, wan = p['interface'], p['wan_interface']
        local_outer, remote_outer = p['local_public_ip'], p['remote_public_ip']
        local_inner = str(ipaddress.IPv4Interface(p['local_gre_cidr']).ip)
        peer = p['remote_gre_ip']
        add('filter','GREMGR_IN','-i',wan,'-s',remote_outer,'-d',local_outer,'-p','gre','-j','ACCEPT')
        add('filter','GREMGR_OUT','-o',wan,'-s',local_outer,'-d',remote_outer,'-p','gre','-j','ACCEPT')
        # Permit inner management replies and diagnostics from this peer.
        add('filter','GREMGR_IN','-i',iface,'-s',peer,'-d',local_inner,'-p','icmp','-j','ACCEPT')
        add('filter','GREMGR_IN','-i',iface,'-s',peer,'-d',local_inner,'-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
        add('filter','GREMGR_OUT','-o',iface,'-s',local_inner,'-d',peer,'-j','ACCEPT')
        # Keep PMTU error traffic usable across the underlay and forwarding path.
        add('filter','GREMGR_IN','-i',wan,'-d',local_outer,'-p','icmp','--icmp-type','3/4','-m','conntrack','--ctstate','RELATED','-j','ACCEPT')
        add('filter','GREMGR_FWD','-i',iface,'-o',wan,'-m','conntrack','--ctstate','RELATED','-j','ACCEPT')
        add('filter','GREMGR_FWD','-i',wan,'-o',iface,'-m','conntrack','--ctstate','RELATED','-j','ACCEPT')
        for direction in ('-i','-o'):
            add('mangle','GREMGR_MSS',direction,iface,'-p','tcp','--tcp-flags','SYN,RST','SYN','-j','TCPMSS','--clamp-mss-to-pmtu')
        for m in p['forwards']:
            proto, ext, dst = m['protocol'], m['listen_port'], m['target_port']
            add('nat','GREMGR_DNAT','-i',wan,'-d',local_outer,'-p',proto,'--dport',ext,'-j','DNAT','--to-destination',f'{peer}:{dst}')
            add('nat','GREMGR_SNAT','-o',iface,'-d',peer,'-p',proto,'--dport',dst,'-m','conntrack','--ctstate','DNAT','-j','SNAT','--to-source',local_inner)
            add('filter','GREMGR_FWD','-i',wan,'-o',iface,'-d',peer,'-p',proto,'--dport',dst,'-m','conntrack','--ctstate','NEW,ESTABLISHED','-j','ACCEPT')
            add('filter','GREMGR_FWD','-i',iface,'-o',wan,'-s',peer,'-p',proto,'--sport',dst,'-m','conntrack','--ctstate','ESTABLISHED','-j','ACCEPT')
        # On a receiving server, explicitly permit only the chosen service ports.
        for m in p.get('accept_ports', []):
            add('filter','GREMGR_IN','-i',iface,'-s',peer,'-d',local_inner,'-p',m['protocol'],'--dport',m['target_port'],'-j','ACCEPT')
    result = []
    for table, chains in CHAINS.items():
        result.append('*'+table)
        result.extend(':'+c+' - [0:0]' for c in chains)
        result.extend(rules[table])
        result.append('COMMIT')
    return '\n'.join(result)+'\n'

def ensure_hooks():
    for table, base, chain in HOOKS:
        args = ['-m','comment','--comment','gre-manager','-j',chain]
        if run(['iptables','-w','10','-t',table,'-C',base,*args], check=False).returncode:
            run(['iptables','-w','10','-t',table,'-I',base,'1',*args])

def delete_exact(table, chain, args):
    while run(['iptables','-w','10','-t',table,'-C',chain,*args], check=False).returncode == 0:
        run(['iptables','-w','10','-t',table,'-D',chain,*args])

def clean_legacy(p):
    """Only exact old script/manual repair rules for the imported gre1 profile."""
    if not p.get('legacy_cleanup'):
        return
    wan, iface, peer = p['wan_interface'], p['interface'], p['remote_gre_ip']
    local = str(ipaddress.IPv4Interface(p['local_gre_cidr']).ip)
    ports = list(dict.fromkeys(m['listen_port'] for m in p['forwards']))
    for m in p['forwards']:
        proto, n = m['protocol'], str(m['listen_port'])
        for target in (local, peer):
            delete_exact('nat','PREROUTING',['-i',wan,'-p',proto,'--dport',n,'-j','DNAT','--to-destination',f'{target}:{n}'])
        delete_exact('filter','FORWARD',['-i',wan,'-o',iface,'-d',peer,'-p',proto,'--dport',n,'-m','conntrack','--ctstate','NEW,ESTABLISHED','-j','ACCEPT'])
        delete_exact('filter','FORWARD',['-i',iface,'-o',wan,'-s',peer,'-p',proto,'--sport',n,'-m','conntrack','--ctstate','ESTABLISHED','-j','ACCEPT'])
    if ports:
        for proto in ('tcp','udp'):
            for target in (local,peer):
                delete_exact('filter','FORWARD',['-i',wan,'-o',iface,'-p',proto,'-m','multiport','--dports',','.join(map(str,ports)),'-d',target,'-j','ACCEPT'])
        delete_exact('nat','POSTROUTING',['-o',iface,'-j','MASQUERADE'])
        delete_exact('filter','FORWARD',['-i',iface,'-o',wan,'-m','state','--state','ESTABLISHED,RELATED','-j','ACCEPT'])
    p.pop('legacy_cleanup', None)
    save_profile(p)

def apply_all(profiles=None):
    profiles = load_profiles() if profiles is None else validate_all(profiles)
    preflight(profiles)
    text = firewall_text(profiles)
    run(['iptables-restore','--wait','10','--noflush','--test'], data=text)
    for p in profiles:
        ensure_tunnel(p)
    if profiles:
        run(['sysctl','-w','net.ipv4.ip_forward=1'])
        atomic_write(Path('/etc/sysctl.d/90-gre-manager.conf'), 'net.ipv4.ip_forward=1\n')
    # --noflush rebuilds only our declared chains, retaining all other rules.
    run(['iptables-restore','--wait','10','--noflush'], data=text)
    ensure_hooks()
    for p in profiles:
        clean_legacy(p)
    print(f'Applied {len(profiles)} tunnel(s). Only GRE-manager chains were rebuilt.')

def import_legacy(name='turkey'):
    if not LEGACY.is_file():
        raise Error(f'No legacy configuration at {LEGACY}')
    values = {}
    for line in LEGACY.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise Error('Unexpected legacy configuration line.')
        key, raw = line.split('=', 1)
        tokens = shlex.split(raw, comments=True)
        if len(tokens) != 1:
            raise Error('Unexpected legacy value; configuration was not executed.')
        values[key] = tokens[0]
    wan = values.get('PRIMARY_NIC')
    if not wan:
        wan = ip_json('-4','route','get',values['REMOTE_PUBLIC_IP'])[0]['dev']
    mappings = parse_ports(values.get('FORWARDED_PORTS', ''))
    p = {'name': name, 'interface': 'gre1', 'wan_interface': wan,
         'local_public_ip': values['LOCAL_PUBLIC_IP'], 'remote_public_ip': values['REMOTE_PUBLIC_IP'],
         'local_gre_cidr': values['LOCAL_GRE_IP'], 'remote_gre_ip': values['REMOTE_GRE_IP'],
         'mtu': 1400, 'ttl': 255, 'forwards': mappings, 'accept_ports': [],
         'adopt_existing': True, 'legacy_cleanup': True}
    current = load_profiles()
    if any(x['name'] == name or x['interface'] == 'gre1' for x in current):
        raise Error('A profile with this name or gre1 already exists; use Edit instead.')
    validate_all([*current, p]); preflight([*current, p]); save_profile(p)
    print(f'Imported {LEGACY} as {name}. Original file retained. Apply to adopt gre1.')
    return p

def status():
    profiles = load_profiles()
    if not profiles:
        print('No saved tunnels. Add one or import the old gre1 configuration.')
    for p in profiles:
        link = get_link(p['interface'])
        state = 'UP' if link and 'UP' in link.get('flags',[]) else ('DOWN' if link else 'ABSENT')
        print(f"\n{p['name']} [{state}] {p['interface']} MTU {p['mtu']}")
        print(f"  Outer: {p['local_public_ip']} -> {p['remote_public_ip']}")
        print(f"  GRE:   {p['local_gre_cidr']} -> {p['remote_gre_ip']}")
        for m in p['forwards']:
            print(f"  {m['protocol']} {p['local_public_ip']}:{m['listen_port']} -> {p['remote_gre_ip']}:{m['target_port']}")
        print(f"  Saved: {profile_path(p)}")
    print('\nUP means the interface is up, not that the remote server is reachable.')

def prompt(label, default=''):
    answer = input(f'{label}' + (f' [{default}]' if default != '' else '') + ': ').strip()
    return answer if answer else str(default)

def select_profile():
    profiles = load_profiles()
    if not profiles:
        raise Error('No profiles saved.')
    for p in profiles:
        print(f"  {p['name']}: {p['local_gre_cidr']} -> {p['remote_gre_ip']}")
    name = input('Tunnel name: ').strip()
    return next((p for p in profiles if p['name'] == name), None) or fail('Unknown tunnel name.')

def fail(message):
    raise Error(message)

def format_ports(items):
    return ','.join(f"{m['protocol']}:{m['listen_port']}:{m['target_port']}" for m in items) or 'none'

def edit_profile(old=None):
    current = load_profiles()
    name = old['name'] if old else prompt('Name, e.g. turkey or germany')
    if not old and any(p['name'] == name for p in current):
        raise Error('That name already exists; use Edit.')
    defaults = old or {}
    route = ip_json('-4','route','get','1.1.1.1')[0]
    p = {'name': name,
         'interface': old['interface'] if old else prompt('GRE interface', 'gre-'+name),
         'wan_interface': prompt('Public network interface', defaults.get('wan_interface',route.get('dev','eth0'))),
         'local_public_ip': prompt('Local outer IPv4 (must already be assigned to this server)', defaults.get('local_public_ip',route.get('prefsrc',route.get('src','')))),
         'remote_public_ip': prompt('Remote server outer IPv4', defaults.get('remote_public_ip','')),
         'local_gre_cidr': prompt('Local GRE IPv4/prefix; use a different /30 per tunnel', defaults.get('local_gre_cidr','')),
         'remote_gre_ip': prompt('Remote GRE IPv4', defaults.get('remote_gre_ip','')),
         'mtu': int(prompt('GRE MTU', defaults.get('mtu',1400))), 'ttl': 255,
         'adopt_existing': defaults.get('adopt_existing',False)}
    print('Forwarding syntax: 1402 = TCP+UDP; tcp:4567; udp:1533:1402 = external 1533 to remote 1402.')
    print('On the receiving server, use none for forwarding. Use none to clear existing mappings.')
    p['forwards'] = parse_ports(prompt('Incoming public ports to forward', format_ports(defaults.get('forwards',[]))))
    print('On the receiving server, list service ports to allow from the GRE peer, e.g. 1402,4567.')
    p['accept_ports'] = parse_ports(prompt('Local service ports to allow over GRE', format_ports(defaults.get('accept_ports',[]))))
    validate_all([x for x in current if x['name'] != name]+[p])
    # Legacy rules must be migrated using the original profile before editing its addresses/ports.
    if old and old.get('legacy_cleanup'):
        raise Error('Apply the imported configuration once before editing it, to migrate its old rules.')
    preflight([x for x in current if x['name'] != name]+[p])
    print(json.dumps(p, indent=2))
    if input('Save and apply? Changing addresses or ports can interrupt this tunnel [y/N]: ').lower() != 'y':
        return
    save_profile(p)
    try:
        apply_all()
    except Exception:
        if not old:
            link = get_link(p['interface'])
            if link and link.get('ifalias') == MARKER+p['name']:
                run(['ip','tunnel','del',p['interface']], check=False)
        if old:
            save_profile(old)
        else:
            profile_path(p).unlink()
        print('Saved configuration reverted. Attempting to restore previous settings.')
        try:
            apply_all(current)
        except Exception as exc:
            print(f'Recovery failed; inspect the service before rebooting: {exc}', file=sys.stderr)
        raise

def remove_profile(p):
    if p.get('legacy_cleanup'):
        raise Error('Apply the imported profile first so its old rules can be migrated safely.')
    link = get_link(p['interface'])
    if link and link.get('ifalias') != MARKER+p['name']:
        raise Error('Interface is not owned by this profile; refusing to delete it.')
    others = [x for x in load_profiles() if x['name'] != p['name']]
    apply_all(others)
    if link:
        run(['ip','tunnel','del',p['interface']])
    dest = backup(profile_path(p)); profile_path(p).unlink()
    print(f"Removed only {p['name']}. Configuration backup: {dest}")

def install_service():
    source = Path(SOURCE)
    if not source.is_file() or source.stat().st_size == 0:
        raise Error('Save this script to a regular file before installing. Do not use bash <(curl ...) or pipe it into bash.')
    text = source.read_text()
    if '# GRE_MULTI_MANAGER_V1' not in text:
        raise Error('Source file is not a complete GRE manager script.')
    run(['bash','-n',str(source)])
    backup(INSTALLED); backup(UNIT)
    atomic_write(INSTALLED, text, 0o755)
    unit = '''[Unit]
Description=GRE Multi-Server Tunnel Manager
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gre.sh --apply
ExecReload=/usr/local/bin/gre.sh --apply
RemainAfterExit=yes
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
'''
    atomic_write(UNIT, unit, 0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable',SERVICE])
    print(f'Installed {INSTALLED}; enabled {SERVICE}. Use Apply to activate saved settings now.')
    if not load_profiles():
        print('No profiles saved yet: add or import before rebooting.')

@contextlib.contextmanager
def locked():
    with open('/run/lock/gre-manager.lock','w') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield

def dependencies():
    for name in ('ip','iptables','iptables-save','iptables-restore','sysctl','systemctl','bash'):
        if shutil.which(name) is None:
            raise Error(f'Missing dependency: {name}. On Ubuntu install iproute2, iptables, python3.')

def menu():
    while True:
        print('''\nGRE Multi-Server Manager
1) Add tunnel / choose port forwarding
2) Edit tunnel addresses and ports
3) Show status
4) Apply all saved settings
5) Remove one managed tunnel
6) Import /etc/gre-tunnel.conf
7) Install/update startup service
8) Show saved JSON configuration
0) Exit''')
        try:
            choice = input('Choice: ').strip()
            if choice == '0':
                return
            # Lock only each action, not the whole menu lifetime (boot/reload can still run).
            with locked():
                if choice == '1': edit_profile()
                elif choice == '2': edit_profile(select_profile())
                elif choice == '3': status()
                elif choice == '4': apply_all()
                elif choice == '5':
                    p = select_profile()
                    if input(f"Remove {p['name']} and disconnect its traffic? Type its name: ") == p['name']:
                        remove_profile(p)
                elif choice == '6': import_legacy(prompt('Imported tunnel name','turkey'))
                elif choice == '7': install_service()
                elif choice == '8': print(json.dumps(select_profile(),indent=2))
                else: print('Unknown choice.')
        except (Error, ValueError, OSError) as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            print('\nLeaving menu.'); return

def main(argv):
    global SOURCE
    SOURCE = argv[0]
    parser = argparse.ArgumentParser(description='Persistent GRE tunnels and TCP/UDP port forwarding')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--install',action='store_true')
    group.add_argument('--apply',action='store_true')
    group.add_argument('--status',action='store_true')
    group.add_argument('--import-legacy',metavar='NAME')
    group.add_argument('--check',action='store_true',help='Validate saved JSON without changing networking')
    # Preserve compatibility with the user's existing service command.
    group.add_argument('--service',choices=['start'])
    args = parser.parse_args(argv[1:])
    if os.geteuid() != 0:
        raise Error('Run as root: sudo bash GRETUN.sh')
    dependencies()
    PROFILES.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(ROOT,0o700); os.chmod(PROFILES,0o700)
    if not any((args.install,args.apply,args.status,args.import_legacy,args.check,args.service)):
        return menu()
    with locked():
        if args.check:
            print(f'Configuration valid: {len(load_profiles())} tunnel(s).')
        elif args.install: install_service()
        elif args.import_legacy: import_legacy(args.import_legacy)
        elif args.status: status()
        else: apply_all()

if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (Error, ValueError, KeyError, OSError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr)
        sys.exit(1)

GRE_MANAGER_PYTHON
exec python3 -c "$GRE_MANAGER_CODE" "${BASH_SOURCE[0]:-}" "$@"
