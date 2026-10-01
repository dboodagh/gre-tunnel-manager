import copy
import types
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ARTIFACT = Path(__file__).resolve().parents[1] / 'GRETUN.sh'
source = ARTIFACT.read_text()
embedded = source.split("<<'GRE_MANAGER_PYTHON' || true\n", 1)[1].split('\nGRE_MANAGER_PYTHON\n', 1)[0]
g = types.ModuleType('gre_manager')
exec(compile(embedded, str(ARTIFACT) + ':embedded-python', 'exec'), g.__dict__)

def profile(name='turkey', subnet='10.10.10.1/30', peer='10.10.10.2', outer='203.0.113.20', ports='1402,4567'):
    return dict(name=name, interface='gre-'+name,wan_interface='eth0',local_public_ip='198.51.100.10',remote_public_ip=outer,
                local_gre_cidr=subnet,remote_gre_ip=peer,mtu=1400,ttl=255,forwards=g.parse_ports(ports),accept_ports=[],adopt_existing=False)

class Fake:
    def __init__(self):
        self.links={}; self.addrs={'eth0':[{'family':'inet','local':'198.51.100.10','prefixlen':24}]}
        self.rules={('nat','PREROUTING'):[['-j','XRAYMESH_DNAT']],('filter','FORWARD'):[['-j','XRAYMESH_FWD']],('nat','XRAYMESH_DNAT'):[['-j','RETURN']]}
        self.calls=[]; self.fail_test=False
    def result(self,args,code=0,out=''):
        return subprocess.CompletedProcess(args,code,out,'injected failure' if code else '')
    def run(self,args,check=True,data=None):
        args=list(map(str,args)); self.calls.append(args); code=0; out=''
        if args[0]=='ip':
            if args[:5]==['ip','-j','-4','route','show']:
                rs=[{'dst':'default','dev':'eth0'},{'dst':'198.51.100.0/24','dev':'eth0'}]
                for iface,addresses in self.addrs.items():
                    if iface=='eth0': continue
                    for a in addresses: rs.append({'dst':str(ipaddress.IPv4Interface(f"{a['local']}/{a['prefixlen']}").network),'dev':iface})
                out=json.dumps(rs)
            elif args[:5]==['ip','-j','-4','route','get']: out=json.dumps([{'dev':'eth0','prefsrc':'198.51.100.10'}])
            elif args[:5]==['ip','-j','-4','addr','show']:
                out=json.dumps([{'addr_info':self.addrs.get(args[-1],[])}])
            elif args[:5]==['ip','-j','-d','link','show']:
                if args[-1] not in self.links: code=1
                else: out=json.dumps([self.links[args[-1]]])
            elif args[1]=='tunnel':
                op,iface=args[2:4]
                if op=='del': self.links.pop(iface,None); self.addrs.pop(iface,None)
                else:
                    d={k:args[args.index(k)+1] for k in ('local','remote','ttl')}; d['ttl']=int(d['ttl'])
                    old=self.links.get(iface,{})
                    self.links[iface]={**old,'linkinfo':{'info_kind':'gre','info_data':d}}
            elif args[1:4]==['link','set','dev']:
                iface=args[4]
                if 'alias' in args: self.links[iface]['ifalias']=args[-1]
                if 'up' in args: self.links[iface]['flags']=['UP']
            elif args[1]=='addr':
                op,cidr=args[2:4]; iface=args[-1]; addr=ipaddress.IPv4Interface(cidr)
                record={'family':'inet','local':str(addr.ip),'prefixlen':addr.network.prefixlen}
                rows=self.addrs.setdefault(iface,[])
                if op=='del': rows.remove(record)
                elif record not in rows: rows.append(record)
            else: raise AssertionError(args)
        elif args[0]=='iptables-save':
            out='*nat\n'+'\n'.join('-A '+chain+' '+shlex.join(rule) for (table,chain),rows in self.rules.items() if table=='nat' for rule in rows)+'\nCOMMIT\n'
        elif args[0]=='iptables-restore':
            parsed={}; table=None
            for line in data.splitlines():
                if line.startswith('*'): table=line[1:]
                elif line.startswith(':'): parsed[(table,line.split()[0][1:])]=[]
                elif line.startswith('-A '):
                    words=shlex.split(line); parsed[(table,words[1])].append(words[2:])
            if '--test' in args:
                if self.fail_test: code=1
            else: self.rules.update(parsed)
            assert '--noflush' in args
        elif args[0]=='iptables':
            table=args[args.index('-t')+1]; i=next(i for i,x in enumerate(args) if x in ('-C','-I','-D'))
            action,chain=args[i:i+2]; rule=args[i+2:]
            rows=self.rules.setdefault((table,chain),[])
            if action=='-C': code=0 if rule in rows else 1
            elif action=='-I': assert rule.pop(0)=='1'; rows.insert(0,rule)
            else: rows.remove(rule)
        elif args[0] in ('sysctl','systemctl'): pass
        elif args[:2]==['bash','-n']:
            p=subprocess.run(args,capture_output=True,text=True); code=p.returncode; out=p.stdout
        else: raise AssertionError(args)
        if check and code: raise g.Error('injected error: '+' '.join(args))
        return self.result(args,code,out)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.original={x:getattr(g,x) for x in ('ROOT','PROFILES','BACKUPS','INSTALLED','UNIT','LEGACY','run','atomic_write','SOURCE')}
        g.ROOT=self.root;g.PROFILES=self.root/'tunnels';g.PROFILES.mkdir();g.BACKUPS=self.root/'backups'
        g.INSTALLED=self.root/'gre.sh';g.UNIT=self.root/'gre-tunnel.service';g.LEGACY=self.root/'gre-tunnel.conf'
        self.fake=Fake();g.run=self.fake.run
        orig=g.atomic_write
        def write(path,text,mode=0o600):
            if str(path).startswith('/etc/sysctl.d/'): path=self.root/'sysctl.conf'
            orig(path,text,mode)
        g.atomic_write=write
    def tearDown(self):
        for k,v in self.original.items():setattr(g,k,v)
        self.tmp.cleanup()
    def test_port_translation_and_both(self):
        self.assertEqual(len(g.parse_ports('1402,udp:1533:1402,tcp:4567')),4)
        for bad in ('udp:0','65536','tcp:22:80,tcp:22:81','icmp:80','123;whoami'):
            with self.assertRaises(g.Error):g.parse_ports(bad)
    def test_invalid_profiles(self):
        for field,value in [('remote_gre_ip','10.10.11.2'),('local_gre_cidr','10.10.10.0/30'),('local_gre_cidr','10.10.10.1/24'),('interface','eth0'),('mtu',True)]:
            p=profile();p[field]=value
            with self.assertRaises(g.Error):g.validate(p)
        p=profile();p['accept_ports']=[{'protocol':'tcp -j ACCEPT','listen_port':80,'target_port':80}]
        with self.assertRaises(g.Error):g.validate(p)
    def test_conflicts(self):
        a=profile();b=profile('germany',outer='192.0.2.9')
        with self.assertRaises(g.Error):g.validate_all([a,b])
        b=profile('germany','10.10.20.1/30','10.10.20.2','192.0.2.9')
        with self.assertRaises(g.Error):g.validate_all([a,b])
        b['forwards']=g.parse_ports('1533');g.validate_all([a,b])
    def test_cold_and_repeat_apply_preserve_other_chains(self):
        a=profile();b=profile('germany','10.10.20.1/30','10.10.20.2','192.0.2.9','1533')
        g.apply_all([a,b]); before=copy.deepcopy(self.fake.rules)
        g.apply_all([a,b]);self.assertEqual(before,self.fake.rules)
        self.assertEqual(len([x for x in self.fake.calls if x[:3]==['ip','tunnel','add']]),2)
        self.assertIn(['-j','XRAYMESH_DNAT'],self.fake.rules[('nat','PREROUTING')])
        self.assertEqual(self.fake.rules[('nat','XRAYMESH_DNAT')],[['-j','RETURN']])
        rules=g.firewall_text([a,b]); self.assertIn('10.10.10.2:1402',rules);self.assertIn('10.10.20.2:1533',rules)
        self.assertNotIn('--to-destination 10.10.10.1:',rules)
        for rows in self.fake.rules.values():self.assertEqual(len(rows),len({tuple(x) for x in rows}))
    def test_edit_changes_peer_ports_and_removes_old_address(self):
        p=profile();g.apply_all([p]);p['remote_public_ip']='192.0.2.9'
        p['local_gre_cidr']='10.10.20.1/30';p['remote_gre_ip']='10.10.20.2';p['forwards']=g.parse_ports('udp:1533:1402')
        g.apply_all([p]);self.assertEqual(self.fake.addrs[p['interface']][0]['local'],'10.10.20.1')
        rows=self.fake.rules[('nat','GREMGR_DNAT')];self.assertEqual(len(rows),1)
        self.assertIn('10.10.20.2:1402',rows[0]);self.assertIn('1533',rows[0])
        self.assertFalse(any(x[:3]==['ip','tunnel','del'] for x in self.fake.calls))
    def test_preflight_refuses_unowned_interface_or_wrong_local(self):
        p=profile();self.fake.links[p['interface']]={'linkinfo':{'info_kind':'gre','info_data':{'local':p['local_public_ip'],'remote':p['remote_public_ip']}}}
        with self.assertRaises(g.Error):g.apply_all([p])
        self.assertFalse(any(x[0]=='iptables-restore' for x in self.fake.calls))
        p['adopt_existing']=True;p['local_public_ip']='192.0.2.100'
        with self.assertRaises(g.Error):g.preflight([p])
    def test_firewall_validation_failure_before_mutation(self):
        self.fake.fail_test=True
        with self.assertRaises(g.Error):g.apply_all([profile()])
        self.assertFalse(self.fake.links)
    def test_import_existing_conf_and_migrate_wrong_rule(self):
        g.LEGACY.write_text('''ROLE="1"\nLOCAL_PUBLIC_IP="198.51.100.10"\nREMOTE_PUBLIC_IP="203.0.113.20"\nLOCAL_GRE_IP="10.10.10.1/30"\nREMOTE_GRE_IP="10.10.10.2"\nPRIMARY_NIC="eth0"\nFORWARDED_PORTS="1402,4567"\n''')
        p=profile();self.fake.links['gre1']={'linkinfo':{'info_kind':'gre','info_data':{'local':p['local_public_ip'],'remote':p['remote_public_ip'],'ttl':255}}}
        wrong=['-i','eth0','-p','tcp','--dport','1402','-j','DNAT','--to-destination','10.10.10.1:1402']
        self.fake.rules[('nat','PREROUTING')].extend([wrong,wrong])
        g.import_legacy();g.apply_all();g.apply_all()
        self.assertTrue(g.LEGACY.exists());self.assertNotIn(wrong,self.fake.rules[('nat','PREROUTING')])
        self.assertFalse(any(x[:3]==['ip','tunnel','del'] for x in self.fake.calls))
        self.assertNotIn('legacy_cleanup',g.load_profiles()[0])
    def test_remove_one_preserves_other(self):
        a=profile();b=profile('germany','10.10.20.1/30','10.10.20.2','192.0.2.9','1533')
        g.save_profile(a);g.save_profile(b);g.apply_all();g.remove_profile(a)
        self.assertNotIn(a['interface'],self.fake.links);self.assertIn(b['interface'],self.fake.links)
        self.assertEqual([x['name'] for x in g.load_profiles()],['germany'])
        self.assertIn(['-j','XRAYMESH_DNAT'],self.fake.rules[('nat','PREROUTING')])
    def test_install_same_source_atomic_and_reject_empty(self):
        artifact=ARTIFACT
        g.INSTALLED.write_text(artifact.read_text());g.SOURCE=str(g.INSTALLED)
        g.install_service();g.install_service()
        self.assertEqual(g.INSTALLED.read_text(),artifact.read_text())
        self.assertIn('--apply',g.UNIT.read_text())
        g.INSTALLED.write_text('')
        with self.assertRaises(g.Error):g.install_service()
    def test_xray_port_conflict_is_rejected(self):
        self.fake.rules[('nat','XRAYMESH_DNAT')]=[['-i','eth0','-p','tcp','--dport','1402','-j','DNAT','--to-destination','10.233.24.2:1402']]
        with self.assertRaises(g.Error):g.apply_all([profile()])
        self.assertFalse(self.fake.links)
    def test_shared_target_deduplicates_nat_forward_rules(self):
        p=profile(ports='udp:1402:1402,udp:1533:1402');g.apply_all([p])
        self.assertEqual(len(self.fake.rules[('nat','GREMGR_SNAT')]),1)

if __name__=='__main__':unittest.main(verbosity=2)
