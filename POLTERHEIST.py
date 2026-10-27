#!/usr/bin/env python3
"""STALKER v1.4. Inventario y auditoría de una LAN propia/autorizada."""
import csv
import datetime
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

GREEN='\033[92m'; AMBER='\033[93m'; RESET='\033[0m'
COLOR=sys.stdout.isatty() and not os.getenv('NO_COLOR')
def tint(s,c=GREEN): return c+str(s)+RESET if COLOR else str(s)

BANNER=r'''
  ███████╗████████╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
  ██╔════╝╚══██╔══╝██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
  ███████╗   ██║   ███████║██║     █████╔╝ █████╗  ██████╔╝
  ╚════██║   ██║   ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
  ███████║   ██║   ██║  ██║███████╗██║  ██╗███████╗██║  ██║
  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
%%%%%%%++;:,.       .,;%%+:,++%t%%+++t++$t++%+,,.. .,..  ...  .,..
ttttt%%++;,..    .;;:..,:;:      .  .,,.::;;;;:;:,.. .. .... ..,....
tt$$$t%+;:,.    :t$%:.         .            ..,,.,.      ......,........
tttttt%+;:,.. ,;;;,.    .,;%t&#&%+t$$+.                  ......,,,......  .
ttttt%%+;:,,,:+;,.  ..,+&###########t,                     .,,,,.....,..  ..
%ttt%%%+;:::;t&%:..,,,%############&:  .,.                  .,,,,....,.......
t$$%%%%++++%$$%+;;:::+&############%,,;$$:                   ...,...,....,,,,.
$$t%%%%%%%t$$t%+++;;+$############&;;%##&;                     .,...,...,,,,.
$t%%%%%%%$&&$tt%+++%&#############t:+%%t;.                      .,.....,,,,,.
&$ttttt$&###$$t%++%$##############t,++;:,.     .,,.             .,..,,,,,,,,,
&&$tt$######&$t+;+&###############t,:;;;:,     ,:::,            .,,,,,,,,,::,
&&$$&######&$t++t##################;.:+;:,,,,,:;;;;:.   .       .,,,,,,,,,,::
#&&&#######&%;%####################$;:;++++:;;;+%+;,  :%%:.     .,:::::::::;:
############t%######################t::%%%+;++;+%;,..+&#$+,.    .,::::::::;;:
#############&&######################$;;;++::;+;::;t##$+;;,,,.....,::::;;;++;.
###############&$&#&##################&%++;,,:+t&##&t+::::,,,.,,,.,,::;;++%%+,
################&&#&&&$&&#######################&&$t%+;:,,,,:;;;;:::::;++%tt%,
###############&$&&t$t%t&&&&################&$$$$$ttt+;:,,,;+%%%++;;+;+%%t$$%,
#################&$$$$t&&$$&&t%$$$&&$$&&$&&$%%tt&t++++:,,,;%$$$$$tt%%%%%tt$$t,
#################&$&&$$&&t&#$t$&%t&t%$&$t$$ttt%%%++;:,,,,;%$&##&&&$$tttt$$&&$:
                        EVERY HOST LEAVES A TRACE
'''

MACLINE=re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s+([a-fA-F0-9:]{17})\s*(.*)$')
CVE=re.compile(r'\bCVE-\d{4}-\d{4,}\b',re.I)
PERCENT=re.compile(r'(\d+(?:\.\d+)?)%\s+done',re.I)
REMAIN=re.compile(r'\(([^)]*remaining)\)',re.I)

class Spinner:
    """Indeterminate activity indicator: not a fabricated percentage."""
    def __init__(self,label): self.label=label; self.stop_event=threading.Event(); self.thread=None
    def __enter__(self):
        self.started=time.monotonic()
        def animate():
            frames='|/-\\'; i=0
            while not self.stop_event.wait(.12):
                elapsed=int(time.monotonic()-self.started)
                msg=f'\r  [{frames[i%4]}] {self.label}  [{elapsed}s transcurridos]'
                print(tint(msg,AMBER)+' '*10,end='',flush=True);i+=1
        self.thread=threading.Thread(target=animate,daemon=True);self.thread.start();return self
    def __exit__(self,*args):
        self.stop_event.set();self.thread.join()
        print('\r'+' '*105+'\r',end='',flush=True)
        print(tint(f'  [✓] {self.label} ({time.monotonic()-self.started:.1f}s)'))


def run_quiet(cmd,timeout=120):
    try: return subprocess.run(cmd,text=True,capture_output=True,timeout=timeout)
    except (subprocess.TimeoutExpired,OSError) as err:
        return None

def netinfo():
    routes=json.loads(subprocess.check_output(['ip','-j','-4','route','show','default'],text=True))
    route=next((r for r in routes if r.get('dev')),None)
    if not route: raise RuntimeError('No hay ruta predeterminada IPv4')
    dev=route['dev']; gateway=route.get('gateway')
    addr=json.loads(subprocess.check_output(['ip','-j','-4','addr','show','dev',dev],text=True))
    info=next(x for d in addr for x in d.get('addr_info',[]) if x.get('family')=='inet' and x.get('scope')=='global')
    my_ip=info['local'];network=ipaddress.ip_network(f"{my_ip}/{info['prefixlen']}",strict=False)
    return dev,my_ip,gateway,network

def good_vendor(v):
    return bool(v) and not any(x in v.lower() for x in ['unknown','desconocido','locally administered'])

def discover(dev,my_ip,gateway,network,folder):
    found={}
    def add(ip,mac='',vendor='',source=''):
        try:
            if ipaddress.ip_address(ip) not in network: return
        except ValueError:return
        entry=found.setdefault(ip,{'ip':ip,'mac':'-','vendor':'Desconocido','sources':[],'local':False})
        if mac and entry['mac']=='-':entry['mac']=mac.lower()
        if good_vendor(vendor) and (not good_vendor(entry['vendor']) or source=='Nmap'):
            entry['vendor']=vendor.strip()
        if source and source not in entry['sources']:entry['sources'].append(source)

    with Spinner('ARP discovery'):
        res=run_quiet(['arp-scan','--interface',dev,'--localnet','--plain','--ignoredups'],timeout=70)
    if res and res.returncode==0:
        for line in res.stdout.splitlines():
            match=MACLINE.match(line.strip())
            if match: add(*match.groups(),source='ARP')
    else:print(tint('  [!] arp-scan falló; se continúa con Nmap.',AMBER))

    # XML to file avoids mixing messages with parser output.
    xml=folder/'discovery_nmap.xml'
    with Spinner('Nmap host discovery'):
        res=run_quiet(['nmap','-sn','-PR','-n','-oX',str(xml),str(network)],timeout=180)
    if xml.exists():
        try:
            root=ET.parse(xml).getroot()
            for h in root.findall('host'):
                if h.find('status') is None or h.find('status').get('state')!='up':continue
                ipv4=mac=vendor=''
                for a in h.findall('address'):
                    if a.get('addrtype')=='ipv4':ipv4=a.get('addr','')
                    if a.get('addrtype')=='mac':mac=a.get('addr','');vendor=a.get('vendor','')
                if ipv4:add(ipv4,mac,vendor,'Nmap')
        except ET.ParseError:print(tint('  [!] XML de descubrimiento ilegible.',AMBER))
    else: print(tint('  [!] Sin XML de descubrimiento Nmap.',AMBER))

    add(my_ip,source='LOCAL')
    found[my_ip]['local']=True;found[my_ip]['vendor']='Kali Linux (local)'
    hosts=[found[ip] for ip in sorted(found,key=ipaddress.ip_address)]
    for index,h in enumerate(hosts,1):
        h['id']=index;h['gateway']=(h['ip']==gateway)
    return hosts

def cut(s,w):
    s=str(s);return s if len(s)<=w else s[:w-3]+'...'

def table(headers,rows,widths):
    border='+'+'+'.join('-'*(w+2) for w in widths)+'+'
    def line(row):return '|'+'|'.join(' '+cut(v,w).ljust(w)+' ' for v,w in zip(row,widths))+'|'
    print(border);print(line(headers));print(border)
    for r in rows:print(line(r))
    print(border)

def show_hosts(hosts):
    print(tint('\n[+] STALKER :: NETWORK DISCOVERY'))
    rows=[[h['id'],h['ip'],h['mac'],h['vendor'],', '.join(h['sources'])] for h in hosts]
    table(['ID','IP','MAC','FABRICANTE / INFO','FUENTE'],rows,[3,15,17,38,16])
    print(f'  Total: {len(hosts)} IPs; LOCAL incluye la propia Kali.')

def identify(host,folder):
    ip=host['ip'];vendor=host['vendor'];loc=host['local']
    data={'id':host['id'],'ip':ip,'vendor':vendor,'vendor_confidence':'Media' if good_vendor(vendor) else 'Baja',
          'type':'Desconocido','os':'Desconocido','type_confidence':'Baja','evidence':[],'mobile':False}
    if loc:
        data.update(type='Kali (LOCAL)',os='Linux',type_confidence='Alta');data['evidence'].append('Interfaz local')
        return data
    if host['gateway']:
        data.update(type='Router / gateway',type_confidence='Alta');data['evidence'].append('Puerta de enlace')
    elif 'apple' in vendor.lower():
        data['type']='Apple device';data['evidence'].append('OUI Apple; sin identificar tipo')
    elif 'sichuan ai-link' in vendor.lower():
        data['type']='IoT posible';data['evidence'].append('Marca de modulo WiFi; no concluyente')

    path=folder/f'identify_{ip}.xml'
    cmd=['nmap','-n','-Pn','-sS','-sV','--version-light','-O','--osscan-guess',
         '-p','21,22,23,53,80,139,443,445,554,3389,62078,8080,8443,9100',
         '--max-retries','1','--host-timeout','75s','-T2','-oX',str(path),ip]
    res=run_quiet(cmd,timeout=90)
    if not path.exists():return data
    try: root=ET.parse(path).getroot()
    except ET.ParseError:return data
    match=root.find('./host/os/osmatch')
    accuracy=0
    if match is not None:
        name=match.get('name','');accuracy=int(match.get('accuracy','0'))
        low=name.lower()
        for token,label in [('windows','Windows'),('iphone','iOS'),('ios','iOS'),('android','Android'),('mac os','macOS'),('linux','Linux')]:
            if token in low:data['os']=label+' (estimado)';break
        else:
            if name:data['os']=cut(name,30)
        data['evidence'].append(f'Nmap osmatch {accuracy}% similitud')
    ports={}
    products=[]
    for p in root.findall('./host/ports/port'):
        st=p.find('state')
        if st is not None and st.get('state')=='open':
            number=int(p.get('portid'));ports[number]=True
            svc=p.find('service')
            if svc is not None:products.append(svc.get('product','').lower())
    if not host['gateway']:
        if 9100 in ports:
            data.update(type='Impresora probable',type_confidence='Media')
        elif any(x in ' '.join(products) for x in ['routeros','openwrt','fritz!os']):
            data.update(type='Router probable',type_confidence='Media')
        elif data['os'] in ('iOS (estimado)','Android (estimado)') and accuracy>=95:
            data.update(type='Movil/tablet probable',type_confidence='Media',mobile=True)
        elif (3389 in ports or 445 in ports):
            data.update(type='PC / servidor posible',type_confidence='Media')
    return data

def show_ids(ident):
    print(tint('\n[+] STALKER :: IDENTIFICACION PRELIMINAR'))
    rows=[[d['id'],d['ip'],d['vendor'],d['type'],d['os'],d['vendor_confidence'],d['type_confidence']] for d in ident]
    table(['ID','IP','FABRICANTE','TIPO ESTIMADO','SO ESTIMADO','CONF FAB','CONF TIPO'],rows,[3,15,27,23,19,8,9])
    print('  Las clasificaciones son estimaciones; Apple no implica iPhone.')

def choose(hosts,ident):
    valid=[d for d in ident if not d['mobile'] and d['type']!='Kali (LOCAL)']
    print(tint('\n[+] STALKER :: OBJETIVOS'))
    print(f'  [0] All IPs ({len(hosts)}; incluye Kali)')
    print(f'  [1] All non-mobile IPs ({len(valid)}; excluye Kali)')
    for d in valid:print(f"      [{d['id']}] {d['ip']} - {d['type']}")
    print('  [2] Custom - IDs separados por comas, ej. 1,3,5')
    while True:
        mode=input('  Selecciona [0/1/2] (q salir): ').strip().lower()
        if mode=='q':return []
        if mode=='0':selected=hosts
        elif mode=='1':selected=[hosts[d['id']-1] for d in valid]
        elif mode=='2':
            raw=input('  IDs: ').strip()
            parts=[p.strip() for p in raw.split(',')]
            if not parts or any(not p.isdigit() for p in parts):print('  Formato no valido');continue
            ids=list(dict.fromkeys(int(p) for p in parts))
            if any(i<1 or i>len(hosts) for i in ids):print('  ID fuera de rango');continue
            selected=[hosts[i-1] for i in ids]
        else:continue
        if selected:
            print('  Seleccionados: '+', '.join(h['ip'] for h in selected));return selected
        print('  Sin objetivos. Prueba otra opcion.')

def scan_one(host,mode,folder,index,total):
    ip=host['ip'];xml=folder/f'scan_{ip}.xml'
    cmd=['nmap','-n','-Pn','-sS','-sV','-sC','--script','vuln','-p-',
         '--stats-every','10s','-v','-oX',str(xml)]
    cmd += ['-T2','--max-rate','50'] if mode=='1' else ['-T3']
    cmd.append(ip)
    print(tint(f'\n[{index}/{total}] Analizando {ip}'))
    pct=0.;eta='desconocida';start=time.monotonic()
    try:
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                              text=True,bufsize=1,errors='replace')
        for line in proc.stdout:
            m=PERCENT.search(line)
            if m:
                pct=float(m.group(1));r=REMAIN.search(line)
                if r:eta=r.group(1)
                size=28;filled=min(size,round(size*pct/100))
                msg=f'\r  [{"#"*filled}{"-"*(size-filled)}] {pct:5.1f}%  ETA: {eta}'
                print(msg+' '*12,end='',flush=True)
            elif 'error' in line.lower() or 'failed' in line.lower():
                print('\n  '+line.strip()[:180])
        status=proc.wait()
    except KeyboardInterrupt:
        if 'proc' in locals() and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill()
        raise
    print(f'\n  Finalizado: {time.monotonic()-start:.0f}s | codigo {status}')
    rows=[]
    if not xml.exists():return rows
    try:root=ET.parse(xml).getroot()
    except ET.ParseError:return rows
    for h in root.findall('host'):
        host_cves=set()
        for script in h.findall('./hostscript/script'):
            host_cves.update(CVE.findall(ET.tostring(script,encoding='unicode')))
        open_ports=[]
        for p in h.findall('./ports/port'):
            st=p.find('state')
            if st is not None and st.get('state')=='open':open_ports.append(p)
        if not open_ports:
            rows.append({'ip':ip,'vendor':host['vendor'],'port':'-','service':'-','version':'-',
                         'cves':','.join(sorted(host_cves)) or '-'})
        for p in open_ports:
            svc=p.find('service');pcves=set(host_cves)
            for s in p.findall('script'):pcves.update(CVE.findall(ET.tostring(s,encoding='unicode')))
            rows.append({'ip':ip,'vendor':host['vendor'],
                         'port':p.get('portid','?')+'/'+p.get('protocol','tcp'),
                         'service':svc.get('name','-') if svc is not None else '-',
                         'version':' '.join(filter(None,[svc.get(k,'') for k in ('product','version','extrainfo')])) or '-' if svc is not None else '-',
                         'cves':','.join(sorted(pcves)) or '-'})
    return rows

def dump_json(path,data):path.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8')

def main():
    print(tint(BANNER));print(tint('  STALKER :: WATCHING THE WIRE :: v1.4',AMBER))
    for binary in ('arp-scan','nmap','ip'):
        if not shutil.which(binary):sys.exit(f'Falta {binary}: sudo apt install nmap arp-scan iproute2')
    if os.geteuid()!=0:sys.exit('Ejecuta con: sudo python3 stalker.py')
    try:dev,my_ip,gateway,network=netinfo()
    except Exception as e:sys.exit(f'Error de red: {e}')
    if network.num_addresses>4096:sys.exit('Subred demasiado grande (>4096 direcciones)')
    print(f'  Interface={dev} | Local={my_ip} | Gateway={gateway} | Network={network}')
    print('\n  [1] GHOST MODE: completo, menor velocidad (detectable)')
    print('  [2] HUNTER MODE: completo, velocidad normal')
    mode=input('  Modo [1/2]: ').strip()
    if mode not in ('1','2'):return
    print(tint('  Ambos modos generan tráfico y logs; algunos scripts vuln pueden ser intrusivos.',AMBER))
    if input('  ¿Red propia o autorizada? [s/N]: ').strip().lower() not in ('s','si','sí'):return
    folder=Path('stalker_reports')/datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    folder.mkdir(parents=True,exist_ok=True)
    hosts=discover(dev,my_ip,gateway,network,folder)
    show_hosts(hosts)
    dump_json(folder/'discovery.json',hosts)
    ident=[]
    print(tint('\n[*] Identificación preliminar...'))
    for i,h in enumerate(hosts,1):
        with Spinner(f'Identificando {i}/{len(hosts)}: {h["ip"]}'):
            ident.append(identify(h,folder))
    show_ids(ident)
    dump_json(folder/'identification.json',ident)
    selected=choose(hosts,ident)
    if not selected:return
    dump_json(folder/'selection.json',{'mode':mode,'ips':[h['ip'] for h in selected]})
    if input('  Pulsa INTRO para escanear (q salir): ').strip().lower()=='q':return
    rows=[]
    try:
        for i,h in enumerate(selected,1):rows.extend(scan_one(h,mode,folder,i,len(selected)))
    except KeyboardInterrupt:print('\n  Interrumpido; guardando resultados completados.')
    csvpath=folder/'report.csv'
    with csvpath.open('w',newline='',encoding='utf-8') as f:
        cols=['ip','vendor','port','service','version','cves'];w=csv.DictWriter(f,fieldnames=cols)
        w.writeheader();w.writerows(rows)
    print(tint('\n[+] STALKER :: RESULTADOS'))
    table(['IP','FABRICANTE','PUERTO','SERVICIO','VERSION','CVEs'],
          [[r[k] for k in ('ip','vendor','port','service','version','cves')] for r in rows],
          [15,24,10,14,30,28])
    print(f'  Informe CSV: {csvpath}\n  XML/JSON: {folder}')
    print('  Los CVE son referencias potenciales, no vulnerabilidades confirmadas.')

if __name__=='__main__':main()
