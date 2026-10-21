@chcp 65001 >nul & set PYTHONIOENCODING=utf-8 & py -3 -x "%~f0" %* & pause & exit /b
# -*- coding: utf-8 -*-
"""One-file Windows BAT + Python Goke deployment, standard library only."""
import datetime
import ftplib
import hashlib
import io
import ipaddress
import os
import re
import socket
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

OLD_IP='192.168.1.25'
MASK='255.255.0.0'
LOGIN='root'
PASSWORD='123456'
ARCHIVE=Path(__file__).resolve().with_name('GOKE_CLONE.tar.gz')
REQUIRED=['goke/start.sh','goke/disable_stock.sh','goke/goke_video_manager.sh',
          'goke/bin/goke_shm_detect','goke/bin/goke_mjpeg_web_v4']


def info(s): print(s,flush=True)

def ftp_open(host,timeout=6):
    f=ftplib.FTP()
    f.connect(host,21,timeout=timeout)
    try:
        f.login('anonymous','goke@local')
    except ftplib.error_perm:
        f.login(LOGIN,PASSWORD)
    return f

def ftp_read(f,path):
    chunks=[]
    f.retrbinary('RETR '+path,chunks.append)
    return b''.join(chunks)

def ftp_exists(f,path):
    try: return ftp_read(f,path)
    except ftplib.error_perm: return None

def ftp_write(f,path,data):
    f.storbinary('STOR '+path,io.BytesIO(data))
    if ftp_read(f,path)!=data:
        raise RuntimeError('FTP: файл не співпадає після передачі: '+path)

def ftp_dirs(f,path):
    parts=path.split('/')[:-1]
    prefix=''
    for part in parts:
        prefix=prefix+'/'+part if prefix else part
        try: f.mkd(prefix)
        except ftplib.error_perm: pass

def tar_content():
    if not ARCHIVE.is_file():
        raise RuntimeError('Немає GOKE_CLONE.tar.gz поруч із BAT: '+str(ARCHIVE))
    out={}
    with tarfile.open(ARCHIVE,'r:gz') as archive:
        for member in archive.getmembers():
            name=member.name.replace('\\','/').removeprefix('./')
            if not name or member.isdir(): continue
            if name.startswith('/') or '..' in name.split('/'):
                raise RuntimeError('Небезпечний шлях в архіві: '+name)
            if not member.isfile(): continue
            if not name.startswith('goke/'):
                raise RuntimeError('Архів повинен містити файли всередині папки goke/: '+name)
            out[name]=archive.extractfile(member).read()
    missing=[p for p in REQUIRED if p not in out]
    if missing: raise RuntimeError('Не вистачає файлів в архіві: '+', '.join(missing))
    return out

def mac_new():
    stamp=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')
    digest=hashlib.sha256((stamp+str(os.getpid())).encode()).digest()
    return '02:'+':'.join('%02x'%x for x in digest[:5])

def network_scripts(ip,mac):
    network='''#!/bin/sh
ROOT=/mnt/s0/goke
mkdir -p "$ROOT/logs"
LOG="$ROOT/logs/network_identity.log"
echo "NET CONFIG $(date) IP=__IP__ MAC=__MAC__" >> "$LOG"
killall udhcpc 2>/dev/null
ifconfig eth0 down >> "$LOG" 2>&1
ifconfig eth0 hw ether __MAC__ >> "$LOG" 2>&1
ifconfig eth0 __IP__ netmask 255.255.0.0 up >> "$LOG" 2>&1
ifconfig eth0 >> "$LOG" 2>&1
/bin/sh "$ROOT/network_guard.sh" >> "$ROOT/logs/network_guard.log" 2>&1 &
'''.replace('__IP__',ip).replace('__MAC__',mac)
    guard='''#!/bin/sh
WANT_IP=__IP__
WANT_MAC=__MAC__
LOG=/mnt/s0/goke/logs/network_guard.log
if [ -f /tmp/goke_net_guard_v2.pid ]; then
  OLD=$(cat /tmp/goke_net_guard_v2.pid)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then exit 0; fi
fi
echo $$ > /tmp/goke_net_guard_v2.pid
echo "guard started $(date)"
while :; do
  killall udhcpc 2>/dev/null
  CURRENT_MAC=$(cat /sys/class/net/eth0/address 2>/dev/null)
  if [ "$CURRENT_MAC" != "$WANT_MAC" ]; then
    ifconfig eth0 down
    ifconfig eth0 hw ether "$WANT_MAC"
    ifconfig eth0 "$WANT_IP" netmask 255.255.0.0 up
    echo "MAC restored $(date)" >> "$LOG"
  fi
  if ! ifconfig eth0 2>/dev/null | grep -q "inet addr:$WANT_IP "; then
    ifconfig eth0 "$WANT_IP" netmask 255.255.0.0 up
    echo "IP restored $(date)" >> "$LOG"
  fi
  sleep 5
done
'''.replace('__IP__',ip).replace('__MAC__',mac)
    return network.encode('ascii'),guard.encode('ascii')

def integrate_start(content):
    s=content.decode('utf-8','replace')
    lines=[]
    for ln in s.splitlines():
        # Remove earlier generated network hook to prevent double execution.
        if ('network_identity.sh' in ln and not ln.lstrip().startswith('#')) or '# GOKE_NET_V2' in ln:
            continue
        lines.append(ln)
    idx=next((i for i,ln in enumerate(lines) if 'disable_stock.sh' in ln and not ln.lstrip().startswith('#')),None)
    if idx is None:
        idx=next((i for i,ln in enumerate(lines) if 'goke_video_manager.sh' in ln and not ln.lstrip().startswith('#')),None)
    if idx is None:
        raise RuntimeError('У start.sh немає виклику disable_stock.sh або goke_video_manager.sh')
    lines.insert(idx,'/bin/sh /mnt/s0/goke/network_identity.sh # GOKE_NET_V2')
    return ('\n'.join(lines)+'\n').encode('utf-8')

class Telnet:
    def __init__(self,host):
        self.sock=socket.create_connection((host,23),timeout=7)
        self.sock.settimeout(0.6)
        self.buf=''
        self.iac=0
        self.neg=0
    def recv(self,duration=0.6):
        until=time.monotonic()+duration
        while time.monotonic()<until:
            try: raw=self.sock.recv(8192)
            except socket.timeout: continue
            if not raw: raise ConnectionError('Telnet розірвано')
            decoded=bytearray()
            for x in raw:
                if self.iac==0:
                    if x==255:self.iac=1
                    else:decoded.append(x)
                elif self.iac==1:
                    if x in (251,252,253,254):self.neg=x;self.iac=2
                    elif x==255:decoded.append(255);self.iac=0
                    else:self.iac=0
                else:
                    if self.neg==253:self.sock.sendall(bytes((255,252,x)))
                    elif self.neg==251:self.sock.sendall(bytes((255,254,x)))
                    self.iac=0
            self.buf+=decoded.decode('utf-8','replace').replace('\r','')
    def send(self,s): self.sock.sendall((s+'\n').encode('ascii'))
    def login(self):
        user_sent=False
        password_sent=False
        limit=time.monotonic()+17
        while time.monotonic()<limit:
            self.recv(0.6)
            tail=self.buf[-600:]
            if re.search(r'(?:login|username)\s*:\s*$',tail,re.I) and not user_sent:
                self.send(LOGIN);user_sent=True;self.buf='';continue
            if re.search(r'password\s*:\s*$',tail,re.I) and not password_sent:
                self.send(PASSWORD);password_sent=True;self.buf='';continue
            if 'login incorrect' in tail.lower():raise RuntimeError('Telnet: невірні root/123456')
            if re.search(r'(?:^|\n)[^\n]{0,90}[#\$]\s*$',tail):
                self.buf=''
                return
        raise RuntimeError('Telnet: не вдалося увійти. '+repr(self.buf[-160:]))
    def command(self,line,timeout=18):
        # Distinct start/end markers avoid parsing echoed commands as results.
        marker='__GOKE_RESULT_837261__'
        start='__GOKE_BEGIN_837261__'
        self.buf=''
        self.send('echo '+start+'; '+line+'; rc=$?; echo; echo '+marker+':$rc')
        limit=time.monotonic()+timeout
        while time.monotonic()<limit:
            self.recv(0.5)
            begin=self.buf.find(start)
            # The first occurrence may be the terminal's echoed command.
            begin=self.buf.find('\n'+start,begin+len(start)) if begin>=0 else -1
            if begin<0:
                # Some Telnet consoles do not echo commands.
                match_begin=re.search(r'(?m)^'+start+r'\s*$',self.buf)
                if match_begin:begin=match_begin.start()-1
            if begin>=0:
                text=self.buf[begin+len(start)+1:]
                match=re.search(r'(?m)^'+marker+r':(\d+)\s*$',text)
                if match:
                    return int(match.group(1)),text[:match.start()].strip()
        raise TimeoutError('Telnet: тайм-аут команди '+line+' '+repr(self.buf[-240:]))
    def require(self,line,timeout=18):
        code,out=self.command(line,timeout)
        if code:raise RuntimeError('Помилка виконання: '+line+'\n'+out[-350:])
        return out
    def close(self):
        try:self.sock.close()
        except Exception:pass


def patch_config(t):
    path='/rom/config/video_channel_cfg.ini'
    t.require('cp '+path+' /mnt/s0/goke/video_factory_backup.ini')
    # Only master section values. Standalone BusyBox sed -i rules; no variable-width editing of other sections.
    for old,new in [('codec_type=2','codec_type=1'),('width=1920','width=1280'),
                    ('height=1080','height=720'),('frame_rate=30','frame_rate=25'),
                    ('bitrate=288','bitrate=1200'),('rate_ctrl=1','rate_ctrl=0'),
                    ('iframe_interval=50','iframe_interval=25')]:
        t.require('sed -i s/'+old+'/'+new+'/g '+path)
    settings=t.require('cat '+path)
    master=settings.partition('[master_channel_info0]')[2].partition('[slave_channel_info0]')[0]
    for k,v in [('codec_type','1'),('width','1280'),('height','720'),('frame_rate','25'),
                ('bitrate','1200'),('rate_ctrl','0')]:
        if not re.search(r'(?m)^'+re.escape(k)+'='+re.escape(v)+r'\s*$',master):
            raise RuntimeError('Невірний параметр відео '+k+'='+v+'; поточне: '+master)
    return master


def check_identity(ip,mac,remaining=135):
    cutoff=time.monotonic()+remaining
    last='Ще немає відповіді'
    while time.monotonic()<cutoff:
        try:
            with ftp_open(ip,timeout=3) as f:
                found=ftp_read(f,'goke/network_identity.sh')
                if mac.encode() not in found:
                    raise RuntimeError('На новому IP інший Goke або старий файл MAC')
            t=Telnet(ip)
            try:
                t.login()
                foundmac=t.require('cat /sys/class/net/eth0/address').strip().lower().splitlines()[-1]
                if foundmac!=mac:
                    raise RuntimeError('MAC: очікується '+mac+', фактично '+foundmac)
                cfg=t.require('cat /rom/config/video_channel_cfg.ini')
                master=cfg.partition('[master_channel_info0]')[2].partition('[slave_channel_info0]')[0]
                checks=[('codec_type','1'),('width','1280'),('height','720'),('frame_rate','25'),('bitrate','1200'),('rate_ctrl','0')]
                for k,v in checks:
                    if not re.search(r'(?m)^'+k+'='+v+r'\s*$',master):
                        raise RuntimeError('Відео: неправильний '+k)
                ipdump=t.require('ifconfig eth0')
                if ('inet addr:'+ip) not in ipdump and ('inet '+ip) not in ipdump:
                    raise RuntimeError('ifconfig не показує IP '+ip)
                ready=t.command('test -f /tmp/goke_video/READY')[0]==0
                env=t.command('cat /tmp/goke_video/camera.env')
                info('\nПЕРЕВІРЕНО: FTP, Telnet, IP, MAC і параметри відеокодера.')
                info('IP: '+ip+'  MAC: '+foundmac)
                info('Відео: 1280x720, 25 FPS, codec_type=1, bitrate=1200, rate_ctrl=0')
                info('SHM/READY: '+('ГОТОВО' if ready else 'ЩЕ НЕ ГОТОВО'))
                if ready and env[0]==0: info('Дані камери:\n'+env[1])
                return ready
            finally:t.close()
        except Exception as exc:
            last=str(exc)
        time.sleep(4)
    raise RuntimeError('Після перезавантаження новий IP не підтверджено: '+last)


def main():
    info('==============================================')
    info('     GOKE: АВТОМАТИЧНЕ ВСТАНОВЛЕННЯ КЛОНА')
    info('==============================================')
    info('Початкова IP прошивки BIN: '+OLD_IP)
    info('FTP: порт 21, Telnet: root / 123456, маска: '+MASK)
    info('Підключіть тільки ОДИН клонований Goke до мережі.')
    archive=tar_content()
    info('Архів перевірено: '+str(len(archive))+' файлів.')
    raw=input('Введіть останнє число нової IP [26]: ').strip() or '26'
    if not raw.isdecimal() or int(raw)<2 or int(raw)>254 or int(raw)==25:
        raise ValueError('Потрібне число від 2 до 254, окрім 25.')
    newip='192.168.1.'+str(int(raw))
    mac=mac_new()
    try:
        with socket.create_connection((newip,21),timeout=1):
            raise RuntimeError('Нова IP вже зайнята FTP-пристроєм: '+newip)
    except (ConnectionRefusedError,TimeoutError,OSError):
        pass
    info('Буде встановлено IP '+newip+' і MAC '+mac)
    # Check both services before mutating any on-device content.
    t=Telnet(OLD_IP)
    try:
        t.login()
        info('1/5 Telnet: з’єднання встановлено.')
        info('FTP: створюємо папку goke, навіть якщо SD повністю порожня.')
        # Verify ability to access current device via FTP before writing anything.
        with ftp_open(OLD_IP) as f:
            current=ftp_exists(f,'goke/start.sh')
            # Prepare derived contents before writing.
            start=integrate_start(archive['goke/start.sh'])
            network,guard=network_scripts(newip,mac)
            # Backup currently operational script if it has not been backed up before.
            if current and ftp_exists(f,'goke/start_before_auto_install.sh') is None:
                ftp_write(f,'goke/start_before_auto_install.sh',current)
            info('2/5 Передавання файлів на SD через FTP...')
            for p,data in sorted(archive.items()):
                ftp_dirs(f,p)
                # On deployment do not copy archived auto-network identity or archived start.sh.
                if p in ('goke/network_identity.sh','goke/network_guard.sh','goke/start.sh'):
                    continue
                ftp_write(f,p,data)
            ftp_dirs(f,'goke/logs/.keep')
            ftp_write(f,'goke/network_guard.sh',guard)
            ftp_write(f,'goke/network_identity.sh',network)
            ftp_write(f,'goke/start.sh',start)
        info('3/5 Файли записані й перевірені повторним читанням FTP.')
        cfg=patch_config(t)
        info('4/5 Відеокодер налаштовано: 1280x720 25 FPS, codec_type=1.')
        # Avoid disconnecting current ssh/telnet by changing IP live; reboot uses auto-hook.
        info('5/5 Перезавантаження Goke. Очікуємо нове з’єднання...')
        t.send('reboot')
    finally:t.close()
    ready=check_identity(newip,mac)
    # When READY isn't present after first reachability, wait extra 60 sec for video.
    if not ready:
        end=time.monotonic()+60
        while time.monotonic()<end:
            try:
                with urllib.request.urlopen('http://'+newip+':8080/status',timeout=3) as response:
                    if response.status==200:
                        info('HTTP відеосервер: ВІДПОВІДАЄ (200)')
                        ready=True
                        break
            except Exception:pass
            time.sleep(4)
    info('Адреса відео: http://'+newip+':8080/video1')
    info('Перевірка відеосервера: '+('ОК' if ready else 'НЕ ПІДТВЕРДЖЕНА, перегляньте SHM-журнал'))
    if not ready:
        info('Діагностика на новій IP: перевірте camera.env і SHM-журнал.');sys.exit(2)

if __name__=='__main__':
    try:main()
    except KeyboardInterrupt:info('Зупинено користувачем.');sys.exit(130)
    except Exception as exc:info('\nПОМИЛКА: '+str(exc));sys.exit(1)
