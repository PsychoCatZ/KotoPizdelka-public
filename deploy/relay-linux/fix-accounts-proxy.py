#!/usr/bin/env python3
"""Allow account API in the existing KotoPizdelka Caddy matcher only."""
import os,re,subprocess,sys,time
from pathlib import Path
if os.geteuid()!=0:sys.exit('Run with sudo/root.')
p=Path('/etc/kotopizdelka-relay/Caddyfile')
if p.is_symlink() or not p.is_file():sys.exit('Unexpected config path; nothing changed.')
original=p.read_bytes();text=original.decode()
pattern=r'(?m)^(\s*@client\s+path\s+/health\s+/v1/queues/\*)(\s*)$'
already=r'(?m)^\s*@client\s+path\s+/health\s+/v1/queues/\*\s+/v1/accounts/\*\s*$'
if re.search(already,text):sys.exit('Account API matcher already present; nothing changed.')
if len(list(re.finditer(pattern,text)))!=1:sys.exit('Expected one KotoPizdelka matcher; nothing changed.')
updated=re.sub(pattern,lambda m:m[1]+' /v1/accounts/*'+m[2],text).encode()
backup_dir=Path('/var/backups/kotopizdelka-relay')
backup_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
if backup_dir.is_symlink() or backup_dir.stat().st_uid!=0 or backup_dir.stat().st_mode & 0o077:sys.exit('Unsafe backup directory; nothing changed.')
backup=backup_dir/('Caddyfile.before-accounts-'+str(time.time_ns()))
fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(original);f.flush();os.fsync(f.fileno())
# Write in place: keep inode, permissions and ownership used by the proxy unit.
def write(data):
 with p.open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def validate():
 return subprocess.run(['sudo','-u','kotopizdelka-proxy','env','XDG_DATA_HOME=/var/lib/kotopizdelka-proxy/data','XDG_CONFIG_HOME=/var/lib/kotopizdelka-proxy/config','/opt/kotopizdelka-relay/bin/caddy','validate','--config',str(p),'--adapter','caddyfile'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
try:
 write(updated)
 if not validate():raise RuntimeError('Caddy validation failed')
 if subprocess.run(['systemctl','restart','kotopizdelka-relay-proxy.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:raise RuntimeError('Proxy restart failed')
 if subprocess.run(['systemctl','is-active','--quiet','kotopizdelka-relay-proxy.service']).returncode:raise RuntimeError('Proxy not active')
except BaseException:
 write(original)
 subprocess.run(['systemctl','restart','kotopizdelka-relay-proxy.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 sys.exit('Fix failed; original config restored. Backup: '+str(backup))
print('Account API allowed; proxy active. Backup: '+str(backup))
print('Only the existing KotoPizdelka matcher was extended. Proxy connections may briefly reconnect.')
