#!/usr/bin/env python3
"""Bundle locked npm archives, checking integrity before replacing registry URLs."""
from pathlib import Path
import base64, concurrent.futures, hashlib, json, os, shutil, urllib.request
root=Path(__file__).resolve().parents[1]
cache=Path(os.environ.get('NPM_CACHE', str(Path.home()/'.npm')))/'_cacache/content-v2'
target=root/'vendor/npm-tarballs'; target.mkdir(exist_ok=True)
locks=[root/n/'package-lock.json' for n in ('door-app','door-contract','door-app/publish')]
origins=root/'vendor/npm-sources.json'
previous=json.loads(origins.read_text()) if origins.exists() else {}
items={}; docs=[]
for lock in locks:
 data=json.loads(lock.read_text());docs.append((lock,data))
 for p in data['packages'].values():
  if 'resolved' not in p: continue
  integrity=p['integrity']; algo,b64=integrity.split('-',1); digest=base64.b64decode(b64).hex()
  url=p['resolved']
  if url.startswith('file:'): url=previous[digest+'.tgz']
  items[integrity]=(url,algo,digest)
  p['resolved']='file:'+os.path.relpath(target/(digest+'.tgz'),lock.parent)
def fetch(item):
 url,algo,digest=item
 dest=target/(digest+'.tgz'); src=cache/algo/digest[:2]/digest[2:4]/digest[4:]
 data=dest.read_bytes() if dest.exists() else (src.read_bytes() if src.exists() else urllib.request.urlopen(url,timeout=120).read())
 if hashlib.new(algo,data).hexdigest()!=digest: raise ValueError(url)
 dest.write_bytes(data)
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
 list(pool.map(fetch,items.values()))
for lock,data in docs:lock.write_text(json.dumps(data,indent=2)+'\n')
(root/'vendor/npm-sources.json').write_text(json.dumps({digest+'.tgz':url for url,algo,digest in items.values()},indent=2)+'\n')
print('Vendored',len(items),'npm archives; rewrote all three locks to local files.')
