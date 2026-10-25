#!/usr/bin/env python3
"""Create one version-7 raw artifact. Never persist credentials or signed URLs."""
import base64, datetime, hashlib, http.client, json, os, pathlib, urllib.parse

OUT = pathlib.Path('evidence'); OUT.mkdir(exist_ok=True)
LOG = OUT / 'fixture.jsonl'
TOKEN = os.environ['ACTIONS_RUNTIME_TOKEN']
GH_TOKEN = os.environ['GH_TOKEN']
claims = json.loads(base64.urlsafe_b64decode(TOKEN.split('.')[1] + '==='))
scope = next(v for v in claims['scp'].split() if v.startswith('Actions.Results:')).split(':')
PLAN, JOB = scope[1:]
RESULTS = urllib.parse.urlsplit(os.environ['ACTIONS_RESULTS_URL'])
ORIGIN = RESULTS.scheme + '://' + RESULTS.netloc
NAME = 'transfer-sentinel.json'
DATA = b'{"experiment":"artifact-transfer","sequence":1}\n'
STORED = 'application/json\x85'

def shape(url):
    u = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    return {'host':u.hostname, 'path':u.path,
            'path_sha256':hashlib.sha256(u.path.encode()).hexdigest(),
            'parameter_names':sorted(q),
            'selected_parameters':{k:q.get(k) for k in ['rsct','rscd','sv','skv','api-version']}}

def clean(value):
    if isinstance(value,dict):
        return {k:('[REDACTED]' if k.lower() in ['authorization','token','sig','signature'] else clean(v)) for k,v in value.items()}
    if isinstance(value,list): return [clean(v) for v in value]
    if isinstance(value,str) and value.startswith(('http://','https://')): return shape(value)
    return value

def event(label, **kw):
    row = clean({'label':label,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**kw})
    with LOG.open('a') as f: f.write(json.dumps(row,ensure_ascii=True)+'\n')
    print(json.dumps(row,ensure_ascii=True),flush=True)

def exchange(label,method,url,body=None,headers=None,token=None):
    u=urllib.parse.urlsplit(url)
    h={'User-Agent':'artifact-transfer-audit/1',**(headers or {})}
    if token:h['Authorization']='Bearer '+token
    sent=json.dumps(body,separators=(',',':')).encode() if isinstance(body,dict) else body
    if isinstance(body,dict):h.setdefault('Content-Type','application/json')
    c=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=30)
    try:
        c.request(method,u.path+('?' + u.query if u.query else ''),body=sent,headers=h)
        r=c.getresponse();data=r.read();rh={k.lower():v for k,v in r.getheaders()}
        try: obj=json.loads(data)
        except (ValueError,UnicodeDecodeError):obj=None
        event(label,method=method,url=shape(url),status=r.status,
              request=body if isinstance(body,dict) else {'body_bytes':len(sent or b'')},
              request_headers={k:v for k,v in h.items() if k.lower()!='authorization'},
              request_blob_property_bytes_hex=h.get('x-ms-blob-content-type','').encode('latin-1').hex(),
              response_headers={k:v for k,v in rh.items() if k in ['content-type','content-length','content-disposition','etag','last-modified','x-ms-version','x-ms-error-code','location','x-github-request-id']},
              content_type_bytes_hex=rh.get('content-type','').encode('latin-1').hex(),
              response=obj,body_bytes=len(data),body_sha256=hashlib.sha256(data).hexdigest())
        return r.status,rh,obj,data
    finally:c.close()

def rpc(label,method,body):
    s,h,o,d=exchange(label,'POST',ORIGIN+'/twirp/github.actions.results.api.v1.ArtifactService/'+method,body,token=TOKEN)
    assert s==200, (label,s)
    return o

def download(label,url,token=None,old=False):
    for hop in range(6):
        headers={'Accept':'application/vnd.github+json'}
        if old:headers['x-ms-version']='2009-09-19'
        s,h,o,d=exchange(label+'.hop'+str(hop),'GET',url,headers=headers,token=token)
        if s in [301,302,303,307,308] and 'location' in h:
            new=urllib.parse.urljoin(url,h['location'])
            if urllib.parse.urlsplit(new).netloc != urllib.parse.urlsplit(url).netloc:token=None
            url=new
        else:return s,h,d
    raise RuntimeError('Too many redirects')

ids={'workflow_run_backend_id':PLAN,'workflow_job_run_backend_id':JOB}
created=rpc('create','CreateArtifact',{**ids,'name':NAME,'version':7,'mime_type':'application/json'})
upload=created['signed_upload_url']
s,_,_,_=exchange('blob.put','PUT',upload,DATA,{'Content-Type':'application/octet-stream',
    'x-ms-version':'2023-11-03','x-ms-blob-type':'BlockBlob','x-ms-blob-content-type':STORED})
assert s==201,s
final=rpc('finalize','FinalizeArtifact',{**ids,'name':NAME,'size':str(len(DATA)),
    'hash':'sha256:'+hashlib.sha256(DATA).hexdigest()})
aid=str(final['artifact_id'])
rpc('list','ListArtifacts',{**ids,'id_filter':aid})
signed=rpc('results.sign','GetSignedArtifactURL',{**ids,'name':NAME})['signed_url']
for old in [False,True]:
    s,h,d=download('results.download.'+('old-version' if old else 'default'),signed,old=old)
    assert s==200 and d==DATA,(s,len(d))
    expected=STORED if old else 'application/json'
    assert h['content-type']==expected,(h['content-type'].encode('latin-1').hex(),expected.encode('latin-1').hex())
repo=os.environ['GITHUB_REPOSITORY'];run=os.environ['GITHUB_RUN_ID']
for old in [False,True]:
    s,h,d=download('rest.download.'+('old-version' if old else 'default'),
        f'https://api.github.com/repos/{repo}/actions/artifacts/{aid}/zip',GH_TOKEN,old)
    assert s==200 and d==DATA,(s,len(d))
state={'repository':repo,'run_id':run,'artifact_id':aid,'name':NAME,'protocol_version':7,
       'create_mime_type':'application/json','stored_content_type_bytes_hex':STORED.encode('latin-1').hex(),
       'body_bytes':len(DATA),'body_sha256':hashlib.sha256(DATA).hexdigest(),
       'run_backend_id':PLAN,'job_backend_id':JOB,'blob':shape(signed)}
(OUT/'state.json').write_text(json.dumps(state,indent=2)+'\n')
event('fixture.ready',state=state)
