#!/usr/bin/env python3
"""Two small controls distinguish filename guessing from older protocol behavior."""
import hashlib,io,json,os,zipfile
from probe import PLAN,JOB,ORIGIN,TOKEN,GH_TOKEN,DATA,STORED,OUT,exchange,rpc,download,event,shape

ids={'workflow_run_backend_id':PLAN,'workflow_job_run_backend_id':JOB}
buf=io.BytesIO()
with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_STORED) as z:
    z.writestr(zipfile.ZipInfo('body.json',date_time=(1980,1,1,0,0,0)),DATA)
cases=[('name-says-zip.zip',7,'application/json',DATA),
       ('v4-mime-omitted',4,None,buf.getvalue())]
states=[]
for name,version,mime,data in cases:
    req={**ids,'name':name,'version':version}
    if mime is not None:req['mime_type']=mime
    upload=rpc(name+'.create','CreateArtifact',req)['signed_upload_url']
    status,_,_,_=exchange(name+'.put','PUT',upload,data,{'Content-Type':'application/octet-stream',
        'x-ms-version':'2023-11-03','x-ms-blob-type':'BlockBlob','x-ms-blob-content-type':STORED})
    assert status==201,status
    aid=str(rpc(name+'.finalize','FinalizeArtifact',{**ids,'name':name,'size':str(len(data)),
        'hash':'sha256:'+hashlib.sha256(data).hexdigest()})['artifact_id'])
    url=rpc(name+'.sign','GetSignedArtifactURL',{**ids,'name':name})['signed_url']
    for old in [False,True]:
        s,h,d=download(name+'.download.'+('old-version' if old else 'default'),url,old=old)
        assert s==200 and d==data,(s,len(d))
    state={'repository':os.environ['GITHUB_REPOSITORY'],'run_id':os.environ['GITHUB_RUN_ID'],
           'name':name,'protocol_version':version,'create_mime_type':mime,'artifact_id':aid,
           'body_bytes':len(data),'body_sha256':hashlib.sha256(data).hexdigest(),'blob':shape(url),
           'run_backend_id':PLAN,'job_backend_id':JOB}
    states.append(state)
status,_,_,_=exchange('v7.missing-mime.create','POST',
    ORIGIN+'/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact',
    {**ids,'name':'v7-missing-mime','version':7},token=TOKEN)
result={'cases':states,'v7_missing_mime_create_status':status}
(OUT/'controls-state.json').write_text(json.dumps(result,indent=2)+'\n')
event('metadata-controls.ready',state=result)
