import json,os,ssl,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'python'))
from auth import AuthClient,AuthError,https_transport
r=json.load(sys.stdin)
c=AuthClient(https_transport(os.environ['MESGD_AUTH_URL'],context=ssl.create_default_context(cafile=os.environ['MESGD_AUTH_CA_FILE'])))
try: print(json.dumps({'result':getattr(c,r['op'])(*r['args'])}))
except AuthError as e: print(json.dumps({'status':e.status}))
