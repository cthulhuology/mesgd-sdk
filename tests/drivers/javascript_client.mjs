import {readFileSync} from 'node:fs';
import {AuthClient,AuthError,httpsTransport} from '../../javascript/auth.mjs';
const r=JSON.parse(readFileSync(0,'utf8'));
const c=new AuthClient(httpsTransport(process.env.MESGD_AUTH_URL));
const names={reset_password:'resetPassword',set_keys:'setKeys'};
try{console.log(JSON.stringify({result:await c[names[r.op]||r.op](...r.args)}));}
catch(e){if(!(e instanceof AuthError))throw e;console.log(JSON.stringify({status:e.status}));}
