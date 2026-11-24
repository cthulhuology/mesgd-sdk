import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {AuthClient,AuthError,httpsTransport} from './auth.mjs';
const rows=JSON.parse(readFileSync(new URL('../fixtures/auth_contract.json',import.meta.url)));
const names={reset_password:'resetPassword',set_keys:'setKeys'};
for(const r of rows){
 const c=new AuthClient(async(m,p,b,t)=>{assert.deepEqual([m,p,b,t],[r.method,r.path,r.body,r.token]);return [200,r.result];});
 assert.deepEqual(await c[names[r.op]||r.op](...r.args),r.result);
}
const never=new AuthClient(()=>{throw new Error('invalid input reached transport');});
for(const code of [123456,'12345','01234x','012345\n','１２３４５６']) assert.throws(()=>never.login('u','p',code));
for(const f of ['d','p','q','dp','dq','qi','oth','k']) assert.throws(()=>never.signup('u','e','p',[{[f]:'PRIVATE'}]));
assert.throws(()=>httpsTransport('http://localhost'));
assert.throws(()=>httpsTransport('https://u:p@example.com'));
await assert.rejects(new AuthClient(async()=>[401,{secret:'DO_NOT_LOG'}]).login('u','p','012345'),e=>e instanceof AuthError&&e.status===401&&!e.message.includes('DO_NOT_LOG'));
// Verify actual fetch options, including redirect/cookie policy and string OTP.
const transport=httpsTransport('https://example.com',async(url,options)=>{
 assert.equal(url.href,'https://example.com/auth/login'); assert.equal(options.redirect,'error');
 assert.equal(options.credentials,'omit'); assert.equal(JSON.parse(options.body).otp,'012345');
 assert.equal(options.headers.Authorization,undefined);
 return {ok:true,status:200,json:async()=>({access_token:'token'})};
});
assert.equal((await new AuthClient(transport).login('u','p','012345')).access_token,'token');
console.log('JavaScript auth contract and validation passed');
