local Auth = require('auth')
local rows = dofile(assert(arg[1], 'contract Lua table required (run tests/test_auth.py)'))
local function equal(a,b)
 if type(a)~=type(b) then return false end
 if type(a)~='table' then return a==b end
 for k,v in pairs(a) do if not equal(v,b[k]) then return false end end
 for k,v in pairs(b) do if not equal(v,a[k]) then return false end end
 return true
end
for _,r in ipairs(rows) do
 local client=Auth.new(function(m,p,b,t)
  assert(m==r.method and p==r.path and equal(b,r.body) and t==r.token,'incorrect auth request')
  return 200,r.result
 end)
 assert(equal(client[r.op](client,table.unpack(r.args)),r.result),'incorrect auth response')
end
local c=Auth.new(function()return 401,{secret='DO_NOT_LOG'} end)
local ok,e=pcall(function()c:login('u','p','012345') end);assert(not ok and e.status==401)
local invalid=Auth.new(function()return 200,{} end)
for _,o in ipairs({123456,'12345','01234x','012345\n'}) do assert(not pcall(function()invalid:login('u','p',o) end)) end
for _,f in ipairs({'d','p','q','dp','dq','qi','oth','k'}) do assert(not pcall(function()invalid:signup('u','e','p',{{[f]='PRIVATE'}}) end)) end
print('Lua auth contract and validation passed')
