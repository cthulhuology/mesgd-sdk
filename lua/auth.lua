-- Inject transport(method, path, body_or_nil, token_or_nil) -> status, decoded_object.
local Auth = {}; Auth.__index = Auth
function Auth.new(transport) return setmetatable({transport=transport}, Auth) end
local function otp(code)
  assert(type(code)=='string' and #code==6 and code:match('^%d%d%d%d%d%d$'), 'OTP must be a six-digit string')
  return code
end
local function keys(values)
  assert(type(values)=='table' and #values<=2, 'expected at most two public JWKs')
  for _,k in ipairs(values) do
    assert(type(k)=='table', 'expected public JWKs')
    for _,f in ipairs({'d','p','q','dp','dq','qi','oth','k'}) do assert(k[f]==nil, 'private JWKs are not accepted') end
  end
  return values
end
function Auth:request(method,path,body,token)
  local status,result=self.transport(method,path,body,token)
  if status<200 or status>=300 then error({status=status,message='mesgd authentication failed'},0) end
  return result
end
function Auth:signup(user,email,password,public_keys) return self:request('POST','/auth/signup',{user=user,email=email,password=password,public_keys=keys(public_keys or {})}) end
function Auth:confirm(user,enrollment,code) return self:request('POST','/auth/signup/confirm',{user=user,enrollment_token=enrollment,otp=otp(code)}) end
function Auth:login(user,password,code) return self:request('POST','/auth/login',{user=user,password=password,otp=otp(code)}) end
function Auth:reset_password(user,recovery,password,code) return self:request('POST','/auth/password/reset',{user=user,recovery_code=recovery,new_password=password,otp=otp(code)}) end
function Auth:keys(token) return self:request('GET','/auth/keys',nil,token) end
function Auth:set_keys(token,password,code,public_keys) return self:request('PUT','/auth/keys',{password=password,otp=otp(code),public_keys=keys(public_keys)},token) end
function Auth:logout(token) return self:request('POST','/auth/logout',nil,token) end
return Auth
