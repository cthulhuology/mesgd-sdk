-- Requires: luarocks install openssl
local openssl = require('openssl')

-- Simple Base64 encode/decode for Lua (public domain implementation)
local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function base64_encode(data)
    return ((data:gsub('.', function(x)
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

local function base64_decode(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

local PKI = {}
local signing_priv, signing_pub, encrypting_priv, encrypting_pub

local files = {
    signing_priv = 'signing_priv.pem',
    signing_pub = 'signing_pub.pem',
    encrypting_priv = 'encrypting_priv.pem',
    encrypting_pub = 'encrypting_pub.pem'
}

function PKI.init()
    if openssl.load_private_key(files.signing_priv) then
        signing_priv = openssl.load_private_key(files.signing_priv)
        signing_pub = openssl.load_public_key(files.signing_pub)
        encrypting_priv = openssl.load_private_key(files.encrypting_priv)
        encrypting_pub = openssl.load_public_key(files.encrypting_pub)
        return
    end

    -- Generate signing keypair (ECDSA P-256)
    signing_priv = openssl.evp_new('ec', nil, {curve = 'prime256v1'})
    signing_pub = signing_priv.pubkey

    -- Generate encrypting keypair (RSA 2048)
    encrypting_priv = openssl.evp_new('rsa', 2048)
    encrypting_pub = encrypting_priv.pubkey

    -- Save to PEM files
    local f = io.open(files.signing_priv, 'w')
    f:write(signing_priv:tostring('PEM'))
    f:close()

    f = io.open(files.signing_pub, 'w')
    f:write(signing_pub:tostring('PEM'))
    f:close()

    f = io.open(files.encrypting_priv, 'w')
    f:write(encrypting_priv:tostring('PEM'))
    f:close()

    f = io.open(files.encrypting_pub, 'w')
    f:write(encrypting_pub:tostring('PEM'))
    f:close()
end

function PKI.sign(message)
    if not signing_priv then PKI.init() end
    local signature = signing_priv:sign(message, 'sha256')
    return base64_encode(signature)
end

function PKI.verify(message, signature_b64)
    if not signing_pub then PKI.init() end
    local signature = base64_decode(signature_b64)
    return signing_pub:verify(message, signature, 'sha256')
end

function PKI.encrypt(message)
    if not encrypting_pub then PKI.init() end
    local ciphertext = encrypting_pub:encrypt(message, 'oaep', 'sha256')
    return base64_encode(ciphertext)
end

function PKI.decrypt(ciphertext_b64)
    if not encrypting_priv then PKI.init() end
    local ciphertext = base64_decode(ciphertext_b64)
    local plaintext = encrypting_priv:decrypt(ciphertext, 'oaep', 'sha256')
    return plaintext
end

-- Usage example:
-- PKI.init()
-- local sig = PKI.sign('Hello World')
-- print(PKI.verify('Hello World', sig))  -- true
-- local enc = PKI.encrypt('Secret message')
-- print(PKI.decrypt(enc))  -- Secret message
