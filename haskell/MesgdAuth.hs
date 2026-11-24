{-# LANGUAGE OverloadedStrings #-}
module MesgdAuth where
import Control.Exception (Exception, throwIO)
import Control.Monad (unless)
import Data.Aeson (Value, object, (.=), toJSON)
import qualified Data.Map.Strict as M
import Data.Text (Text)
import qualified Data.Text as T

type Transport = Text -> Text -> Maybe Value -> Maybe Text -> IO (Int,Value)
data AuthError = HttpError Int | InvalidInput deriving (Show)
instance Exception AuthError
request :: Transport -> Text -> Text -> Maybe Value -> Maybe Text -> IO Value
request t m p b token = do
 (status,result) <- t m p b token
 if status>=200 && status<300 then pure result else throwIO (HttpError status)
otp :: Text -> IO Text
otp o = do
 unless (T.length o==6 && T.all (\c -> c>='0' && c<='9') o) (throwIO InvalidInput)
 pure o
publicKeys :: [M.Map Text Value] -> IO Value
publicKeys ks = do
 unless (length ks<=2 && all (\k -> all (\f -> M.notMember f k) ["d","p","q","dp","dq","qi","oth","k"]) ks) (throwIO InvalidInput)
 pure (toJSON ks)
signup t u e p ks = do
 k <- publicKeys ks
 request t "POST" "/auth/signup" (Just(object["user" .= (u::Text),"email" .= (e::Text),"password" .= (p::Text),"public_keys" .= k])) Nothing
confirm t u enrollment code = do
 o <- otp code
 request t "POST" "/auth/signup/confirm" (Just(object["user" .= (u::Text),"enrollment_token" .= (enrollment::Text),"otp" .= o])) Nothing
login t u p code = do
 o <- otp code
 request t "POST" "/auth/login" (Just(object["user" .= (u::Text),"password" .= (p::Text),"otp" .= o])) Nothing
resetPassword t u r p code = do
 o <- otp code
 request t "POST" "/auth/password/reset" (Just(object["user" .= (u::Text),"recovery_code" .= (r::Text),"new_password" .= (p::Text),"otp" .= o])) Nothing
keys t token = request t "GET" "/auth/keys" Nothing (Just token)
setKeys t token p code ks = do
 o <- otp code
 k <- publicKeys ks
 request t "PUT" "/auth/keys" (Just(object["password" .= (p::Text),"otp" .= o,"public_keys" .= k])) (Just token)
logout t token = request t "POST" "/auth/logout" Nothing (Just token)
