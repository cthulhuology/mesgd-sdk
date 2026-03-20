{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module PKI where

import Crypto.Error (CryptoFailable(..))
import Crypto.PubKey.DSA (PrivateKey(..), PublicKey(..))
import Crypto.PubKey.ECC.ECDSA (PrivateKey(..), PublicKey(..), Signature(..), sign, verify)
import Crypto.PubKey.ECC.Generate (generate)
import Crypto.PubKey.ECC.Prim (Curve(..), Point(..), ECCurve(..), getCurveByName)
import Crypto.PubKey.ECC.Types (Domain, Point(..), CurveName(..))
import Crypto.PubKey.RSA (PrivateKey(..), PublicKey(..), generate, decryptOAEP, encryptOAEP)
import Crypto.Hash (SHA256(..))
import Crypto.Random (newGenIO, withRandomBytesGen)
import qualified Crypto.Hash as Hash
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import Data.Aeson (ToJSON, FromJSON, deriveJSON, encode, decode)
import GHC.Generics (Generic)
import System.IO (IOMode(..), withFile)

data Keys = Keys
  { signingPriv :: PrivateKey
  , signingPub :: PublicKey
  , encryptingPriv :: PrivateKey
  , encryptingPub :: PublicKey
  } deriving (Show, Generic)

instance ToJSON Keys
instance FromJSON Keys

file :: FilePath
file = "pki_keys.json"

initPKI :: IO Keys
initPKI = do
  keys <- loadKeys
  case keys of
    Just k -> return k
    Nothing -> do
      gen <- newGenIO
      let curve = getCurveByName SEC_p256r1
      let (signingPriv, _) = withRandomBytesGen gen 32 $ \g -> generate curve g
      let signingPub = getPublicKey signingPriv
      let (encryptingPriv, _) = withRandomBytesGen gen 32 $ \g -> generate 2048 g
      let encryptingPub = getPublicKey encryptingPriv
      let newKeys = Keys signingPriv signingPub encryptingPriv encryptingPub
      saveKeys newKeys
      return newKeys

loadKeys :: IO (Maybe Keys)
loadKeys = do
  content <- BS.readFile file
  case decode content of
    Just k -> return (Just k)
    Nothing -> return Nothing

saveKeys :: Keys -> IO ()
saveKeys keys = do
  let content = encode keys
  withFile file WriteMode $ \h -> BS.hPut h content

sign :: Keys -> String -> String
sign keys message = B64.encode $ BS.pack $ BS.unpack $ encodeSignature $ sign (SHA256) (signingPriv keys) (BS.pack $ Hash.digestToHex $ Hash.hash $ BS.pack message)
  where
    encodeSignature (Signature r s) = Z.encode (r :: Integer) ++ Z.encode (s :: Integer)  -- Assuming Z for bigints

verify :: Keys -> String -> String -> Bool
verify keys message sigB64 = verify (SHA256) (signingPub keys) (BS.pack $ Hash.digestToHex $ Hash.hash $ BS.pack message) (decodeSignature $ B64.decodeLenient sigB64)
  where
    decodeSignature bs = let (r, rest) = Z.decode bs; (s, _) = Z.decode rest in Signature r s  -- Assuming Z for bigints

encrypt :: Keys -> String -> String
encrypt keys message = B64.encode $ encryptOAEP (SHA256) (BS.pack message) mempty (encryptingPub keys)

decrypt :: Keys -> String -> String
decrypt keys ctB64 = BS.unpack $ decryptOAEP (SHA256) mempty (B64.decodeLenient ctB64) (encryptingPriv keys)

-- Note: This uses simplified serialization; for production, use proper ASN.1 DER encoding.
-- Assuming 'Z' module for big integers (e.g., from integer-simple).

-- Usage example:
main :: IO ()
main = do
  keys <- initPKI
  let sig = sign keys "Hello World"
  putStrLn $ "Signature: " ++ sig
  putStrLn $ "Verify: " ++ show (verify keys "Hello World" sig)
  let enc = encrypt keys "Secret message"
  putStrLn $ "Encrypted: " ++ enc
  putStrLn $ "Decrypted: " ++ decrypt keys enc
