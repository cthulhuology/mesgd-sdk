{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- mesgd-sdk Haskell Ping/Pong Sample
-- =====================================
-- Demonstrates the full mesgd-sdk lifecycle in Haskell:
--   1. Initialise local PKI keys (crypton)
--   2. Register our public keys with the mesgd echo server
--   3. Open a TLS WebSocket connection (websockets + wuss)
--   4. Send 3 signed+encrypted "ping" messages
--   5. Receive and verify the echoed "pong" response each time
--
-- Build: cabal build
-- Run:   cabal run pki-sample

module Main where

import           Control.Exception          (SomeException, catch, throwIO)
import           Control.Monad              (forM_)
import           Data.Aeson                 (Value, eitherDecode, encode,
                                             object, (.=))
import qualified Data.ByteString.Char8      as BC
import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import           Data.IORef
import           Data.Maybe                 (fromMaybe)
import qualified Data.Text                  as T
import qualified Data.Text.IO               as TIO
import           Network.URI                (parseURI, uriAuthority,
                                             uriRegName, uriPort, uriPath,
                                             uriScheme)
import qualified Network.WebSockets         as WS
import           System.Environment         (lookupEnv)
import           System.Exit                (exitFailure)
import           System.IO                  (hPutStrLn, stderr)

-- SDK modules (conceptually in the same package in a real workspace)
import qualified PKI    -- pki.hs / PKI module from SDK root
import qualified Mesgd  -- mesgd.hs / Mesgd module from SDK root

main :: IO ()
main = do
    putStrLn "=== mesgd-sdk Haskell Ping/Pong Sample ===\n"

    -- Configuration from environment variables
    mesgdUrl   <- fromMaybe "wss://echo.mesgd.org/ws" <$> lookupEnv "MESGD_URL"
    pubJwkPath <- fromMaybe "mesgd_pub.json"           <$> lookupEnv "MESGD_PUB_JWK"
    let rounds = 3 :: Int

    -- ------------------------------------------------------------------
    -- Step 1: Initialise PKI
    --   Loads pki_keys.json or generates ECDSA P-256 + RSA-2048 key
    --   pairs using the crypton library and saves as JWK JSON.
    -- ------------------------------------------------------------------
    putStrLn "Step 1: Initialising PKI …"
    keys <- PKI.initPKI `catch` (\(e :: SomeException) -> do
        hPutStrLn stderr $ "ERROR: PKI init failed: " ++ show e
        exitFailure)
    putStrLn "        Keys ready.\n"

    -- ------------------------------------------------------------------
    -- Step 2: Load mesgd's public encryption key
    -- ------------------------------------------------------------------
    putStrLn $ "Step 2: Loading mesgd public key from '" ++ pubJwkPath ++ "' …"
    mesgdPubJwk <- loadMesgdPubJwk pubJwkPath
    putStrLn "        Loaded.\n"

    -- ------------------------------------------------------------------
    -- Step 3: Register with mesgd
    -- ------------------------------------------------------------------
    putStrLn "Step 3: Registering with mesgd …"
    registrationCt <- PKI.register keys mesgdPubJwk `catch` (\(e :: SomeException) -> do
        hPutStrLn stderr $ "ERROR: Registration failed: " ++ show e
        exitFailure)
    let preview = take 40 (BC.unpack registrationCt)
    putStrLn $ "        Registration payload (first 40 chars): " ++ preview ++ "…\n"

    -- ------------------------------------------------------------------
    -- Step 4 & 5: Connect WebSocket and run ping/pong
    --   The websockets library provides a synchronous API within a
    --   runClient / runSecureClient callback.
    -- ------------------------------------------------------------------
    putStrLn $ "Step 4: Connecting to " ++ mesgdUrl ++ " …"
    runWsClient mesgdUrl $ \conn -> do
        -- Send registration handshake
        WS.sendTextData conn (BC.unpack registrationCt :: String)
        putStrLn "        Connected.\n"
        putStrLn $ "Step 5: Starting " ++ show rounds ++ "-round ping/pong …\n"

        forM_ [1..rounds] $ \i -> do
            let message = "Hello from mesgd-sdk! Haskell ping #" ++ show i

            putStrLn $ "  [" ++ show i ++ "/" ++ show rounds ++ "] Sending  : " ++ message

            -- Sign + encrypt
            ciphertext <- Mesgd.signAndEncrypt keys mesgdPubJwk message
            WS.sendTextData conn ciphertext

            -- Receive, decrypt, verify
            rawFrame <- WS.receiveData conn :: IO String
            (response, _sig) <- Mesgd.decryptAndVerify keys mesgdPubJwk rawFrame

            putStrLn $ "  [" ++ show i ++ "/" ++ show rounds ++ "] Received : " ++ response

            if response /= message
                then do
                    hPutStrLn stderr $ "ERROR: Echo mismatch — expected: "
                        ++ show message ++ ", got: " ++ show response
                    exitFailure
                else putStrLn $ "  [" ++ show i ++ "/" ++ show rounds ++ "] ✓ Echo verified\n"

        WS.sendClose conn ("bye" :: String)
        putStrLn "Connection closed."

    putStrLn $ "\nAll " ++ show rounds ++ " ping/pong rounds passed."

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- | Load mesgd's RSA-2048 public encryption JWK from a JSON file.
loadMesgdPubJwk :: FilePath -> IO Value
loadMesgdPubJwk path = do
    contents <- BL.readFile path `catch` (\(e :: SomeException) -> do
        hPutStrLn stderr $ "ERROR: Cannot read '" ++ path ++ "': " ++ show e
        hPutStrLn stderr "  Fetch it with: curl https://mesgd.org/.well-known/mesgd-pub.json -o mesgd_pub.json"
        exitFailure)
    case eitherDecode contents of
        Right v  -> return v
        Left err -> do
            hPutStrLn stderr $ "ERROR: Parsing '" ++ path ++ "': " ++ err
            exitFailure

-- | Run a WebSocket client, selecting TLS (wss) or plaintext (ws) automatically.
runWsClient :: String -> (WS.Connection -> IO ()) -> IO ()
runWsClient url action =
    case parseURI url of
        Nothing  -> ioError $ userError $ "Invalid URL: " ++ url
        Just uri -> do
            let scheme = uriScheme uri
                auth   = fromMaybe (error "missing host") (uriAuthority uri)
                host   = uriRegName auth
                port   = case uriPort auth of
                             ':':p -> read p
                             _     -> if scheme == "wss:" then 443 else 80
                path   = case uriPath uri of { "" -> "/"; p -> p }
            case scheme of
                "wss:" -> WS.runSecureClient host (fromIntegral (port :: Int)) path action
                _      -> WS.runClient       host (fromIntegral (port :: Int)) path action
