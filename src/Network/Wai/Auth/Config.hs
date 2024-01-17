{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
module Network.Wai.Auth.Config
  ( AuthConfig(..)
  , SecretKey(..)
  , Service(..)
  , FileServer(..)
  , ReverseProxy(..)
  , encodeKey
  , decodeKey
  ) where

import           Data.Aeson hiding      (Key)
import           Data.Aeson.TH          (deriveJSON)
import qualified Data.Text              as T
import           Data.Text.Encoding     (encodeUtf8)
import           Network.Wai.Auth.Tools (decodeKey, encodeKey,
                                         toLowerUnderscore)
import           Web.ClientSession      (Key)

-- | Configuration for a secret key that will be used to encrypt authenticated
-- user as client side cookie.
data SecretKey
  = SecretKeyFile FilePath -- ^ Path to a secret key file in binary form, if it
                           -- is malformed or doesn't exist it will be
                           -- (re)created. If empty "client_session_key.aes"
                           -- name will be used
  | SecretKey Key -- ^ Serialized and base64 encoded form of a secret key. Use
                  -- `encodeKey` to get a proper encoded form.


-- | Configuration for reverse proxy application.
data FileServer = FileServer
    { fsRootFolder       :: FilePath -- ^ Path to a folder containing files
                                     -- that will be served by this app.
    , fsRedirectToIndex  :: Bool -- ^ Redirect to the actual index file, not
                                 -- leaving the URL containing the directory
                                 -- name
    , fsAddTrailingSlash :: Bool -- ^ Add a trailing slash to directory names
    }

-- | Configuration for reverse proxy application.
data ReverseProxy = ReverseProxy
    { rpHost   :: T.Text -- ^ Hostname of the destination webserver
    , rpPort   :: Int -- ^ Port of the destination webserver
    , rpSecure :: Maybe Bool -- ^ Should the request be sent to destination webbserver using https or not (default: false)
    }

-- | Available services.
data Service = ServiceFiles FileServer
             | ServiceProxy ReverseProxy

-- | Configuration for @wai-auth@ executable and any other, that is created using
-- `Network.Wai.Auth.Executable.mkMain`
data AuthConfig = AuthConfig
  { configAppRoot    :: Maybe T.Text -- ^ Root Url of the website, eg:
                                     -- http://example.com or
                                     -- https://example.com It will be used to
                                     -- perform redirects back from external
                                     -- authentication providers.
  , configAppPort    :: Int  -- ^ Port number. Default is 3000
  , configRequireTls :: Bool -- ^ Require requests come in over a secure
                             -- connection (determined via headers). Will
                             -- redirect to HTTPS if non-secure
                             -- dedected. Default is @False@
  , configSkipAuth   :: Bool -- ^ Turn off authentication middleware, useful for
                             -- testing. Default is @False@
  , configCookieAge  :: Int -- ^ Duration of the session in seconds. Default is
                            -- one hour (3600 seconds).
  , configSecretKey  :: SecretKey -- ^ Secret key. Default is "client_session_key.aes"
  , configService    :: Service
  , configProviders  :: Object
  }

$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 2} ''FileServer)

$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 2} ''ReverseProxy)

instance FromJSON AuthConfig where
  parseJSON =
    withObject "Auth Config Object" $ \obj -> do
      configAppRoot <- obj .:? "app_root"
      configAppPort <- obj .:? "app_port" .!= 3000
      configRequireTls <- (obj .:? "require_tls" .!= False)
      configSkipAuth <- obj .:? "skip_auth" .!= False
      configCookieAge <- obj .:? "cookie_age" .!= 3600
      mSecretKeyB64T <- obj .:? "secret_key"
      configSecretKey <-
        case mSecretKeyB64T of
          Just secretKeyB64T ->
            either fail (return . SecretKey) $ decodeKey (encodeUtf8 secretKeyB64T)
          Nothing -> SecretKeyFile <$> (obj .:? "secret_key_file" .!= "")
      mFileServer <- obj .:? "file_server"
      mReverseProxy <- obj .:? "reverse_proxy"
      let sErrMsg =
            "Either 'file_server' or 'reverse_proxy' is required, but not both."
      configService <-
        case (mFileServer, mReverseProxy) of
          (Just fileServer, Nothing) -> ServiceFiles <$> parseJSON fileServer
          (Nothing, Just reverseProxy) ->
            ServiceProxy <$> parseJSON reverseProxy
          (Just _, Just _) -> fail $ "Too many services. " ++ sErrMsg
          (Nothing, Nothing) -> fail $ "No service is supplied. " ++ sErrMsg
      configProviders <- obj .: "providers"
      return AuthConfig {..}
