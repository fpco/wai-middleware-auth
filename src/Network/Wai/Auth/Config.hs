{-# LANGUAGE OverloadedStrings #-}
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

import           Data.Aeson
import           Data.Aeson.TH                        (defaultOptions,
                                                       deriveJSON,
                                                       fieldLabelModifier)
import qualified Data.Text                            as T
import           Data.Text.Encoding
import           Network.Wai.Auth.Tools

import           Web.ClientSession                    (Key)


data SecretKey
  = SecretKeyFile FilePath -- ^ Path to a secret key file, if it is malformed or
                           -- doesn't exist it will be (re)created.
  | SecretKey Key -- ^ Serialized and base64 encoded form of a secret key. Use
                  -- `encodeKey` to get a proper encoded form.


data FileServer = FileServer
    { fsRootFolder       :: FilePath -- ^ Path to a folder containing files
                                     -- that will be served by this app.
    , fsRedirectToIndex  :: Bool -- ^ Redirect to the actual index file, not
                                 -- leaving the URL containing the directory
                                 -- name
    , fsAddTrailingSlash :: Bool -- ^ Add a trailing slash to directory names
    }

data ReverseProxy = ReverseProxy
    { rpHost :: T.Text -- ^ Hostname of the webserver
    , rpPort :: Int -- ^ Port of the webserver
    }

data Service = ServiceFiles FileServer
             | ServiceProxy ReverseProxy


data AuthConfig = AuthConfig
  { configAppRoot    :: T.Text -- ^ Root path that will be secured, eg: example.com
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


instance FromJSON AuthConfig where
  parseJSON =
    withObject "Auth Config Object" $ \obj -> do
      appRoot <- obj .: "app_root"
      appPort <- obj .:? "app_port" .!= 3000
      requireTLS <- (obj .:? "require_tls" .!= False)
      skipAuth <- obj .:? "skip_auth" .!= False
      cookieAge <- obj .:? "cookie_age" .!= 3600
      mSecretKeyB64T <- obj .:? "secret_key"
      secretKey <-
        case mSecretKeyB64T of
          Just secretKeyB64T ->
            SecretKey <$> decodeKey (encodeUtf8 secretKeyB64T)
          Nothing -> SecretKeyFile <$> (obj .:? "secret_key_file" .!= "")
      mFileServer <- obj .:? "file_server"
      mReverseProxy <- obj .:? "reverse_proxy"
      let sErrMsg =
            "Either 'file_server' or 'reverse_proxy' is required, but not both."
      service <-
        case (mFileServer, mReverseProxy) of
          (Just fileServer, Nothing) -> ServiceFiles <$> parseJSON fileServer
          (Nothing, Just reverseProxy) ->
            ServiceProxy <$> parseJSON reverseProxy
          (Just _, Just _) -> fail $ "Too many services. " ++ sErrMsg
          (Nothing, Nothing) -> fail $ "No service is supplied. " ++ sErrMsg
      providers <- obj .: "providers"
      return $
        AuthConfig
          appRoot
          appPort
          requireTLS
          skipAuth
          cookieAge
          secretKey
          service
          providers


$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 2} ''FileServer)

$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 2} ''ReverseProxy)


