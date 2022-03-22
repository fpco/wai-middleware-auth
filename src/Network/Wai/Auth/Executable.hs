{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Auth.Executable
  ( mkMain
  , readAuthConfig
  , serviceToApp
  , module Network.Wai.Auth.Config
  , Port
  ) where
import           Data.Aeson                           (Result (..))
import           Data.String                          (fromString)
import           Data.Text.Encoding                   (encodeUtf8)
import           Data.Yaml.Config                     (loadYamlSettings, useEnv)
import           Network.HTTP.Client.TLS              (getGlobalManager)
import           Network.HTTP.ReverseProxy            (ProxyDest (..),
                                                       WaiProxyResponse (WPRProxyDest, WPRProxyDestSecure),
                                                       defaultOnExc, waiProxyTo)
import           Network.Wai                          (Application)
import           Network.Wai.Application.Static       (defaultFileServerSettings,
                                                       ssAddTrailingSlash,
                                                       ssRedirectToIndex,
                                                       staticApp)
import           Network.Wai.Auth.Config
import           Network.Wai.Middleware.Auth
import           Network.Wai.Middleware.Auth.Provider
import           Network.Wai.Middleware.ForceSSL      (forceSSL)
import           Web.ClientSession                    (getKey)


type Port = Int

-- | Create an `Application` from a `Service`
--
-- @since 0.1.0
serviceToApp :: Service -> IO Application
serviceToApp (ServiceFiles FileServer {..}) = do
  return $
    staticApp
      (defaultFileServerSettings $ fromString fsRootFolder)
      { ssRedirectToIndex = fsRedirectToIndex
      , ssAddTrailingSlash = fsAddTrailingSlash
      }
serviceToApp (ServiceProxy (ReverseProxy host port secure)) = do
  manager <- getGlobalManager
  return $
    waiProxyTo
      (const $ return $ proxydest $ ProxyDest (encodeUtf8 host) port)
      defaultOnExc
      manager
  where
    proxydest =
      case secure of
        Just True -> WPRProxyDestSecure
        _         -> WPRProxyDest


-- | Read configuration from a yaml file with ability to use environment
-- variables. See "Data.Yaml.Config" module for details.
--
-- @since 0.1.0
readAuthConfig :: FilePath -> IO AuthConfig
readAuthConfig confFile = loadYamlSettings [confFile] [] useEnv


-- | Construct a @main@ function.
--
-- @since 0.1.0
mkMain
  :: AuthConfig -- ^ Use `readAuthConfig` to read config from a file.
  -> [ProviderParser]
  -- ^ Parsers for supported providers. `ProviderParser` can be created with
  -- `Network.Wai.Middleware.Auth.Provider.mkProviderParser`.
  -> (Port -> Application -> IO ())
  -- ^ Application runner, for instance Warp's @run@ function.
  -> IO ()
mkMain AuthConfig {..} providerParsers run = do
  let !providers =
        case parseProviders configProviders providerParsers of
          Error errMsg       -> error errMsg
          Success providers' -> providers'
  let authSettings =
        (case configSecretKey of
           SecretKey key         -> setAuthKey $ return key
           SecretKeyFile ""      -> id
           SecretKeyFile keyPath -> setAuthKey (getKey keyPath))
        . (case configAppRoot of
             Just appRoot -> setAuthAppRootStatic appRoot
             Nothing      -> id)
        . setAuthProviders providers
        . setAuthSessionAge configCookieAge
        $ defaultAuthSettings
  authMiddleware <- mkAuthMiddleware authSettings
  app <- serviceToApp configService
  run configAppPort $
    (if configRequireTls
       then forceSSL
       else id)
      (if configSkipAuth
         then app
         else authMiddleware app)
