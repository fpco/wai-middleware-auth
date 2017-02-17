{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Auth.Executable
  ( mkMain
  , readAuthConfig
  , parseProviders
  , Port
  ) where


import           Data.Aeson.Types                     (parseEither)
import qualified Data.HashMap.Strict                  as HM

import           Data.String                          (fromString)
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8)
import           Data.Yaml.Config                     (loadYamlSettings, useEnv)
import           Network.HTTP.Client                  (Manager, newManager)
import           Network.HTTP.Client.TLS              (tlsManagerSettings)
import           Network.HTTP.ReverseProxy            (ProxyDest (..), WaiProxyResponse (WPRProxyDest),
                                                       defaultOnExc, waiProxyTo)
import           Network.Wai                          (Application)
import           Network.Wai.Application.Static       (defaultFileServerSettings,
                                                       ssAddTrailingSlash,
                                                       ssRedirectToIndex,
                                                       staticApp)
import           Network.Wai.Auth.Config
import           Network.Wai.Middleware.Auth

import           Network.Wai.Middleware.Auth.Provider
import           Network.Wai.Middleware.Redirect2tls

import           Web.ClientSession                    (getKey)

type Port = Int


serviceToApp :: Manager -> Service -> IO Application
serviceToApp _ (ServiceFiles FileServer {..}) =
    return $ staticApp (defaultFileServerSettings $ fromString fsRootFolder)
        { ssRedirectToIndex = fsRedirectToIndex
        , ssAddTrailingSlash = fsAddTrailingSlash
        }
serviceToApp manager (ServiceProxy (ReverseProxy host port)) =
    return $ waiProxyTo
        (const $ return $ WPRProxyDest $ ProxyDest (encodeUtf8 host) port)
        defaultOnExc
        manager


readAuthConfig :: FilePath -> IO AuthConfig
readAuthConfig confFile = loadYamlSettings [confFile] [] useEnv


parseProviders :: AuthConfig -> [ProviderParser] -> Providers
parseProviders conf providerParsers =
  if HM.null unrecognized
    then HM.intersectionWith parseProvider unparsedProvidersHM parsersHM
    else error $
         "Provider name(s) are not recognized or not supported: " ++
         T.unpack (T.intercalate ", " $ HM.keys unrecognized)
  where
    parsersHM = HM.fromList providerParsers
    unparsedProvidersHM = configProviders conf
    unrecognized = HM.difference unparsedProvidersHM parsersHM
    parseProvider v p = either error id $ parseEither p v



mkMain
  :: AuthConfig
  -> [ProviderParser]
  -> (Port -> Application -> IO ())
  -> IO ()
mkMain conf@AuthConfig {..} providerParsers run = do
  manager <- newManager tlsManagerSettings
  let !providers = parseProviders conf providerParsers
  let authSettings =
        (case configSecretKey of
           SecretKey key         -> setAuthKey $ return key
           SecretKeyFile ""      -> id
           SecretKeyFile keyPath -> setAuthKey (getKey keyPath))
        . setAuthProviders providers
        . setAuthSessionAge configCookieAge
        . setAuthManager (return manager)
        $ defaultAuthSettings
  authMiddleware <- mkAuthMiddleware authSettings
  app <- serviceToApp manager configService
  run configAppPort $
    (if configRequireTls
       then redirect2tls
       else id)
      (if configSkipAuth
         then app
         else authMiddleware app)
