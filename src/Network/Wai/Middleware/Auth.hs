{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
module Network.Wai.Middleware.Auth
    ( -- * Settings
      AuthSettings
    , defaultAuthSettings
    , setAuthKey
    , setAuthAppRootStatic
    , setAuthAppRootGeneric
    , setAuthManager
    , setAuthSessionAge
    , setAuthPrefix
    , setAuthCookieName
    , setAuthProviders
    , setAuthProvidersTemplate
      -- * Middleware
    , mkAuthMiddleware
      -- * Helpers
    , smartAppRoot
    , waiMiddlewareAuthVersion
    , getAuthUser
    ) where

import           Blaze.ByteString.Builder             (fromByteString)
import           Data.Binary                          (Binary)
import qualified Data.ByteString                      as S
import           Data.ByteString.Builder              (Builder)
import qualified Data.HashMap.Strict                  as HM
import           Data.Monoid                          ((<>))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (decodeUtf8With,
                                                       encodeUtf8)
import           Data.Text.Encoding.Error             (lenientDecode)
import qualified Data.Vault.Lazy                      as Vault
import           Data.Version                         (Version)
import           Foreign.C.Types                      (CTime (..))
import           GHC.Generics                         (Generic)
import           Network.HTTP.Client                  (Manager, newManager)
import           Network.HTTP.Client.TLS              (tlsManagerSettings)
import           Network.HTTP.Types                   (status200, status303,
                                                       status404, status501)
import           Network.Wai                          (Middleware, Request,
                                                       pathInfo,
                                                       rawPathInfo,
                                                       rawQueryString,
                                                       responseBuilder,
                                                       responseLBS, vault)
import           Network.Wai.Auth.AppRoot
import           Network.Wai.Auth.ClientSession
import           Network.Wai.Middleware.Auth.Provider
import qualified Paths_wai_middleware_auth            as Paths
import           System.IO.Unsafe                     (unsafePerformIO)
import           System.PosixCompat.Time              (epochTime)
import           Text.Hamlet                          (Render)




-- | Settings for creating the Auth middleware.
--
-- To create a value, use 'defaultAuthSettings' and then various setter
-- functions.
--
-- Since 0.1.0
data AuthSettings = AuthSettings
  { asGetKey            :: IO Key
  , asGetAppRoot        :: Request -> IO T.Text
  , asGetManager        :: IO Manager -- ^ new TLS Manager
  , asSessionAge        :: Int -- ^ default: 3600 seconds (2 hours)
  , asAuthPrefix        :: T.Text -- ^ default: _auth_middleware
  , asStateKey          :: S.ByteString -- ^ Cookie name, default: auth_state
  , asProviders         :: Providers
  , asProvidersTemplate :: Maybe T.Text -> Render Provider -> Providers -> Builder
  }

-- | Default middleware settings. See various setters in order to change available settings
defaultAuthSettings :: AuthSettings
defaultAuthSettings =
  AuthSettings
  { asGetKey = getDefaultKey
  , asGetAppRoot = smartAppRoot
  , asGetManager = newManager tlsManagerSettings
  , asSessionAge = 3600
  , asAuthPrefix = "_auth_middleware"
  , asStateKey = "auth_state"
  , asProviders = HM.empty
  , asProvidersTemplate = providersTemplate
  }


-- | Set the function to get client session key for encrypting cookie data.
--
-- Default: 'getDefaultKey'
--
-- Since 0.1.0
setAuthKey :: IO Key -> AuthSettings -> AuthSettings
setAuthKey x as = as { asGetKey = x }

-- | Set the cookie name.
--
-- Default: "auth_state"
--
-- Since 0.1.0
setAuthCookieName :: S.ByteString -> AuthSettings -> AuthSettings
setAuthCookieName x as = as { asStateKey = x }


-- | Set the cookie key.
--
-- Default: "auth_state"
--
-- Since 0.1.0
setAuthPrefix :: T.Text -> AuthSettings -> AuthSettings
setAuthPrefix x as = as { asAuthPrefix = x }


-- | The application root for this application.
--
-- | Set the root for this Aplication. Required for external Authentication
-- providers to perform proper redirect.
--
-- Default: use the APPROOT environment variable.
--
-- Since 0.1.0
setAuthAppRootStatic :: T.Text -> AuthSettings -> AuthSettings
setAuthAppRootStatic = setAuthAppRootGeneric . const . return

-- | More generalized version of 'setAuthApprootStatic'.
--
-- Since 0.1.0
setAuthAppRootGeneric :: (Request -> IO T.Text) -> AuthSettings -> AuthSettings
setAuthAppRootGeneric x as = as { asGetAppRoot = x }

-- | Acquire an HTTP connection manager.
--
-- Default: get a new tls-enabled manager.
--
-- Since 0.1.0
setAuthManager :: IO Manager -> AuthSettings -> AuthSettings
setAuthManager x as = as { asGetManager = x }

-- | Number of seconds to keep an authentication cookie active
--
-- Default: 3600
--
-- Since 0.1.0
setAuthSessionAge :: Int -> AuthSettings -> AuthSettings
setAuthSessionAge x as = as { asSessionAge = x }


-- | Set Authentication providers to be used.
--
-- Default is empty.
--
-- Since 0.1.0
setAuthProviders :: Providers -> AuthSettings -> AuthSettings
setAuthProviders !ps as = as { asProviders = ps }


-- | Set a custom template that will be rendered for a providers page
--
-- Default: `providersTemplate`
--
-- Since 0.1.0
setAuthProvidersTemplate :: (Maybe T.Text -> Render Provider -> Providers -> Builder)
                        -> AuthSettings
                        -> AuthSettings
setAuthProvidersTemplate t as = as { asProvidersTemplate = t }


-- | Current state of the user.
data AuthState = AuthNeedRedirect !S.ByteString
               | AuthLoggedIn !AuthUser
    deriving (Generic, Show)

instance Binary AuthState


-- | Creates an Authentication middleware that will make sure application is
-- protected, thus allowing access only to users that go through an
-- authentication process with one of the available providers. If more than one
-- provider is specified, user will be directed to a page were one can be chosen
-- from a list.
mkAuthMiddleware
  :: AuthSettings -> IO Middleware
mkAuthMiddleware AuthSettings {..} = do
  secretKey <- asGetKey
  man <- asGetManager
  let saveAuthState = saveCookieValue secretKey asStateKey asSessionAge
      authRouteRender = mkRouteRender Nothing asAuthPrefix []
  -- Redirect to a list of providers if more than one is available, otherwise
  -- start login process with the only provider.
  let enforceLogin protectedPath req respond =
        case pathInfo req of
          (prefix:rest)
            | prefix == asAuthPrefix ->
              case rest of
                [] ->
                  case HM.elems asProviders of
                    [] ->
                      respond $
                      responseLBS
                        status501
                        []
                        "No Authentication providers available."
                    [soleProvider] ->
                      let loginUrl =
                            encodeUtf8 $ authRouteRender soleProvider []
                      in respond $
                         responseLBS
                           status303
                           [("Location", loginUrl)]
                           "Redirecting to Login page"
                    _ ->
                      respond $
                      responseBuilder status200 [] $
                      asProvidersTemplate Nothing authRouteRender asProviders
                (providerName:pathSuffix)
                  | HM.member providerName asProviders -> do
                    appRoot <- asGetAppRoot req
                    let provider = asProviders HM.! providerName
                    let onSuccess userIdentity = do
                          CTime now <- epochTime
                          cookie <-
                            saveAuthState $
                            AuthLoggedIn $
                            AuthUser
                            { authUserIdentity = userIdentity
                            , authProviderName = encodeUtf8 $ getProviderName provider
                            , authLoginTime = now
                            }
                          return $
                            responseBuilder
                              status303
                              [("Location", protectedPath), cookie]
                              (fromByteString "Redirecting to " <>
                               fromByteString protectedPath)
                    let onFailure status errMsg =
                          return $
                          responseBuilder status [] $
                          asProvidersTemplate
                            (Just $ decodeUtf8With lenientDecode errMsg)
                            authRouteRender
                            asProviders
                    let providerUrlRenderer (ProviderUrl suffix) =
                          mkRouteRender
                            (Just appRoot)
                            asAuthPrefix
                            suffix
                            provider
                    respond =<<
                      handleLogin
                        provider
                        man
                        req
                        providerUrlRenderer
                        pathSuffix
                        onSuccess
                        onFailure
                _ -> respond $ responseLBS status404 [] "Unknown URL"
          _ -> do
            cookie <-
              saveAuthState $
              AuthNeedRedirect (rawPathInfo req <> rawQueryString req)
            respond $
              responseBuilder
                status303
                [("Location", "/" <> encodeUtf8 asAuthPrefix), cookie]
                "Redirecting to Login Page"
  return $ \app req respond -> do
    authState <- loadCookieValue secretKey asStateKey req
    case authState of
      Just (AuthLoggedIn user) ->
        let req' = req {vault = Vault.insert userKey user $ vault req}
        in app req' respond
      Just (AuthNeedRedirect url) -> enforceLogin url req respond
      Nothing -> enforceLogin "/" req respond


userKey :: Vault.Key AuthUser
userKey = unsafePerformIO Vault.newKey
{-# NOINLINE userKey #-}


-- | Get the username for the current user.
--
-- If called on a @Request@ behind the middleware, should always return a
-- @Just@ value.
--
-- Since 0.1.1.0
getAuthUser :: Request -> Maybe AuthUser
getAuthUser = Vault.lookup userKey . vault


-- | Current version
--
-- Since 0.1.0
waiMiddlewareAuthVersion :: Version
waiMiddlewareAuthVersion = Paths.version

