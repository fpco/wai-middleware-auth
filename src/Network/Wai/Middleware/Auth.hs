{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
module Network.Wai.Middleware.Auth
    ( -- * Settings
      AuthSettings
    , AuthProvider(..)
    , Provider (..)
    , defaultAuthSettings
    , setAuthKey
    , setAuthAppRootStatic
    , setAuthAppRootGeneric
    , setAuthManager
    , setAuthSessionAge
    , setAuthPrefix
    , setAuthCookieName
      -- * Middleware
    , mkAuthMiddleware
      -- * Helpers
    , smartAppRoot
    , waiMiddlewareAuthVersion
    , getUserName
    ) where

import           Blaze.ByteString.Builder  (fromByteString, toByteString)
import           Data.Binary               (Binary)
import qualified Data.ByteString           as S
import qualified Data.ByteString.Lazy      as LS
import qualified Data.HashMap.Strict       as HM
import           Data.Monoid               ((<>))
import qualified Data.Text                 as T
import           Data.Text.Encoding        (decodeUtf8With, encodeUtf8)
import           Data.Text.Encoding.Error  (lenientDecode)
import qualified Data.Vault.Lazy           as Vault
import           Data.Version              (Version)
import           GHC.Generics              (Generic)
import           Network.HTTP.Client       (Manager, newManager)
import           Network.HTTP.Client.TLS   (tlsManagerSettings)
import           Network.HTTP.Types        (Header, status200, status303,
                                            status404, status501)
import           Network.Wai               (Middleware, Request, Response,
                                            pathInfo, rawPathInfo,
                                            rawQueryString, responseBuilder,
                                            responseLBS, vault)
import           Network.Wai.AppRoot
import           Network.Wai.ClientSession
import qualified Paths_wai_middleware_auth as Paths
import           System.IO.Unsafe          (unsafePerformIO)


type Url = S.ByteString

class AuthProvider ap where

  getName :: ap -> T.Text

  handleLogin
    :: ap
    -> Manager
    -> Request -- ^ Request made to the login page
    -> (Request -> IO T.Text) -- ^ Action that will return Application root path.
    -> ([T.Text], [T.Text])
    -- ^ Path split by @'\/'@ character and separated into prefix and suffix,
    -- for eg: https:\/\/example.com\/auth\/providerName\/login\/complete
    --
    -- * Application root: @"https:\/\/example.com\/"@
    -- * Prefix: @["auth", "providerName", "login"]@
    -- * Suffix: @["complete"]@
    --
    -> (Identity -> IO Response) -- ^ Action to call on successfull login
    -> IO Response -- ^ Url were user can supply credentials and login.




-- | Settings for creating the Auth middleware.
--
-- To create a value, use 'defaultAuthSettings' and then various setter
-- functions.
--
-- Since 0.1.0
data AuthSettings = AuthSettings
  { asGetKey     :: IO Key
  , asGetAppRoot :: IO (Request -> IO T.Text)
  , asGetManager :: IO Manager -- ^ new TLS Manager
  , asSessionAge :: Int -- ^ default: 3600 seconds (2 hours)
  , asAuthPrefix :: T.Text -- ^ default: _auth_middleware
  , asStateKey   :: S.ByteString -- ^ Cookie name, default: auth_state
  }

defaultAuthSettings :: AuthSettings
defaultAuthSettings =
  AuthSettings
  { asGetKey = getDefaultKey
  , asGetAppRoot = smartAppRoot
  , asGetManager = newManager tlsManagerSettings
  , asSessionAge = 3600
  , asAuthPrefix = "_auth_middleware"
  , asStateKey = "auth_state"
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
setAuthAppRootStatic x = setAuthAppRootGeneric $ return $ const $ return x

-- | More generalized version of 'setAuthApprootStatic'.
--
-- Since 0.1.0
setAuthAppRootGeneric :: IO (Request -> IO T.Text) -> AuthSettings -> AuthSettings
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


-- data Identity = Identity
--   { authUser         :: S.ByteString
--   , authProviderName :: S.ByteString
--   , authLoginTime    :: Int64
--   } deriving (Binary)

type Identity = S.ByteString

data AuthState = AuthNeedRedirect Url
               | AuthLoggedIn Identity
    deriving (Generic, Show)
instance Binary AuthState


data Provider where
  Provider :: AuthProvider p => p -> Provider

instance AuthProvider Provider where
  getName (Provider p) = getName p
  handleLogin (Provider p) = handleLogin p


mkAuthMiddleware
  :: AuthSettings -> HM.HashMap T.Text Provider -> IO Middleware
mkAuthMiddleware AuthSettings {..} providers = do
  secretKey <- asGetKey
  getAppRoot <- asGetAppRoot
  man <- asGetManager
  let saveAuthState = saveCookieValue secretKey asStateKey asSessionAge
  -- Redirect to a list of providers if more than one is availiable, otherwise
  -- start login process with the only provider.
  let enforceLogin protectedPath req respond =
        case pathInfo req of
          (prefix:rest)
            | prefix == asAuthPrefix ->
              case rest of
                [] ->
                  case HM.keys providers of
                    [] ->
                      respond $
                      responseLBS
                        status501
                        []
                        "No Authentication providers available."
                    [soleProvider] ->
                      let loginUrl =
                            T.intercalate
                              "/"
                              ["", prefix, soleProvider, "login"]
                      in respond $
                         responseLBS
                           status303
                           [("Location", encodeUtf8 loginUrl)]
                           "Redirecting to Login page"
                    _ ->
                      respond $
                      responseLBS status501 [] "Show list of providers"
                (providerName:login@"login":pathSuffix)
                  | HM.member providerName providers ->
                    let onSuccess userIdentity = do
                          cookie <- saveAuthState $ AuthLoggedIn userIdentity
                          return $
                            responseBuilder
                              status303
                              [("Location", protectedPath), cookie]
                              (fromByteString "Redirecting to " <>
                               fromByteString protectedPath)
                    in respond =<<
                       handleLogin
                         (providers HM.! providerName)
                         man
                         req
                         getAppRoot
                         ([prefix, providerName, login], pathSuffix)
                         onSuccess
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


userKey :: Vault.Key S.ByteString
userKey = unsafePerformIO Vault.newKey
{-# NOINLINE userKey #-}


-- | Get the username for the current user.
--
-- If called on a @Request@ behind the middleware, should always return a
-- @Just@ value.
--
-- Since 0.1.1.0
getUserName :: Request -> Maybe S.ByteString
getUserName = Vault.lookup userKey . vault


-- | Current version
--
-- Since 0.1.0
waiMiddlewareAuthVersion :: Version
waiMiddlewareAuthVersion = Paths.version
