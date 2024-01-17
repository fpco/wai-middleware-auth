{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
module Network.Wai.Middleware.Auth.Provider
  ( AuthProvider(..)
  -- * Provider
  , Provider(..)
  , ProviderUrl(..)
  , ProviderInfo(..)
  , Providers
  -- * Provider Parsing
  , ProviderParser
  , mkProviderParser
  , parseProviders
  -- * User
  , AuthUser(..)
  , AuthLoginState
  , UserIdentity
  , authUserIdentity
  -- * Template
  , mkRouteRender
  , providersTemplate
  ) where

import           Blaze.ByteString.Builder      (toByteString)
import           Control.Arrow                 (second)
import           Data.Aeson                    (FromJSON (..), Object,
                                                Result (..), Value)
import           Data.Aeson.TH                 (defaultOptions, deriveJSON,
                                                fieldLabelModifier)
import           Data.Aeson.Types              (Parser, parseEither)
import           Data.Aeson.KeyMap             (toHashMapText)
import           Data.Binary                   (Binary)
import qualified Data.ByteString               as S
import qualified Data.ByteString.Builder       as B
import qualified Data.HashMap.Strict           as HM
import           Data.Int
import           Data.Maybe                    (fromMaybe)
import           Data.Proxy                    (Proxy)
import qualified Data.Text                     as T
import           Data.Text.Encoding            (decodeUtf8With)
import           Data.Text.Encoding.Error      (lenientDecode)
import           GHC.Generics                  (Generic)
import           Network.HTTP.Types            (Status, renderQueryText)
import           Network.Wai                   (Request, Response)
import           Network.Wai.Auth.Tools        (toLowerUnderscore)
import           Text.Blaze.Html.Renderer.Utf8 (renderHtmlBuilder)
import           Text.Hamlet                   (Render, hamlet)

-- | Core Authentication class, that allows for extensibility of the Auth
-- middleware created by `Network.Wai.Middleware.Auth.mkAuthMiddleware`. Most
-- important function is `handleLogin`, which implements the actual behavior of a
-- provider. It's function arguments in order:
--
--     * @`ap`@ - Current provider.
--     * @`Request`@ - Request made to the login page
--     * @[`T.Text`]@ - Url suffix, i.e. last part of the Url split by @\'/\'@ character,
--     for instance @["login", "complete"]@ suffix in the example below.
--     * @`Render` `ProviderUrl`@ -
--     Url renderer. It takes desired suffix as first argument and produces an
--     absolute Url renderer. It can further be used to generate provider urls,
--     for instance in Hamlet templates as
--     will result in
--     @"https:\/\/approot.com\/_auth_middleware\/providerName\/login\/complete?user=Hamlet"@
--     or generate Urls for callbacks.
--
--         @
--         \@?{(ProviderUrl ["login", "complete"], [("user", "Hamlet")])}
--         @
--
--     * @(`AuthLoginState` -> `IO` `Response`)@ - Action to call on a successfull login.
--     * @(`Status` -> `S.ByteString` -> `IO` `Response`)@ - Should be called in case of
--     a failure with login process by supplying a
--     status and a short error message.
class AuthProvider ap where

  -- | Return a name for the provider. It will be used as a unique identifier
  -- for this provider. Argument should not be evaluated, as there are many
  -- places were `undefined` value is passed to this function.
  --
  -- @since 0.1.0
  getProviderName :: ap -> T.Text

  -- | Get info about the provider. It will be used in rendering the web page
  -- with a list of providers.
  --
  -- @since 0.1.0
  getProviderInfo :: ap -> ProviderInfo

  -- | Handle a login request in a custom manner. Can be used to render a login
  -- page with a form or redirect to some other authentication service like
  -- OpenID or OAuth2.
  --
  -- @since 0.1.0
  handleLogin
    :: ap
    -> Request
    -> [T.Text]
    -> Render ProviderUrl
    -> (AuthLoginState -> IO Response)
    -> (Status -> S.ByteString -> IO Response)
    -> IO Response

  -- | Check if the login state in a session is still valid, and have the
  -- opportunity to update it. Return `Nothing` to indicate a session has
  -- expired, and the user will be directed to re-authenticate. 
  --
  -- The default implementation never invalidates a session once set.
  --
  -- @since 0.2.3.0
  refreshLoginState 
    :: ap
    -> Request
    -> AuthUser
    -> IO (Maybe (Request, AuthUser))
  refreshLoginState _ req loginState = pure (Just (req, loginState))

-- | Generic authentication provider wrapper.
data Provider where
  Provider :: AuthProvider p => p -> Provider


instance AuthProvider Provider where

  getProviderName (Provider p) = getProviderName p

  getProviderInfo (Provider p) = getProviderInfo p

  handleLogin (Provider p) = handleLogin p

  refreshLoginState (Provider p) = refreshLoginState p 

-- | Collection of supported providers.
type Providers = HM.HashMap T.Text Provider

-- | Aeson parser for a provider with unique provider name (same as returned by
-- `getProviderName`)
type ProviderParser = (T.Text, Value -> Parser Provider)

-- | Data type for rendering Provider specific urls.
newtype ProviderUrl = ProviderUrl [T.Text]

-- | Provider information used for rendering a page with list of supported providers.
data ProviderInfo = ProviderInfo
  { providerTitle   :: T.Text
  , providerLogoUrl :: T.Text
  , providerDescr   :: T.Text
  } deriving (Show)


-- | An arbitrary state that comes with logged in user, eg. a username, token or an email address.
type AuthLoginState = S.ByteString

type UserIdentity = S.ByteString
{-# DEPRECATED UserIdentity "In favor of `AuthLoginState`" #-}

authUserIdentity :: AuthUser -> UserIdentity
authUserIdentity = authLoginState
{-# DEPRECATED authUserIdentity "In favor of `authLoginState`" #-}

-- | Representation of a user for a particular `Provider`.
data AuthUser = AuthUser
  { authLoginState   :: !UserIdentity
  , authProviderName :: !S.ByteString
  , authLoginTime    :: !Int64
  } deriving (Eq, Generic, Show)

instance Binary AuthUser



-- | First argument is not evaluated and is only needed for restricting the type.
mkProviderParser :: forall ap . (FromJSON ap, AuthProvider ap) => Proxy ap -> ProviderParser
mkProviderParser _ =
  ( getProviderName nameProxyError
  , fmap Provider <$> (parseJSON :: Value -> Parser ap))
  where
    nameProxyError :: ap
    nameProxyError = error "AuthProvider.getProviderName should not evaluate it's argument."

-- | Parse configuration for providers from an `Object`.
parseProviders :: Object -> [ProviderParser] -> Result Providers
parseProviders unparsedProvidersO providerParsers =
  if HM.null unrecognized
    then sequence $ HM.intersectionWith parseProvider unparsedProvidersHM parsersHM
    else Error $
         "Provider name(s) are not recognized: " ++
         T.unpack (T.intercalate ", " $ HM.keys unrecognized)
  where
    unparsedProvidersHM = toHashMapText unparsedProvidersO
    parsersHM = HM.fromList providerParsers
    unrecognized = HM.difference unparsedProvidersHM parsersHM
    parseProvider v p = either Error Success $ parseEither p v

-- | Create a url renderer for a provider.
mkRouteRender :: Maybe T.Text -> T.Text -> [T.Text] -> Render Provider
mkRouteRender appRoot authPrefix authSuffix (Provider p) params =
  (T.intercalate "/" $ [root, authPrefix, getProviderName p] ++ authSuffix) <>
  decodeUtf8With
    lenientDecode
    (toByteString $ renderQueryText True (map (second Just) params))
  where
    root = fromMaybe "" appRoot


$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 8} ''ProviderInfo)


-- | Template for the providers page
providersTemplate :: Maybe T.Text -- ^ Error message to display, if any.
                  -> Render Provider -- ^ Renderer function for provider urls.
                  -> Providers -- ^ List of available providers.
                  -> B.Builder
providersTemplate merrMsg render providers =
  renderHtmlBuilder $ [hamlet|
$doctype 5
<html>
  <head>
    <title>WAI Auth Middleware - Authentication Providers.
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js">
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous">
    <style>
      .provider-logo {
        max-height: 64px;
        max-width: 64px;
        padding: 5px;
        margin: auto;
        position: absolute;
        top: 0;
        bottom: 0;
        left: 0;
        right: 0;
      }
      .media-container {
        width: 600px;
        position: absolute;
        top: 100px;
        bottom: 0;
        left: 0;
        right: 0;
        margin: auto;
      }
      .provider.media {
        border: 1px solid #e1e1e8;
        padding: 5px;
        height: 82px;
        text-overflow: ellipsis;
        margin-top: 5px;
      }
      .provider.media:hover {
        background-color: #f5f5f5;
        border: 1px solid #337ab7;
      }
      .provider .media-left {
        height: 70px;
        width: 0px;
        padding-right: 70px;
        position: relative;
      }
      a:hover {
        text-decoration: none;
      }
  <body>
    <div .media-container>
      <h3>Select one of available authentication methods:
      $maybe errMsg <- merrMsg
        <div .alert .alert-danger role="alert">
          #{errMsg}
      $forall provider <- providers
        $with info <- getProviderInfo provider
          <div .media.provider>
            <a href=@{provider}>
              <div .media-left .container>
                <img .provider-logo src=#{providerLogoUrl info}>
              <div .media-body>
                <h3 .media-heading>
                  #{providerTitle info}
                #{providerDescr info}
|] render
