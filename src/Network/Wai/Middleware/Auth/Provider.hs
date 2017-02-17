{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE QuasiQuotes         #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
module Network.Wai.Middleware.Auth.Provider
  ( AuthProvider(..)
  , Provider(..)
  , ProviderUrl(..)
  , ProviderInfo(..)
  , AuthUser(..)
  , UserIdentity
  , ProviderParser
  , Providers
  , mkRouteRender
  , mkProviderParser
  , providersTemplate
  ) where

import           Blaze.ByteString.Builder      (toByteString)
import           Control.Arrow                 (second)

import           Data.Aeson
import           Data.Aeson.TH                 (defaultOptions, deriveJSON,
                                                fieldLabelModifier)
import           Data.Aeson.Types              (Parser)
import           Data.Binary                   (Binary)
import qualified Data.ByteString               as S
import qualified Data.ByteString.Builder       as B
import qualified Data.HashMap.Strict           as HM
import           Data.Int
import           Data.Maybe                    (fromMaybe)
import           Data.Monoid                   ((<>))
import qualified Data.Text                     as T
import           Data.Text.Encoding            (decodeUtf8With)
import           Data.Text.Encoding.Error      (lenientDecode)
import           Data.Text.Lazy.Encoding       (encodeUtf8Builder)
import           GHC.Generics                  (Generic)
import           Network.HTTP.Client           (Manager)
import           Network.HTTP.Types            (Status, renderQueryText)
import           Network.Wai                   (Request, Response)
import           Network.Wai.Auth.Tools        (toLowerUnderscore)
import           Text.Blaze.Html.Renderer.Text (renderHtml)
import           Text.Hamlet                   (Render, hamlet)

type UserIdentity = S.ByteString

data AuthUser = AuthUser
  { authUserIdentity :: !UserIdentity
  , authProviderName :: !S.ByteString
  , authLoginTime    :: !Int64
  } deriving (Generic, Show)

instance Binary AuthUser

-- | Core Authentication class, that allows for extensibility of the Auth middleware.
class AuthProvider ap where

  -- | Return a name for the provider. It will be used as a unique identifier
  -- for this provider. Argument should not be evaluated, as there are many
  -- places were `undefined` value is passed to this function.
  getProviderName :: ap -> T.Text

  -- | Get info about the provider. It will be used in rendering the web page
  -- with a list of providers.
  getProviderInfo :: ap -> ProviderInfo

  -- | Handle a login request.
  handleLogin
    :: ap
    -> Manager -- ^ Default manager.
    -> Request -- ^ Request made to the login page
    -> Render ProviderUrl
    -- ^ Url renderer. It takes desired suffix as first argument and produces a
    -- absolute Url renderer. It can further be used to generate provider urls,
    -- for instance in Hamlet templates as
    -- @\@?{(ProviderUrl ["login", "complete"], [("user", "Hamlet")])}@
    -- will result in
    -- "https:\/\/appRoot.com\/_auth_middleware\/providerName\/login\/complete?user=Hamlet"
    -- or generate Urls for callbacks.
    -> [T.Text]
    -- ^ Url suffix, i.e. last part of the Url split by @'\/'@ character, eg:
    -- https:\/\/example.com\/_auth_middleware\/providerName\/login\/complete
    -- Suffix is: @["login", "complete"]@
    --
    -> (UserIdentity -> IO Response) -- ^ Action to call on successfull login
    -> (Status -> S.ByteString -> IO Response)
    -- ^ Should be called in case of a failure with login process by supplying a
    -- status and a short error message.
    -> IO Response -- ^ Response to login request.


type Providers = HM.HashMap T.Text Provider

type ProviderParser = (T.Text, Value -> Parser Provider)

-- | First argument is not evaluated and is only needed for restricting the type.
mkProviderParser :: forall ap . (FromJSON ap, AuthProvider ap) => ap -> ProviderParser
mkProviderParser ap = (getProviderName ap,
                       fmap Provider <$> (parseJSON :: Value -> Parser ap))

data ProviderUrl = ProviderUrl [T.Text]


data ProviderInfo = ProviderInfo
  { providerTitle   :: T.Text
  , providerLogoUrl :: T.Text
  , providerDescr   :: T.Text
  } deriving (Show)


data Provider where
  Provider :: AuthProvider p => p -> Provider


instance AuthProvider Provider where

  getProviderName (Provider p) = getProviderName p

  getProviderInfo (Provider p) = getProviderInfo p

  handleLogin (Provider p) = handleLogin p


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
  encodeUtf8Builder $ renderHtml $ [hamlet|
$doctype 5
<html>
  <head>
    <title>WAI Auth Middleware - Authentication Providers.
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">
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
