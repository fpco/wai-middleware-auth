{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Middleware.Auth.OAuth2.Google
    ( Google(..)
    , googleParser
    , mkGoogleProvider
    ) where
import           Control.Exception.Safe               (catchAny)
import           Control.Monad                        (guard)
import           Data.Aeson
import qualified Data.ByteString                      as S
import           Data.Monoid                          ((<>))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8)
import           Network.HTTP.Simple
import           Network.HTTP.Types
import           Network.Wai.Auth.Tools               (getValidEmail)
import           Network.Wai.Middleware.Auth.OAuth2
import           Network.Wai.Middleware.Auth.Provider


mkGoogleProvider
  :: T.Text -- ^ client_id
  -> T.Text -- ^ client_secret
  -> [T.Text] -- ^ Email white list
  -> Google
mkGoogleProvider clientId clientSecret emailWhiteList =
  Google
    "https://www.googleapis.com/oauth2/v3/userinfo"
    emailWhiteList
    OAuth2
    { oa2ClientId = clientId
    , oa2ClientSecret = clientSecret
    , oa2AuthorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    , oa2AccessTokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"
    , oa2Scope = Just ["https://www.googleapis.com/auth/userinfo.email"]
    , oa2ProviderInfo =
        ProviderInfo
        { providerTitle = "Google"
        , providerLogoUrl =
            "https://upload.wikimedia.org/wikipedia/commons/thumb/5/53/Google_%22G%22_Logo.svg/200px-Google_%22G%22_Logo.svg.png"
        , providerDescr =
            "Use your Google account to access this page."
        }
    }

googleParser :: ProviderParser
googleParser = mkProviderParser (undefined :: Google)


data Google = Google
  { googleAPIEmailEndpoint :: T.Text
  , googleEmailWhitelist   :: [T.Text]
  , googleOAuth2           :: OAuth2
  }

instance FromJSON Google where

  parseJSON = withObject "Google Provider Object" $ \ obj -> do
    clientId <- obj .: "client_id"
    clientSecret <- obj .: "client_secret"
    emailWhiteList <- obj .:? "email_white_list" .!= []
    return $ mkGoogleProvider clientId clientSecret emailWhiteList


newtype GoogleEmail = GoogleEmail { googleEmail :: T.Text } deriving Show

instance FromJSON GoogleEmail where
  parseJSON = withObject "Google Verified Email" $ \ obj -> do
    verified <- obj .: "email_verified"
    guard verified
    email <- obj .: "email"
    return (GoogleEmail email)



retrieveEmail :: T.Text -> S.ByteString -> IO GoogleEmail
retrieveEmail emailApiEndpoint accessToken = do
  req <- parseRequest (T.unpack emailApiEndpoint)
  resp <- httpJSON $ setRequestHeaders headers req
  return $ getResponseBody resp
  where
    headers = [("Authorization", "Bearer " <> accessToken)]


instance AuthProvider Google where
  getProviderName _ = "google"
  getProviderInfo = getProviderInfo . googleOAuth2
  handleLogin Google {..} man req renderUrl suffix onSuccess onFailure = do
    let onOAuth2Success accessToken = do
          catchAny
            (do email <-
                  googleEmail <$>
                  retrieveEmail googleAPIEmailEndpoint accessToken
                let mEmail = getValidEmail googleEmailWhitelist [email]
                case mEmail of
                  Just email' -> onSuccess (encodeUtf8 email')
                  Nothing ->
                    onFailure
                      status403
                      "No valid email with permission to access was found.") $ \_err ->
            onFailure status501 "Issue communicating with google."
    handleLogin googleOAuth2 man req renderUrl suffix onOAuth2Success onFailure
