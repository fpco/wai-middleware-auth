{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Middleware.Auth.OAuth2.Google
    ( Google(..)
    , mkGoogleProvider
    , googleParser
    ) where
import           Control.Exception.Safe               (catchAny)
import           Control.Monad                        (guard)
import           Data.Aeson
import qualified Data.ByteString                      as S
import           Data.Maybe                           (fromMaybe)
import           Data.Monoid                          ((<>))
import           Data.Proxy                           (Proxy (..))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8)
import           Network.HTTP.Simple                  (getResponseBody,
                                                       httpJSON, parseRequest,
                                                       setRequestHeaders)
import           Network.HTTP.Types
import           Network.Wai.Auth.Tools               (getValidEmail)
import           Network.Wai.Middleware.Auth.OAuth2
import           Network.Wai.Middleware.Auth.Provider
import           System.IO                            (hPutStrLn, stderr)


-- | Create a google authentication provider
--
-- @since 0.1.0
mkGoogleProvider
  :: T.Text -- ^ @client_id@ from google
  -> T.Text -- ^ @client_secret@ from google
  -> [S.ByteString] -- ^ White list of posix regular expressions for emails
  -- attached to github account.
  -> Maybe ProviderInfo -- ^ Replacement for default info
  -> Google
mkGoogleProvider clientId clientSecret emailWhiteList mProviderInfo =
  Google
    "https://www.googleapis.com/oauth2/v3/userinfo"
    emailWhiteList
    OAuth2
    { oa2ClientId = clientId
    , oa2ClientSecret = clientSecret
    , oa2AuthorizeEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    , oa2AccessTokenEndpoint = "https://www.googleapis.com/oauth2/v4/token"
    , oa2Scope = Just ["https://www.googleapis.com/auth/userinfo.email"]
    , oa2ProviderInfo = fromMaybe defProviderInfo mProviderInfo
    }
  where
    defProviderInfo =
      ProviderInfo
      { providerTitle = "Google"
      , providerLogoUrl =
          "https://upload.wikimedia.org/wikipedia/commons/thumb/5/53/Google_%22G%22_Logo.svg/200px-Google_%22G%22_Logo.svg.png"
      , providerDescr = "Use your Google account to access this page."
      }

-- | Aeson parser for `Google` provider.
--
-- @since 0.1.0
googleParser :: ProviderParser
googleParser = mkProviderParser (Proxy :: Proxy Google)


data Google = Google
  { googleAPIEmailEndpoint :: T.Text
  , googleEmailWhitelist   :: [S.ByteString]
  , googleOAuth2           :: OAuth2
  }

instance FromJSON Google where
  parseJSON =
    withObject "Google Provider Object" $ \obj -> do
      clientId <- obj .: "client_id"
      clientSecret <- obj .: "client_secret"
      emailWhiteList <- obj .:? "email_white_list" .!= []
      mProviderInfo <- obj .:? "provider_info"
      return $
        mkGoogleProvider
          clientId
          clientSecret
          (map encodeUtf8 emailWhiteList)
          mProviderInfo


newtype GoogleEmail = GoogleEmail { googleEmail :: S.ByteString } deriving Show

instance FromJSON GoogleEmail where
  parseJSON = withObject "Google Verified Email" $ \ obj -> do
    verified <- obj .: "email_verified"
    guard verified
    email <- obj .: "email"
    return (GoogleEmail $ encodeUtf8 email)



-- | Makes a call to google API and retrieves user's main email.
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
  handleLogin Google {..} req suffix renderUrl onSuccess onFailure = do
    let onOAuth2Success accessToken = do
          catchAny
            (do email <-
                  googleEmail <$>
                  retrieveEmail googleAPIEmailEndpoint accessToken
                let mEmail = getValidEmail googleEmailWhitelist [email]
                case mEmail of
                  Just email' -> onSuccess email'
                  Nothing ->
                    onFailure
                      status403
                      "No valid email with permission to access was found.") $ \err -> do
            hPutStrLn stderr $ "Issue communicating with Google: " ++ show err
            onFailure status501 "Issue communicating with Google."
    handleLogin googleOAuth2 req suffix renderUrl onOAuth2Success onFailure
