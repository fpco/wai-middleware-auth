{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Middleware.Auth.OAuth2.Gitlab
    ( Gitlab(..)
    , mkGitlabProvider
    , gitlabParser
    , gitlabEmailWhitelist
    ) where
import           Control.Applicative                  ((<|>))
import           Control.Exception.Safe               (catchAny)
import           Data.Maybe                           (fromMaybe)
import           Data.Aeson
import qualified Data.ByteString                      as S
import           Data.Proxy                           (Proxy (..))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8)
import           Network.HTTP.Simple                  (getResponseBody,
                                                       httpJSON, parseRequest,
                                                       setRequestHeaders)
import           Network.HTTP.Types
import qualified Network.OAuth.OAuth2                 as OA2
import           Network.Wai.Auth.Internal            (decodeToken)
import           Network.Wai.Auth.Tools               (getValidEmail)
import           Network.Wai.Middleware.Auth.OAuth2
import           Network.Wai.Middleware.Auth.Provider

-- | Create a gitlab authentication provider
--
-- @since 0.2.4.0
mkGitlabProvider
  :: T.Text -- ^ Hostname of GitLab instance (e.g. @gitlab.com@)
  -> T.Text -- ^ Name of the application as it is registered on gitlab
  -> T.Text -- ^ @client_id@ from gitlab
  -> T.Text -- ^ @client_secret@ from gitlab
  -> [S.ByteString] -- ^ White list of posix regular expressions for emails
  -- attached to gitlab account.
  -> Maybe ProviderInfo -- ^ Replacement for default info
  -> Gitlab
mkGitlabProvider gitlabHost appName clientId clientSecret emailAllowList mProviderInfo =
  Gitlab
    appName
    ("https://" <> gitlabHost <> "/api/v4/user")
    emailAllowList
    OAuth2
    { oa2ClientId = clientId
    , oa2ClientSecret = clientSecret
    , oa2AuthorizeEndpoint = ("https://" <> gitlabHost <> "/oauth/authorize")
    , oa2AccessTokenEndpoint = ("https://" <> gitlabHost <> "/oauth/token")
    , oa2Scope = Just ["read_user"]
    , oa2ProviderInfo = fromMaybe defProviderInfo mProviderInfo
    }
  where
    defProviderInfo =
      ProviderInfo
      { providerTitle = "GitLab"
      , providerLogoUrl =
          "https://about.gitlab.com/images/press/logo/png/gitlab-icon-rgb.png"
      , providerDescr = "Use your GitLab account to access this page."
      }

-- | Aeson parser for `Gitlab` provider.
--
-- @since 0.2.4.0
gitlabParser :: ProviderParser
gitlabParser = mkProviderParser (Proxy :: Proxy Gitlab)


-- | Gitlab authentication provider
data Gitlab = Gitlab
  { gitlabAppName          :: T.Text
  , gitlabAPIUserEndpoint  :: T.Text
  , gitlabEmailAllowlist   :: [S.ByteString]
  , gitlabOAuth2           :: OAuth2
  }

gitlabEmailWhitelist :: Gitlab -> [S.ByteString]
gitlabEmailWhitelist = gitlabEmailAllowlist
{-# DEPRECATED gitlabEmailWhitelist "In favor of `gitlabEmailAllowlist`" #-}

instance FromJSON Gitlab where
  parseJSON =
    withObject "Gitlab Provider Object" $ \obj -> do
      gitlabHost <- obj .:? "gitlab_host"
      appName <- obj .: "app_name"
      clientId <- obj .: "client_id"
      clientSecret <- obj .: "client_secret"
      emailAllowList <- obj .: "email_allow_list" <|> obj .: "email_white_list" <|> pure []
      mProviderInfo <- obj .:? "provider_info"
      return $
        mkGitlabProvider
          (fromMaybe "gitlab.com" gitlabHost)
          appName
          clientId
          clientSecret
          (map encodeUtf8 emailAllowList)
          mProviderInfo

-- | Newtype wrapper for a gitlab user
newtype GitlabEmail = GitlabEmail { gitlabEmail :: S.ByteString } deriving Show

instance FromJSON GitlabEmail where
  parseJSON = withObject "Gitlab Email" $ \ obj -> do
    email <- obj .: "email"
    return (GitlabEmail $ encodeUtf8 email)


-- | Makes an API call to gitlab and retrieves user's verified email.
-- Note: we only retrieve the PRIMARY email, because there is no way
-- to tell whether secondary emails are verified or not.
retrieveUser :: T.Text -> T.Text -> S.ByteString -> IO GitlabEmail
retrieveUser appName userApiEndpoint accessToken = do
  req <- parseRequest (T.unpack userApiEndpoint)
  resp <- httpJSON $ setRequestHeaders headers req
  return $ getResponseBody resp
  where
    headers =
      [ ("Authorization", "Bearer " <> accessToken)
      , ("User-Agent", encodeUtf8 appName)
      ]


instance AuthProvider Gitlab where
  getProviderName _ = "gitlab"
  getProviderInfo = getProviderInfo . gitlabOAuth2
  handleLogin Gitlab {..} req suffix renderUrl onSuccess onFailure = do
    let onOAuth2Success oauth2Tokens = do
          catchAny
            (do accessToken <-
                  case decodeToken oauth2Tokens of
                    Left err -> fail err
                    Right tokens -> pure $ encodeUtf8 $ OA2.atoken $ OA2.accessToken tokens
                email <-
                  gitlabEmail <$>
                  retrieveUser
                    gitlabAppName
                    gitlabAPIUserEndpoint
                    accessToken
                let mValidEmail = getValidEmail gitlabEmailAllowlist [email]
                case mValidEmail of
                  Just validEmail -> onSuccess validEmail
                  Nothing ->
                    onFailure status403 $
                    "Your primary email address does not have permission to access this resource. " <>
                    "Please contact the administrator.")
            (\_err -> onFailure status501 "Issue communicating with gitlab")
    handleLogin gitlabOAuth2 req suffix renderUrl onOAuth2Success onFailure
