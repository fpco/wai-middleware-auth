{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Middleware.Auth.OAuth2.Github
    ( Github(..)
    , mkGithubProvider
    , githubParser
    ) where
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


-- | Create a github authentication provider
--
-- @since 0.1.0
mkGithubProvider
  :: T.Text -- ^ Name of the application as it is registered on github
  -> T.Text -- ^ @client_id@ from github
  -> T.Text -- ^ @client_secret@ from github
  -> [S.ByteString] -- ^ White list of posix regular expressions for emails
  -- attached to github account.
  -> Maybe ProviderInfo -- ^ Replacement for default info
  -> Github
mkGithubProvider appName clientId clientSecret emailWhiteList mProviderInfo =
  Github
    appName
    "https://api.github.com/user/emails"
    emailWhiteList
    OAuth2
    { oa2ClientId = clientId
    , oa2ClientSecret = clientSecret
    , oa2AuthorizeEndpoint = "https://github.com/login/oauth/authorize"
    , oa2AccessTokenEndpoint = "https://github.com/login/oauth/access_token"
    , oa2Scope = Just ["user:email"]
    , oa2ProviderInfo = fromMaybe defProviderInfo mProviderInfo
    }
  where
    defProviderInfo =
      ProviderInfo
      { providerTitle = "GitHub"
      , providerLogoUrl =
          "https://assets-cdn.github.com/images/modules/logos_page/Octocat.png"
      , providerDescr = "Use your GitHub account to access this page."
      }

-- | Aeson parser for `Github` provider.
--
-- @since 0.1.0
githubParser :: ProviderParser
githubParser = mkProviderParser (Proxy :: Proxy Github)


-- | Github authentication provider
data Github = Github
  { githubAppName          :: T.Text
  , githubAPIEmailEndpoint :: T.Text
  , githubEmailWhitelist   :: [S.ByteString]
  , githubOAuth2           :: OAuth2
  }

instance FromJSON Github where
  parseJSON =
    withObject "Github Provider Object" $ \obj -> do
      appName <- obj .: "app_name"
      clientId <- obj .: "client_id"
      clientSecret <- obj .: "client_secret"
      emailWhiteList <- obj .:? "email_white_list" .!= []
      mProviderInfo <- obj .:? "provider_info"
      return $
        mkGithubProvider
          appName
          clientId
          clientSecret
          (map encodeUtf8 emailWhiteList)
          mProviderInfo

-- | Newtype wrapper for a github verified email
newtype GithubEmail = GithubEmail { githubEmail :: S.ByteString } deriving Show

instance FromJSON GithubEmail where
  parseJSON = withObject "Github Verified Email" $ \ obj -> do
    True <- obj .: "verified"
    email <- obj .: "email"
    return (GithubEmail $ encodeUtf8 email)


-- | Makes an API call to github and retrieves all user's verified emails.
retrieveEmails :: T.Text -> T.Text -> S.ByteString -> IO [GithubEmail]
retrieveEmails appName emailApiEndpoint accessToken = do
  req <- parseRequest (T.unpack emailApiEndpoint)
  resp <- httpJSON $ setRequestHeaders headers req
  return $ getResponseBody resp
  where
    headers =
      [ ("Accept", "application/vnd.github.v3+json")
      , ("Authorization", "token " <> accessToken)
      , ("User-Agent", encodeUtf8 appName)
      ]


instance AuthProvider Github where
  getProviderName _ = "github"
  getProviderInfo = getProviderInfo . githubOAuth2
  handleLogin Github {..} req suffix renderUrl onSuccess onFailure = do
    let onOAuth2Success oauth2Tokens = do
          catchAny
            (do accessToken <-
                  case decodeToken oauth2Tokens of
                    Left err -> fail err
                    Right tokens -> pure $ encodeUtf8 $ OA2.atoken $ OA2.accessToken tokens
                emails <-
                  map githubEmail <$>
                  retrieveEmails
                    githubAppName
                    githubAPIEmailEndpoint
                    accessToken
                let mEmail = getValidEmail githubEmailWhitelist emails
                case mEmail of
                  Just email -> onSuccess email
                  Nothing ->
                    onFailure status403 $
                    "No valid email was found with permission to access this resource. " <>
                    "Please contact the administrator.")
            (\_err -> onFailure status501 "Issue communicating with github")
    handleLogin githubOAuth2 req suffix renderUrl onOAuth2Success onFailure
