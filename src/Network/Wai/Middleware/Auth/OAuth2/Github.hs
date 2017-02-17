{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
module Network.Wai.Middleware.Auth.OAuth2.Github
    ( Github(..)
    , githubParser
    , mkGithubProvider
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


mkGithubProvider
  :: T.Text
  -> T.Text
  -> T.Text
  -> [T.Text]
  -> Github
mkGithubProvider appName clientId clientSecret emailWhiteList =
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
    , oa2ProviderInfo =
        ProviderInfo
        { providerTitle = "GitHub"
        , providerLogoUrl =
            "https://assets-cdn.github.com/images/modules/logos_page/Octocat.png"
        , providerDescr =
            "Use your GitHub account to access this page."
        }
    }

githubParser :: ProviderParser
githubParser = mkProviderParser (undefined :: Github)


data Github = Github
  { githubAppName          :: T.Text
  , githubAPIEmailEndpoint :: T.Text
  , githubEmailWhitelist   :: [T.Text]
  , githubOAuth2           :: OAuth2
  }

instance FromJSON Github where

  parseJSON = withObject "Github Provider Object" $ \ obj -> do
    appName <- obj .: "app_name"
    clientId <- obj .: "client_id"
    clientSecret <- obj .: "client_secret"
    emailWhiteList <- obj .:? "email_white_list" .!= []
    return $ mkGithubProvider appName clientId clientSecret emailWhiteList


newtype GithubEmail = GithubEmail { githubEmail :: T.Text } deriving Show

instance FromJSON GithubEmail where
  parseJSON = withObject "Github Verified Email" $ \ obj -> do
    verified <- obj .: "verified"
    guard verified
    email <- obj .: "email"
    return (GithubEmail email)



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
  handleLogin Github {..} man req renderUrl suffix onSuccess onFailure = do
    let onOAuth2Success accessToken = do
          catchAny
            (do emails <-
                  map githubEmail <$>
                  retrieveEmails
                    githubAppName
                    githubAPIEmailEndpoint
                    accessToken
                let mEmail = getValidEmail githubEmailWhitelist emails
                case mEmail of
                  Just email -> onSuccess (encodeUtf8 email)
                  Nothing ->
                    onFailure status403 $
                    "No valid email was found with permission to access this resource. " <>
                    "Please contact the administrator.")
            (\_err -> onFailure status501 "Issue communicating with github")
    handleLogin githubOAuth2 man req renderUrl suffix onOAuth2Success onFailure
