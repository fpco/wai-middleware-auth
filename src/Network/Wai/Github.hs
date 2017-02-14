{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Github
    ( OAuth2Client(..)
    , OAuth2(..)
    , mkGithubProvider
    ) where
import           Control.Exception.Safe      (catchAny)
import           Control.Monad               (guard)
import           Data.Aeson
import qualified Data.ByteString             as S
import qualified Data.ByteString.Lazy        as SL
import           Data.Monoid                 ((<>))
import qualified Data.Text                   as T
import           Data.Text.Encoding          (encodeUtf8)
import           Network.HTTP.Client         (Manager)
import           Network.HTTP.Simple
import           Network.HTTP.Types          --(status303, status403)
import           Network.OAuth.OAuth2
import           Network.Wai                 (Request, queryString, responseLBS)
import           Network.Wai.Middleware.Auth

data OAuth2Client = OAuth2Client
    { oacClientId     :: S.ByteString
    , oacClientSecret :: S.ByteString
    } deriving (Show)



mkGithubProvider
  :: S.ByteString -- ^ Github Application name
  -> OAuth2Client -- ^ Github Application client_id and client_secret
  -> Provider
mkGithubProvider appName client =
  Provider $
  Github
    appName
    "https://api.github.com/user/emails"
    OAuth2
    { oauthClientId = oacClientId client
    , oauthClientSecret = oacClientSecret client
    , oauthOAuthorizeEndpoint = "https://github.com/login/oauth/authorize"
    , oauthAccessTokenEndpoint = "https://github.com/login/oauth/access_token"
    , oauthCallback = Nothing
    }

data Github = Github
  { githubAppName          :: S.ByteString
  , githubAPIEmailEndpoint :: String
  , githubOAuth2           :: OAuth2
  }

newtype GithubEmail = GithubEmail { githubEmail :: T.Text } deriving Show

instance FromJSON GithubEmail where
  parseJSON = withObject "Github Verified Email" $ \ obj -> do
    verified <- obj .: "verified"
    guard verified
    email <- obj .: "email"
    return (GithubEmail email)

retrieveEmails :: S.ByteString -> String -> S.ByteString -> IO [GithubEmail]
retrieveEmails appName emailApiEndpoint accessToken = do
  req <- parseRequest emailApiEndpoint
  resp <- httpJSON $ setRequestHeaders headers req
  return $ getResponseBody resp
  where
    headers =
      [ ("Accept", "application/vnd.github.v3+json")
      , ("Authorization", "token " <> accessToken)
      , ("User-Agent", appName)
      ]




-- TODO:
-- * Add `onFailure`
-- * Add email validation
instance AuthProvider Github where
  getName _ = "github"
  handleLogin (Github appName apiUrl oauth2) man req getAppRoot (prefix, suffix) onSuccess =
    case suffix of
      [] -> do
        appRoot <- getAppRoot req
        let callbackUrl =
              T.intercalate "/" ([appRoot] ++ prefix ++ ["complete"])
        let redirectUrl =
              authorizationUrl
                oauth2 {oauthCallback = Just $ encodeUtf8 callbackUrl}
        let redirectWithScope =
              appendQueryParam redirectUrl [("scope", "user:email")]
        return $
          responseLBS
            status303
            [("Location", redirectWithScope)]
            "Redirect to Github OAuth2"
      ["complete"] -> do
        let params = queryString req
        let onFailure status err = error "return $ responseLBS status []"
        case lookup "code" params of
          Just (Just code) -> do
            eRes <- fetchAccessToken man oauth2 code
            case eRes of
              Left err -> onFailure status403 err
              Right token -> do
                catchAny
                  (do emails <-
                        retrieveEmails appName apiUrl (accessToken token)
                      onSuccess (encodeUtf8 $ githubEmail $ head emails)) $ \err ->
                  return $ responseLBS status501 [] "Issue communicating with github"
          _ ->
            case (lookup "error" params, lookup "error_description" params) of
              (Just (Just "access_denied"), _) -> onFailure status403 "Access Denied"
              (_, Just (Just err_descr)) -> onFailure status400 err_descr
              _ -> onFailure status501 "Unknown error"

