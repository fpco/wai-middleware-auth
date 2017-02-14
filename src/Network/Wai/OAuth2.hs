{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.OAuth2
    ( OAuth2Client(..)
    , OAuth2(..)
    , githubOAuth2
    , oAuth2Complete
    , getUserIdentity
    , getLoginUrl
    ) where

import qualified Data.ByteString      as S
import qualified Data.Text            as T
import           Network.HTTP.Client  (Manager)
import           Network.OAuth.OAuth2
import           Network.Wai          (Request, queryString)

data OAuth2Client = OAuth2Client
    { oacClientId     :: S.ByteString
    , oacClientSecret :: S.ByteString
    } deriving (Show)



githubOAuth2 :: OAuth2Client -> OAuth2
githubOAuth2 client = OAuth2
    { oauthClientId = oacClientId client
    , oauthClientSecret = oacClientSecret client
    , oauthOAuthorizeEndpoint = "https://github.com/login/oauth/authorize"
    , oauthAccessTokenEndpoint = "https://github.com/login/oauth/access_token"
    , oauthCallback = Nothing }


oAuth2Complete :: OAuth2 -> Request -> Manager -> IO (OAuth2Result AccessToken)
oAuth2Complete oauth2 req man = fetchAccessToken man oauth2 code
  where
    code = case lookup "code" $ queryString req of
               Just (Just c) -> c
               Nothing       -> error "code not found" -- TODO: handle error


getLoginUrl :: OAuth2 -> S.ByteString
getLoginUrl = authorizationUrl

getUserIdentity :: AccessToken -> Maybe T.Text
getUserIdentity = const (Just "foobar")

-------- Preliminary ideas. TODO: implement or remove

-- type URI = S.ByteString

-- newtype OAuth2Scope = OAuth2Scope [S.ByteString]

-- newtype OAuth2State1 = OAuth2State (Maybe S.ByteString)

-- -- | Authentication Code, also known as Authorization Grant
-- newtype OAuth2Code = Code S.ByteString


-- class OAuth2Server s where

--     authorizeURL :: s -> OAuth2Client -> OAuth2Scope -> OAuth2State1 -> URI

--     getAccessToken :: s -> OAuth2Client -> OAuth2Code -> OAuth2State1 -> IO OAuth2AccessToken





-- data Identity = Identity S.ByteString

-- class AuthMiddleware auth where
--     type Credentials auth :: *

--     getAuthName :: auth -> T.Text

--     -- | OAuth2: redirect to auth URL
--     --   OpenID: redirect to auth URL
--     --   LDAP:   page with login form
--     -- Will be redirected to
--     loginPage :: auth -> Request -> IO Response

--     loginWith :: auth -> Credentials auth -> Either S.ByteString Identity

