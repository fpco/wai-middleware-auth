{-# LANGUAGE OverloadedStrings #-}

module Spec.Network.Wai.Middleware.Auth.OAuth2 (tests) where

import           Control.Monad                          (void)
import qualified Data.Aeson                             as Aeson
import           Data.ByteString                        (ByteString)
import           Data.Function                          ((&))
import qualified Data.Text                              as T
import           GHC.Exts                               (fromList)
import qualified Network.HTTP.Types.Status              as Status
import qualified Network.OAuth.OAuth2                   as OA2
import qualified Network.Wai                            as Wai
import qualified Network.Wai.Handler.Warp               as Warp
import qualified Network.Wai.Middleware.Auth            as Auth
import           Network.Wai.Middleware.Auth.OAuth2     (OAuth2(..),
                                                         getAccessToken)
import           Network.Wai.Middleware.Auth.Provider   (Provider(..),
                                                         ProviderInfo(..))
import           Network.Wai.Test                       (Session, SResponse,
                                                         assertHeader,
                                                         assertStatus,
                                                         defaultRequest,
                                                         request, runSession,
                                                         setClientCookie,
                                                         setPath)
import           Test.Tasty                             (TestTree, testGroup)
import           Test.Tasty.HUnit                       (testCase)
import qualified Web.Cookie                             as Cookie

tests :: TestTree
tests = testGroup "Network.Wai.Auth.OAuth2"
  [ testCase "when a request without a session is made then the response redirects to the oauth2 authorize endpoint" $ do
      middleware <- Auth.mkAuthMiddleware $ authSettings "http://oauth2provider.com"
      let app = middleware const200
      flip runSession app $ do
        redirect1 <- get "/hi"
        assertStatus 303 redirect1
        assertHeader "Location" "/prefix" redirect1
        redirect2 <- get "/prefix"
        assertStatus 303 redirect2
        assertHeader "location" "/prefix/oauth2" redirect2
        redirect3 <- get "/prefix/oauth2"
        assertStatus 303 redirect3
        assertHeader "location" "http://oauth2provider.com/authorize?scope=scope1%2Cscope2&client_id=client-id&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%2Fprefix%2Foauth2%2Fcomplete" redirect3

  , testCase "when a request with an expired session is made then the response redirects to the oauth2 authorize endpoint" $ do
      Warp.testWithApplication (pure (fakeProvider (-3600))) $ \port -> do
        middleware <- Auth.mkAuthMiddleware $ authSettings ("http://localhost:" <> T.pack (show port))
        let app = middleware const200
        flip runSession app $ do
          createSession
          response <- get "/some/endpoint"
          assertStatus 303 response

  , testCase "when a request with a valid session is made then the middleware passes the request through" $ do
      Warp.testWithApplication (pure (fakeProvider 3600)) $ \port -> do
        middleware <- Auth.mkAuthMiddleware $ authSettings ("http://localhost:" <> T.pack (show port))
        let app = middleware const200
        flip runSession app $ do
          createSession
          response <- get "/some/endpoint"
          assertStatus 200 response

  , testCase "when a request with an invalid session is made then the response redirects to the oauth2 authorize endpoint" $ do
      Warp.testWithApplication (pure (fakeProvider 3600)) $ \port -> do
        middleware <- Auth.mkAuthMiddleware $ authSettings ("http://localhost:" <> T.pack (show port))
        let app = middleware const200
        flip runSession app $ do
          -- First create a known valid session, so we can see that it's the act
          -- of corrupting it that makes the test fail.
          createSession
          setClientCookie
            Cookie.defaultSetCookie
              { Cookie.setCookieName = "auth-cookie"
              , Cookie.setCookieValue = "garbage"
              }
          response <- get "/some/endpoint"
          assertStatus 303 response

  , testCase "when a request is made to the oauth2 complete endpoint then the middleware fatches an access token and sets a user sesion" $ 
      Warp.testWithApplication (pure (fakeProvider 3600)) $ \port -> do
        middleware <- Auth.mkAuthMiddleware $ authSettings ("http://localhost:" <> T.pack (show port))
        let app = middleware const200
        flip runSession app $ do
          response <- get "/prefix/oauth2/complete?code=1234"
          assertStatus 303 response
          assertHeader "location" "/" response

  , testCase "when a request with a valid session is made then the application can access the session payload" $ do
      Warp.testWithApplication (pure (fakeProvider 3600)) $ \port -> do
        middleware <- Auth.mkAuthMiddleware $ authSettings ("http://localhost:" <> T.pack (show port))
        let app = middleware $ \req respond ->
              case getAccessToken req of
                Nothing -> respond $ Wai.responseLBS Status.badRequest400 [] ""
                Just _ -> respond $ Wai.responseLBS Status.ok200 [] ""
        flip runSession app $ do
          createSession
          response <- get "/prefix/oauth2/complete?code=1234"
          assertStatus 200 response
  ]

get :: ByteString -> Session SResponse
get = request . setPath defaultRequest 

createSession :: Session ()
createSession = void $ get "/prefix/oauth2/complete?code=1234"

authSettings :: T.Text -> Auth.AuthSettings
authSettings host =
  Auth.defaultAuthSettings
    & Auth.setAuthProviders (fromList [("oauth2", provider host)])
    & Auth.setAuthPrefix "prefix"
    & Auth.setAuthCookieName "auth-cookie"

provider :: T.Text -> Provider
provider host =
  Provider
    OAuth2
      { oa2ClientId            = "client-id"
      , oa2ClientSecret        = "client-secret"
      , oa2AuthorizeEndpoint   = host <> "/authorize"
      , oa2AccessTokenEndpoint = host <> "/token"
      , oa2Scope               = Just ["scope1", "scope2"]
      , oa2ProviderInfo        = 
          ProviderInfo
            { providerTitle    = ""
            , providerLogoUrl  = ""
            , providerDescr    = ""
            }
      }

const200 :: Wai.Application
const200 _ respond = respond $ Wai.responseLBS Status.ok200 [] ""

fakeProvider :: Int -> Wai.Application
fakeProvider expiresIn req respond =
  case Wai.pathInfo req of
    ["token"] ->
      respond $ Wai.responseLBS Status.ok200 [("Content-Type", "application/json")] body
      where
        body = 
          Aeson.encode OA2.OAuth2Token
            { OA2.accessToken = OA2.AccessToken "access-granted",
              OA2.refreshToken = Nothing,
              OA2.expiresIn = Just expiresIn,
              OA2.tokenType = Nothing,
              OA2.idToken = Nothing
            }
    _ ->
      respond $ Wai.responseLBS Status.notFound404 [] ""
