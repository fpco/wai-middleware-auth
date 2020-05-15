{-# LANGUAGE OverloadedStrings #-}

module Spec.Network.Wai.Middleware.Auth.OAuth2 (tests) where

import           Control.Monad                          (void)
import           Data.Function                          ((&))
import qualified Data.Text                              as T
import qualified Data.Text.Encoding                     as TE
import           GHC.Exts                               (fromList)
import qualified Network.HTTP.Types.Status              as Status
import qualified Network.Wai                            as Wai
import           Network.Wai.Auth.Test                  (ChangeProvider,
                                                         FakeProviderConf(..),
                                                         fakeProvider,
                                                         const200, get)
import qualified Network.Wai.Handler.Warp               as Warp
import qualified Network.Wai.Middleware.Auth            as Auth
import           Network.Wai.Middleware.Auth.OAuth2     (OAuth2(..),
                                                         getAccessToken)
import           Network.Wai.Middleware.Auth.Provider   (Provider(..),
                                                         ProviderInfo(..))
import           Network.Wai.Test                       (Session, assertHeader,
                                                         assertStatus,
                                                         runSession,
                                                         setClientCookie)
import           Test.Tasty                             (TestTree, testGroup)
import           Test.Tasty.HUnit                       (testCase)
import qualified Web.Cookie                             as Cookie
import qualified Web.ClientSession

tests :: TestTree
tests = testGroup "Network.Wai.Auth.OAuth2"
  [ testCase "when a request without a session is made then redirect to re-authorize" $
      runSessionWithProvider const200 $ \host _ -> do
        redirect1 <- get "/hi"
        assertStatus 303 redirect1
        assertHeader "Location" "/prefix" redirect1
        redirect2 <- get "/prefix"
        assertStatus 303 redirect2
        assertHeader "location" "/prefix/oauth2" redirect2
        redirect3 <- get "/prefix/oauth2"
        assertStatus 303 redirect3
        assertHeader
          "location"
          (TE.encodeUtf8 host <> "/authorize?scope=scope1%2Cscope2&client_id=client-id&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%2Fprefix%2Foauth2%2Fcomplete")
          redirect3

  , testCase "when a request is made with a valid session then pass the request through" $
      runSessionWithProvider const200 $ \_ _ -> do
        createSession
        response <- get "/some/endpoint"
        assertStatus 200 response

  , testCase "when an access token expired and no refresh token is available then redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { accessTokenExpiresIn = -600, returnRefreshToken = False })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an access token expired then use a refresh token" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { accessTokenExpiresIn = -600 })
        createSession
        response <- get "/some/endpoint"
        assertStatus 200 response

  , testCase "when a request is made with an invalid session redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ _ -> do
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

  , testCase "when a request is made to the complete endpoint then create a session" $
      runSessionWithProvider const200 $ \_ _ -> do
        response <- get "/prefix/oauth2/complete?code=1234"
        assertStatus 303 response
        assertHeader "location" "/" response

  , testCase "when a request with a valid session is made then the app can access the session" $
      let app req respond = 
            case getAccessToken req of
              Nothing -> respond $ Wai.responseLBS Status.badRequest400 [] ""
              Just _ -> respond $ Wai.responseLBS Status.ok200 [] ""
      in runSessionWithProvider app $ \_ _ -> do
          createSession
          response <- get "/some/endpoint"
          assertStatus 200 response
  ]

createSession :: Session ()
createSession = void $ get "/prefix/oauth2/complete?code=1234"

authSettings :: T.Text -> Auth.AuthSettings
authSettings host =
  Auth.defaultAuthSettings
    & Auth.setAuthProviders (fromList [("oauth2", provider host)])
    & Auth.setAuthPrefix "prefix"
    & Auth.setAuthCookieName "auth-cookie"
    & Auth.setAuthKey (snd <$> Web.ClientSession.randomKey)

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

runSessionWithProvider :: Wai.Application -> (T.Text -> ChangeProvider -> Session a) -> IO a
runSessionWithProvider app session = do
  (p, changeProvider) <- fakeProvider
  Warp.testWithApplication (pure p) $ \port -> do
    let host = "http://localhost:" <> T.pack (show port)
    middleware <- Auth.mkAuthMiddleware $ authSettings host
    let app' = middleware app
    runSession (session host changeProvider) app'
