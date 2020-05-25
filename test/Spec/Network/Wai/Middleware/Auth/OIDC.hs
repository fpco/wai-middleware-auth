{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Spec.Network.Wai.Middleware.Auth.OIDC (tests) where

import           Control.Monad                          (void)
import           Control.Monad.IO.Class                 (liftIO)
import qualified Crypto.JOSE                            as JOSE
import           Data.Function                          ((&))
import qualified Data.Text                              as T
import qualified Data.Text.Encoding                     as TE
import           GHC.Exts                               (fromList, fromString)
import qualified Network.HTTP.Types.Status              as Status
import qualified Network.Wai                            as Wai
import           Network.Wai.Auth.Test                  (ChangeProvider,
                                                         FakeProviderConf(..),
                                                         fakeProvider,
                                                         const200, get)
import qualified Network.Wai.Handler.Warp               as Warp
import qualified Network.Wai.Middleware.Auth            as Auth
import           Network.Wai.Middleware.Auth.OIDC 
import           Network.Wai.Middleware.Auth.Provider   (Provider(..))
import           Network.Wai.Test                       (Session, assertHeader,
                                                         assertStatus,
                                                         runSession,
                                                         setClientCookie)
import           Test.Tasty                             (TestTree, testGroup)
import           Test.Tasty.HUnit                       (testCase)
import qualified Web.Cookie                             as Cookie
import qualified Web.ClientSession

tests :: TestTree
tests = testGroup "Network.Wai.Auth.OIDC"
  [ testCase "when a request without a session is made then redirect to re-authorize" $
      runSessionWithProvider const200 $ \host _ -> do
        redirect1 <- get "/hi"
        assertStatus 303 redirect1
        assertHeader "Location" "/prefix" redirect1
        redirect2 <- get "/prefix"
        assertStatus 303 redirect2
        assertHeader "location" "/prefix/oidc" redirect2
        redirect3 <- get "/prefix/oidc"
        assertStatus 303 redirect3
        assertHeader
          "location"
          (TE.encodeUtf8 host <> "/authorize?scope=openid%20scope1&client_id=client-id&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%2Fprefix%2Foidc%2Fcomplete")
          redirect3

  , testCase "when a request is made with a valid session then pass the request through" $
      runSessionWithProvider const200 $ \_ _ -> do
        createSession
        response <- get "/some/endpoint"
        assertStatus 200 response

  , testCase "when an ID token expired and no refresh token is available then redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtExpiresIn = -600, returnRefreshToken = False })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an ID token expired then use a refresh token" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtExpiresIn = -600 })
        createSession
        changeProvider (\c -> c { jwtExpiresIn = 600 })
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
        response <- get "/prefix/oidc/complete?code=1234"
        assertStatus 303 response
        assertHeader "location" "/" response

  , testCase "when a request with a valid session is made then the app can access the access token" $
      let app req respond = 
            case getAccessToken req of
              Nothing -> respond $ Wai.responseLBS Status.badRequest400 [] ""
              Just _ -> respond $ Wai.responseLBS Status.ok200 [] ""
      in runSessionWithProvider app $ \_ _ -> do
          createSession
          response <- get "/some/endpoint"
          assertStatus 200 response

  , testCase "when a request with a valid session is made then the app can access the id token" $
      let app req respond = 
            case getIdToken req of
              Nothing -> respond $ Wai.responseLBS Status.badRequest400 [] ""
              Just _ -> respond $ Wai.responseLBS Status.ok200 [] ""
      in runSessionWithProvider app $ \_ _ -> do
          createSession
          response <- get "/some/endpoint"
          assertStatus 200 response

  , testCase "when an ID token has an invalid audience then redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtAudience = fromString "wrong-audience" })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an ID token has an invalid issuer then redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtIssuer = "wrong-issuer" })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when a session does not contain an ID token then redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        changeProvider (\c -> c { returnIdToken = False })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an ID token has an invalid signature then redirect to re-authorize" $
      runSessionWithProvider const200 $ \_ changeProvider -> do
        newJWK <- liftIO $ JOSE.genJWK (JOSE.RSAGenParam 256)
        changeProvider (\c -> c { jwtJWK = newJWK })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response
  ]

createSession :: Session ()
createSession = void $ get "/prefix/oidc/complete?code=1234"

runSessionWithProvider :: Wai.Application -> (T.Text -> ChangeProvider -> Session a) -> IO a
runSessionWithProvider app session = do
  (provider, changeProvider) <- fakeProvider
  Warp.testWithApplication (pure provider) $ \port -> do
    let host = "http://localhost:" <> T.pack (show port)
    middleware <- Auth.mkAuthMiddleware =<< authSettings host
    let app' = middleware app
    runSession (session host changeProvider) app'

authSettings :: T.Text -> IO Auth.AuthSettings
authSettings host = do
  oidc' <- discover host
  let oidc =
        oidc'
          { oidcClientId = "client-id"
          , oidcClientSecret = "client-secret"
          , oidcScopes = ["openid", "scope1"]
          }
  pure $ Auth.defaultAuthSettings
    & Auth.setAuthProviders (fromList [("oidc", Provider oidc)])
    & Auth.setAuthPrefix "prefix"
    & Auth.setAuthCookieName "auth-cookie"
    & Auth.setAuthKey (snd <$> Web.ClientSession.randomKey)
