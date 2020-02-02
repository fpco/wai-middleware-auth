{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Spec.Network.Wai.Middleware.Auth.OpenIDConnect (tests) where

import           Control.Monad                          (void)
import           Control.Monad.IO.Class                 (liftIO)
import qualified Crypto.JOSE                            as JOSE
import           Data.Function                          ((&))
import qualified Data.Text                              as T
import           GHC.Exts                               (fromList, fromString)
import           Network.Wai.Auth.Test                  (ChangeProvider,
                                                         FakeProviderConf(..),
                                                         fakeProvider,
                                                         const200, get,
                                                         parseURI)
import qualified Network.Wai.Handler.Warp               as Warp
import qualified Network.Wai.Middleware.Auth            as Auth
import           Network.Wai.Middleware.Auth.OpenIDConnect 
import           Network.Wai.Middleware.Auth.Provider   (Provider(..))
import           Network.Wai.Test                       (Session, assertHeader,
                                                         assertStatus,
                                                         runSession,
                                                         setClientCookie)
import           Test.Tasty                             (TestTree, testGroup)
import           Test.Tasty.HUnit                       (testCase)
import qualified URI.ByteString                         as U
import qualified Web.Cookie                             as Cookie

tests :: TestTree
tests = testGroup "Network.Wai.Auth.OpenIDConnect"
  [ testCase "when a request without a session is made then redirect to re-authorize" $
      runSessionWithProvider $ \host _ -> do
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
          (U.serializeURIRef' host <> "/authorize?scope=openid%2Cscope1&client_id=client-id&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%2Fprefix%2Foidc%2Fcomplete")
          redirect3

  , testCase "when a request is made with a valid session then pass the request through" $
      runSessionWithProvider $ \_ _ -> do
        createSession
        response <- get "/some/endpoint"
        assertStatus 200 response

  , testCase "when an ID token expired and no refresh token is available then redirect to re-authorize" $
      runSessionWithProvider $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtExpiresIn = -600, returnRefreshToken = False })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an ID token expired then use a refresh token" $
      runSessionWithProvider $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtExpiresIn = -600 })
        createSession
        changeProvider (\c -> c { jwtExpiresIn = 600 })
        response <- get "/some/endpoint"
        assertStatus 200 response

  , testCase "when a request is made with an invalid session redirect to re-authorize" $ 
      runSessionWithProvider $ \_ _ -> do
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

  , testCase "when an ID token has an invalid audience then redirect to re-authorize" $
      runSessionWithProvider $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtAudience = fromString "wrong-audience" })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an ID token has an invalid issuer then redirect to re-authorize" $
      runSessionWithProvider $ \_ changeProvider -> do
        changeProvider (\c -> c { jwtIssuer = "wrong-issuer" })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when a session does not contain an ID token then redirect to re-authorize" $
      runSessionWithProvider $ \_ changeProvider -> do
        changeProvider (\c -> c { returnIdToken = False })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response

  , testCase "when an ID token has an invalid signature then redirect to re-authorize" $
      runSessionWithProvider $ \_ changeProvider -> do
        newJWK <- liftIO $ JOSE.genJWK (JOSE.RSAGenParam 256)
        changeProvider (\c -> c { jwtJWK = newJWK })
        createSession
        response <- get "/some/endpoint"
        assertStatus 303 response
  ]

createSession :: Session ()
createSession = void $ get "/prefix/oidc/complete?code=1234"

runSessionWithProvider :: (U.URI -> ChangeProvider -> Session a) -> IO a
runSessionWithProvider session = do
  (provider, changeProvider) <- fakeProvider
  Warp.testWithApplication (pure provider) $ \port -> do
    let host = parseURI $ "http://localhost:" <> T.pack (show port)
    middleware <- Auth.mkAuthMiddleware =<< authSettings host
    let app = middleware const200
    runSession (session host changeProvider) app

authSettings :: U.URI -> IO Auth.AuthSettings
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
