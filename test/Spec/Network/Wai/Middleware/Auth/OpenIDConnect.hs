{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Spec.Network.Wai.Middleware.Auth.OpenIDConnect (tests) where

import           Control.Monad                          (void)
import           Control.Monad.IO.Class                 (liftIO)
import           Data.ByteString                        (ByteString)
import qualified Data.IORef                             as IORef
import qualified Crypto.JOSE                            as JOSE
import qualified Crypto.JWT                             as JWT
import qualified Control.Monad.Except
import qualified Data.Aeson                             as Aeson
import           Data.Function                          ((&))
import qualified Data.Text                              as T
import qualified Data.Text.Encoding
import qualified Data.Text.Lazy
import qualified Data.Text.Lazy.Encoding
import qualified Data.Time.Clock                        as Clock
import           GHC.Exts                               (fromList, fromString)
import qualified Network.HTTP.Types.Status              as Status
import qualified Network.OAuth.OAuth2                   as OA2
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp               as Warp
import qualified Network.Wai.Middleware.Auth            as Auth
import           Network.Wai.Middleware.Auth.OpenIDConnect 
import           Network.Wai.Middleware.Auth.Provider   (Provider(..))
import           Network.Wai.Test                       (Session, SResponse,
                                                         assertHeader,
                                                         assertStatus,
                                                         defaultRequest,
                                                         request, runSession,
                                                         setClientCookie,
                                                         setPath)
import qualified Lens.Micro                             as Lens
import           Test.Tasty                             (TestTree, testGroup)
import           Test.Tasty.HUnit                       (assertBool, testCase)
import qualified URI.ByteString                         as U
import qualified Web.Cookie                             as Cookie

tests :: TestTree
tests = testGroup "Network.Wai.Auth.OpenIDConnect"
  [ testCase "when a request without a session is made then redirect to re-authorize" $ do
      (provider, _) <- fakeProvider
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
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

  , testCase "when a request is made with a valid session then pass the request through" $ do
      (provider, _) <- fakeProvider
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          createSession
          response <- get "/some/endpoint"
          assertStatus 200 response

  , testCase "when an ID token expired and no refresh token is available then redirect to re-authorize" $ do
      (provider, changeConfig) <- fakeProvider
      changeConfig (\c -> c { jwtExpiresIn = -600 })
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          createSession
          response <- get "/some/endpoint"
          assertStatus 303 response

  , testCase "when an ID token expired then use a refresh" $ do
      (provider, changeConfig) <- fakeProvider 
      changeConfig (\c -> c { jwtExpiresIn = -600, returnRefreshToken = True })
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          createSession
          liftIO $ changeConfig (\c -> c { jwtExpiresIn = 600 })
          response <- get "/some/endpoint"
          assertStatus 200 response

  , testCase "when a request is made with an invalid session redirect to re-authorize" $ do
      (provider, _) <- fakeProvider 
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
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

  , testCase "when an ID token has an invalid audience then redirect to re-authorize" $ do
      (provider, changeConfig) <- fakeProvider
      changeConfig (\c -> c { jwtAudience = fromString "wrong-audience" })
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          createSession
          response <- get "/some/endpoint"
          assertStatus 303 response

  , testCase "when an ID token has an invalid issuer then redirect to re-authorize" $ do
      (provider, changeConfig) <- fakeProvider
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          liftIO $ changeConfig (\c -> c { jwtIssuer = "wrong-issuer" })
          createSession
          response <- get "/some/endpoint"
          assertStatus 303 response

  , testCase "when a session does not contain an ID token then redirect to re-authorize" $ do
      (provider, changeConfig) <- fakeProvider
      changeConfig (\c -> c { returnIdToken = False })
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          createSession
          response <- get "/some/endpoint"
          assertStatus 303 response

  , testCase "when an ID token has an invalid signature then redirect to re-authorize" $ do
      (provider, changeConfig) <- fakeProvider
      Warp.testWithApplication (pure provider) $ \port -> do
        let host = parseURI $ "http://localhost:" <> T.pack (show port)
        middleware <- Auth.mkAuthMiddleware =<< authSettings host
        let app = middleware const200
        flip runSession app $ do
          newJWK <- liftIO $ JOSE.genJWK (JOSE.RSAGenParam 256)
          liftIO $ changeConfig (\c -> c { jwtJWK = newJWK })
          createSession
          response <- get "/some/endpoint"
          assertStatus 303 response
  ]

get :: ByteString -> Session SResponse
get = request . setPath defaultRequest 

createSession :: Session ()
createSession = void $ get "/prefix/oidc/complete?code=1234"

const200 :: Wai.Application
const200 _ respond = respond $ Wai.responseLBS Status.ok200 [] ""

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

data FakeOIDCProviderConfig
  = FakeOIDCProviderConfig
      { jwtExpiresIn :: Clock.NominalDiffTime,
        jwtAudience :: JWT.StringOrURI,
        jwtIssuer :: T.Text,
        jwtJWK :: JOSE.JWK,
        jwtSub :: String,
        returnIdToken :: Bool,
        returnRefreshToken :: Bool
      }

defaultConfig :: IO FakeOIDCProviderConfig
defaultConfig = do
  jwk <- JOSE.genJWK (JOSE.RSAGenParam 256)
  pure
    FakeOIDCProviderConfig
      { jwtExpiresIn = 600,
        jwtAudience = "client-id",
        jwtIssuer = "test-oidc-provider",
        jwtJWK = jwk,
        jwtSub = "1234",
        returnIdToken = True,
        returnRefreshToken = False
      }

fakeProvider :: IO (Wai.Application, (FakeOIDCProviderConfig -> FakeOIDCProviderConfig) -> IO ())
fakeProvider = do
  config <- defaultConfig
  configRef <- IORef.newIORef config
  let changeConfig = IORef.modifyIORef configRef
  pure (fakeProvider' configRef, changeConfig)

fakeProvider' :: IORef.IORef FakeOIDCProviderConfig -> Wai.Application
fakeProvider' configRef req respond = do
  config <- IORef.readIORef configRef
  case Wai.pathInfo req of
    [".well-known", "openid-configuration"] ->
      case Data.Text.Encoding.decodeUtf8 <$> Wai.requestHeaderHost req of
        Nothing ->
          Wai.responseLBS Status.badRequest400 [] ""
            & respond
        Just host ->
          Metadata
            { issuer = jwtIssuer config,
              authorizationEndpoint = parseURI ("http://" <> host <> "/authorize"),
              tokenEndpoint = parseURI ("http://" <> host <> "/token"),
              userinfoEndpoint = Nothing,
              revocationEndpoint = Nothing,
              jwksUri = "http://" <> host <> "/jwks",
              responseTypesSupported = ["code"],
              subjectTypesSupported = ["public"],
              idTokenSigningAlgValuesSupported = ["RS256"],
              scopesSupported = Just ["openid"],
              tokenEndpointAuthMethodsSupported = Just ["client_secret_basic"],
              claimsSupported = Just ["iss", "sub", "aud", "exp", "iat"]
            }
            & Aeson.encode
            & Wai.responseLBS Status.ok200 [("Content-Type", "application/json")]
            & respond
    ["jwks"] ->
      JOSE.JWKSet [jwtJWK config]
        & Aeson.encode
        & Wai.responseLBS Status.ok200 [("Content-Type", "application/json")]
        & respond
    ["token"] -> do
      now <- Clock.getCurrentTime
      let claims =
            JWT.emptyClaimsSet
              & Lens.set JWT.claimIss (Just (fromString (T.unpack (jwtIssuer config))))
              & Lens.set JWT.claimAud (Just (JWT.Audience [jwtAudience config]))
              & Lens.set JWT.claimIat (Just (JWT.NumericDate now))
              & Lens.set JWT.claimExp (Just (JWT.NumericDate (Clock.addUTCTime (jwtExpiresIn config) now)))
              & Lens.set JWT.claimSub (Just (fromString (jwtSub config)))
      idToken <- doJwtSign (jwtJWK config) claims
      OA2.OAuth2Token
        { OA2.accessToken = OA2.AccessToken "access-granted",
          OA2.refreshToken =
            if returnRefreshToken config
              then Just (OA2.RefreshToken "refresh-token")
              else Nothing,
          OA2.expiresIn = Just 3600,
          OA2.tokenType = Nothing,
          OA2.idToken =
            if returnIdToken config
              then Just (OA2.IdToken idToken)
              else Nothing
        }
        & Aeson.encode
        & Wai.responseLBS Status.ok200 [("Content-Type", "application/json")]
        & respond
    _ ->
      Wai.responseLBS Status.notFound404 [] ""
        & respond

doJwtSign :: JOSE.JWK -> JWT.ClaimsSet -> IO T.Text
doJwtSign jwk claims = do
  result <- Control.Monad.Except.runExceptT $ do
    alg <- JOSE.bestJWSAlg jwk
    JWT.signClaims jwk (JOSE.newJWSHeader ((), alg)) claims
  case result of
    Left (err :: JOSE.Error) -> fail (show err)
    Right bytestring ->
      JOSE.encodeCompact bytestring
        & Data.Text.Lazy.Encoding.decodeUtf8
        & Data.Text.Lazy.toStrict
        & pure

parseURI :: T.Text -> U.URIRef U.Absolute
parseURI uri =
  Data.Text.Encoding.encodeUtf8 uri
    & U.parseURI U.laxURIParserOptions
    & either (error . show) id
