{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Network.Wai.Auth.Test
  (ChangeProvider
  , FakeProviderConf(..)
  , fakeProvider
  , const200
  , get
  ) where

import           Control.Monad.IO.Class                 (liftIO)
import           Data.ByteString                        (ByteString)
import qualified Data.IORef                             as IORef
import qualified Crypto.JOSE                            as JOSE
import qualified Crypto.JWT                             as JWT
import qualified Data.Aeson                             as Aeson
import           Data.Function                          ((&))
import qualified Data.Text                              as T
import qualified Data.Text.Encoding                     as TE
import qualified Data.Text.Lazy                         as TL
import qualified Data.Text.Lazy.Encoding                as TLE
import qualified Data.Time.Clock                        as Clock
import           GHC.Exts                               (fromString)
import qualified Network.HTTP.Types.Status              as Status
import qualified Network.OAuth.OAuth2                   as OA2
import qualified Network.Wai as Wai
import           Network.Wai.Auth.Internal              (Metadata(..))
import           Network.Wai.Test                       (Session, SResponse,
                                                         defaultRequest,
                                                         request, setPath)
import qualified Lens.Micro                             as Lens
import qualified URI.ByteString                         as U

get :: ByteString -> Session SResponse
get = request . setPath defaultRequest 

const200 :: Wai.Application
const200 _ respond = respond $ Wai.responseLBS Status.ok200 [] ""

data FakeProviderConf
  = FakeProviderConf
      { jwtExpiresIn :: Clock.NominalDiffTime,
        jwtAudience :: JWT.StringOrURI,
        jwtIssuer :: T.Text,
        jwtJWK :: JOSE.JWK,
        jwtSub :: String,
        accessTokenExpiresIn :: Int,
        returnIdToken :: Bool,
        returnRefreshToken :: Bool
      }

defaultConfig :: IO FakeProviderConf
defaultConfig = do
  jwk <- JOSE.genJWK (JOSE.RSAGenParam 256)
  pure
    FakeProviderConf
      { jwtExpiresIn = 600,
        jwtAudience = "client-id",
        jwtIssuer = "test-oidc-provider",
        jwtJWK = jwk,
        jwtSub = "1234",
        accessTokenExpiresIn = 600,
        returnIdToken = True,
        returnRefreshToken = True
      }

type ChangeProvider = (FakeProviderConf -> FakeProviderConf) -> Session ()

fakeProvider :: IO (Wai.Application, ChangeProvider)
fakeProvider = do
  config <- defaultConfig
  configRef <- IORef.newIORef config
  let changeProvider = IORef.modifyIORef configRef
  pure (fakeProvider' configRef, liftIO . changeProvider)

fakeProvider' :: IORef.IORef FakeProviderConf -> Wai.Application
fakeProvider' configRef req respond = do
  config <- IORef.readIORef configRef
  case Wai.pathInfo req of
    [".well-known", "openid-configuration"] ->
      case TE.decodeUtf8 <$> Wai.requestHeaderHost req of
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
          OA2.expiresIn = Just (accessTokenExpiresIn config),
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
  result <- JOSE.runJOSE $ do
    alg <- JOSE.bestJWSAlg jwk
    JWT.signClaims jwk (JOSE.newJWSHeader ((), alg)) claims
  case result of
    Left (err :: JOSE.Error) -> fail (show err)
    Right bytestring ->
      JOSE.encodeCompact bytestring
        & TLE.decodeUtf8
        & TL.toStrict
        & pure

parseURI :: T.Text -> U.URIRef U.Absolute
parseURI uri =
  TE.encodeUtf8 uri
    & U.parseURI U.laxURIParserOptions
    & either (error . show) id
