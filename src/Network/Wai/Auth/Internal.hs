{-# OPTIONS_HADDOCK hide, not-home #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
module Network.Wai.Auth.Internal
  ( OAuth2TokenBinary(..)
  , Metadata(..)
  , encodeToken
  , decodeToken
  , oauth2Login
  , refreshTokens
  ) where


import           Control.Monad.Except                 (runExceptT)
import qualified Data.Aeson                           as Aeson
import           Data.Binary                          (Binary(get, put), encode,
                                                      decodeOrFail)
import qualified Data.ByteString                      as S
import qualified Data.ByteString.Char8                as S8 (pack)
import qualified Data.ByteString.Lazy                 as SL
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8,
                                                       decodeUtf8With)
import           Data.Text.Encoding.Error             (lenientDecode)
import           GHC.Generics                         (Generic)
import           Network.HTTP.Client                  (Manager)
import           Network.HTTP.Types                   (Status, status303,
                                                       status403, status404,
                                                       status501)
import qualified Network.OAuth.OAuth2                 as OA2
import           Network.Wai                          (Request, Response,
                                                       queryString, responseLBS)
import           Network.Wai.Middleware.Auth.Provider
import qualified URI.ByteString                       as U
import           URI.ByteString                       (URI)

decodeToken :: S.ByteString -> Either String OA2.OAuth2Token
decodeToken bs =
  case decodeOrFail $ SL.fromStrict bs of
    Right (_, _, token) -> Right $ unOAuth2TokenBinary token
    Left (_, _, err) -> Left err

encodeToken :: OA2.OAuth2Token -> S.ByteString
encodeToken = SL.toStrict . encode . OAuth2TokenBinary

newtype OAuth2TokenBinary =
  OAuth2TokenBinary { unOAuth2TokenBinary :: OA2.OAuth2Token }
  deriving (Show)

instance Binary OAuth2TokenBinary where
  put (OAuth2TokenBinary token) = do
    put $ OA2.atoken $ OA2.accessToken token
    put $ OA2.rtoken <$> OA2.refreshToken token
    put $ OA2.expiresIn token
    put $ OA2.tokenType token
    put $ OA2.idtoken <$> OA2.idToken token
  get = do
    accessToken <- OA2.AccessToken <$> get
    refreshToken <- fmap OA2.RefreshToken <$> get
    expiresIn <- get
    tokenType <- get
    idToken <- fmap OA2.IdToken <$> get
    pure $ OAuth2TokenBinary $
      OA2.OAuth2Token accessToken refreshToken expiresIn tokenType idToken

oauth2Login
  :: OA2.OAuth2
  -> Manager
  -> Maybe [T.Text]
  -> T.Text
  -> Request 
  -> [T.Text]
  -> (AuthLoginState -> IO Response)
  -> (Status -> S.ByteString -> IO Response)
  -> IO Response
oauth2Login oauth2 man oa2Scope providerName req suffix onSuccess onFailure = 
  case suffix of
    [] -> do
      -- https://tools.ietf.org/html/rfc6749#section-3.3
      let scope = (encodeUtf8 . T.intercalate " ") <$> oa2Scope
      let redirectUrl =
            getRedirectURI $
            appendQueryParams
              (OA2.authorizationUrl oauth2)
              (maybe [] ((: []) . ("scope", )) scope)
      return $
        responseLBS
          status303
          [("Location", redirectUrl)]
          "Redirect to OAuth2 Authentication server"
    ["complete"] ->
      let params = queryString req
      in case lookup "code" params of
            Just (Just code) -> do
              eRes <- runExceptT $ OA2.fetchAccessToken man oauth2 $ getExchangeToken code
              case eRes of
                Left err    -> onFailure status501 $ S8.pack $ show err
                Right token -> onSuccess $ encodeToken token
            _ ->
              case lookup "error" params of
                (Just (Just "access_denied")) ->
                  onFailure
                    status403
                    "User rejected access to the application."
                (Just (Just error_code)) ->
                  onFailure status501 $ "Received an error: " <> error_code
                (Just Nothing) ->
                  onFailure status501 $
                  "Unknown error connecting to " <>
                  encodeUtf8 providerName
                Nothing ->
                  onFailure
                    status404
                    "Page not found. Please continue with login."
    _ -> onFailure status404 "Page not found. Please continue with login."

refreshTokens :: OA2.OAuth2Token -> Manager -> OA2.OAuth2 -> IO (Maybe OA2.OAuth2Token)
refreshTokens tokens manager oauth2 = 
  case OA2.refreshToken tokens of
    Nothing -> pure Nothing
    Just refreshToken -> do
      res <- runExceptT $ OA2.refreshAccessToken manager oauth2 refreshToken
      case res of
        Left _ -> pure Nothing
        Right newTokens -> pure (Just newTokens)

getExchangeToken :: S.ByteString -> OA2.ExchangeToken
getExchangeToken = OA2.ExchangeToken . decodeUtf8With lenientDecode

appendQueryParams :: URI -> [(S.ByteString, S.ByteString)] -> URI
appendQueryParams uri params =
  OA2.appendQueryParams params uri

getRedirectURI :: U.URIRef a -> S.ByteString
getRedirectURI = U.serializeURIRef'

data Metadata
  = Metadata
      { issuer :: T.Text
      , authorizationEndpoint :: U.URI
      , tokenEndpoint :: U.URI
      , userinfoEndpoint :: Maybe T.Text
      , revocationEndpoint :: Maybe T.Text
      , jwksUri :: T.Text
      , responseTypesSupported :: [T.Text]
      , subjectTypesSupported :: [T.Text]
      , idTokenSigningAlgValuesSupported :: [T.Text]
      , scopesSupported :: Maybe [T.Text]
      , tokenEndpointAuthMethodsSupported :: Maybe [T.Text]
      , claimsSupported :: Maybe [T.Text]
      }
  deriving (Generic)

instance Aeson.FromJSON Metadata where
  parseJSON = Aeson.genericParseJSON metadataAesonOptions

instance Aeson.ToJSON Metadata where

  toJSON = Aeson.genericToJSON metadataAesonOptions

  toEncoding = Aeson.genericToEncoding metadataAesonOptions

metadataAesonOptions :: Aeson.Options
metadataAesonOptions =
  Aeson.defaultOptions {Aeson.fieldLabelModifier = Aeson.camelTo2 '_'}
