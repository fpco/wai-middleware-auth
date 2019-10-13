{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE TupleSections     #-}
module Network.Wai.Middleware.Auth.OAuth2
  ( OAuth2(..)
  , oAuth2Parser
  , URIParseException(..)
  , parseAbsoluteURI
  , getAccessToken
  ) where

import           Control.Monad.Catch
import qualified Data.Aeson
import           Data.Aeson.TH                        (defaultOptions,
                                                       deriveJSON,
                                                       fieldLabelModifier)
import qualified Data.ByteString                      as S
import qualified Data.ByteString.Char8                as S8 (pack)
import qualified Data.ByteString.Lazy                 as SL
import           Data.Monoid                          ((<>))
import           Data.Proxy                           (Proxy (..))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8,
                                                       decodeUtf8With)
import           Data.Text.Encoding.Error             (lenientDecode)
import           Network.HTTP.Client.TLS              (getGlobalManager)
import           Network.HTTP.Types                   (status303, status403,
                                                       status404, status501)
import qualified Network.OAuth.OAuth2                 as OA2
import           Network.Wai                          (Request, queryString,
                                                       responseLBS)
import           Network.Wai.Auth.Tools               (toLowerUnderscore)
import qualified Network.Wai.Middleware.Auth          as MA
import           Network.Wai.Middleware.Auth.Provider
import qualified URI.ByteString                       as U
import           URI.ByteString                       (URI)

-- | General OAuth2 authentication `Provider`.
data OAuth2 = OAuth2
  { oa2ClientId            :: T.Text
  , oa2ClientSecret        :: T.Text
  , oa2AuthorizeEndpoint   :: T.Text
  , oa2AccessTokenEndpoint :: T.Text
  , oa2Scope               :: Maybe [T.Text]
  , oa2ProviderInfo        :: ProviderInfo
  }

-- | Used for validating proper url structure. Can be thrown by
-- `parseAbsoluteURI` and consequently by `handleLogin` for `OAuth2` `Provider`
-- instance.
--
-- @since 0.1.2.0
data URIParseException = URIParseException U.URIParseError deriving Show

instance Exception URIParseException

-- | Parse absolute URI and throw `URIParseException` in case it is malformed
--
-- @since 0.1.2.0
parseAbsoluteURI :: MonadThrow m => T.Text -> m U.URI
parseAbsoluteURI urlTxt = do
  case U.parseURI U.strictURIParserOptions (encodeUtf8 urlTxt) of
    Left err  -> throwM $ URIParseException err
    Right url -> return url

parseAbsoluteURI' :: MonadThrow m => T.Text -> m U.URI
parseAbsoluteURI' = parseAbsoluteURI

getExchangeToken :: S.ByteString -> OA2.ExchangeToken
getExchangeToken = OA2.ExchangeToken . decodeUtf8With lenientDecode

appendQueryParams :: URI -> [(S.ByteString, S.ByteString)] -> URI
appendQueryParams uri params =
  OA2.appendQueryParams params uri

getClientId :: T.Text -> T.Text
getClientId = id

getClientSecret :: T.Text -> T.Text
getClientSecret = id

getRedirectURI :: U.URIRef a -> S.ByteString
getRedirectURI = U.serializeURIRef'

encodeAccessToken :: OA2.OAuth2Token -> S.ByteString
encodeAccessToken = SL.toStrict . Data.Aeson.encode


-- | Aeson parser for `OAuth2` provider.
--
-- @since 0.1.0
oAuth2Parser :: ProviderParser
oAuth2Parser = mkProviderParser (Proxy :: Proxy OAuth2)


instance AuthProvider OAuth2 where
  getProviderName _ = "oauth2"
  getProviderInfo = oa2ProviderInfo
  handleLogin oa2@OAuth2 {..} req suffix renderUrl onSuccess onFailure = do
    authEndpointURI <- parseAbsoluteURI' oa2AuthorizeEndpoint
    accessTokenEndpointURI <- parseAbsoluteURI' oa2AccessTokenEndpoint
    callbackURI <- parseAbsoluteURI' $ renderUrl (ProviderUrl ["complete"]) []
    let oauth2 =
          OA2.OAuth2
          { oauthClientId = getClientId oa2ClientId
          , oauthClientSecret = getClientSecret oa2ClientSecret
          , oauthOAuthorizeEndpoint = authEndpointURI
          , oauthAccessTokenEndpoint = accessTokenEndpointURI
          , oauthCallback = Just callbackURI
          }
    case suffix of
      [] -> do
        let scope = (encodeUtf8 . T.intercalate ",") <$> oa2Scope
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
               man <- getGlobalManager
               eRes <- OA2.fetchAccessToken man oauth2 $ getExchangeToken code
               case eRes of
                 Left err    -> onFailure status501 $ S8.pack $ show err
                 Right token -> onSuccess $ encodeAccessToken token
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
                   encodeUtf8 (getProviderName oa2)
                 Nothing ->
                   onFailure
                     status404
                     "Page not found. Please continue with login."
      _ -> onFailure status404 "Page not found. Please continue with login."


$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 3} ''OAuth2)

-- | Get the @AccessToken@ for the current user.
--
-- If called on a @Request@ behind the middleware, should always return a
-- @Just@ value.
--
-- @since 0.2.0.0
getAccessToken :: Request -> Maybe OA2.OAuth2Token
getAccessToken req = do
  user <- MA.getAuthUser req
  Data.Aeson.decodeStrict (authUserIdentity user)
