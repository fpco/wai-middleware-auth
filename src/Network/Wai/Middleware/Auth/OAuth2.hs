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
import           Data.Aeson.TH                        (defaultOptions,
                                                       deriveJSON,
                                                       fieldLabelModifier)
import           Data.Default                         (Default(..))
import           Data.Functor                         ((<&>))
import           Data.Int                             (Int64)
import           Data.Proxy                           (Proxy (..))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8)
import           Foreign.C.Types                      (CTime (..))
import           Network.HTTP.Client.TLS              (getGlobalManager)
import qualified Network.OAuth.OAuth2                 as OA2
import           Network.Wai                          (Request)
import           Network.Wai.Auth.Internal            (decodeToken, encodeToken,
                                                       oauth2Login,
                                                       refreshTokens)
import           Network.Wai.Auth.Tools               (toLowerUnderscore)
import qualified Network.Wai.Middleware.Auth          as MA
import           Network.Wai.Middleware.Auth.Provider
import           System.PosixCompat.Time              (epochTime)
import qualified URI.ByteString                       as U

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

getClientId :: T.Text -> T.Text
getClientId = id

getClientSecret :: T.Text -> T.Text
getClientSecret = id

$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 3} ''OAuth2)

-- | Aeson parser for `OAuth2` provider.
--
-- @since 0.1.0
oAuth2Parser :: ProviderParser
oAuth2Parser = mkProviderParser (Proxy :: Proxy OAuth2)


instance AuthProvider OAuth2 where
  getProviderName _ = "oauth2"
  getProviderInfo = oa2ProviderInfo
  handleLogin oa2@OAuth2 {..} req suffix renderUrl onSuccess onFailure = do
    authEndpointURI <- parseAbsoluteURI oa2AuthorizeEndpoint
    accessTokenEndpointURI <- parseAbsoluteURI oa2AccessTokenEndpoint
    callbackURI <- parseAbsoluteURI $ renderUrl (ProviderUrl ["complete"]) []
    let oauth2 =
          def
          { OA2.oauth2ClientId = getClientId oa2ClientId
          , OA2.oauth2ClientSecret = getClientSecret oa2ClientSecret
          , OA2.oauth2AuthorizeEndpoint = authEndpointURI
          , OA2.oauth2TokenEndpoint = accessTokenEndpointURI
          , OA2.oauth2RedirectUri = callbackURI
          }
    man <- getGlobalManager
    oauth2Login
      oauth2
      man
      oa2Scope
      (getProviderName oa2)
      req
      suffix
      onSuccess
      onFailure
  refreshLoginState OAuth2 {..} req user = do
    authEndpointURI <- parseAbsoluteURI oa2AuthorizeEndpoint
    accessTokenEndpointURI <- parseAbsoluteURI oa2AccessTokenEndpoint
    let loginState = authLoginState user
    case decodeToken loginState of
      Left _ -> pure Nothing
      Right tokens -> do
        CTime now <- epochTime
        if tokenExpired user now tokens then do
          let oauth2 =
                def
                { OA2.oauth2ClientId = getClientId oa2ClientId
                , OA2.oauth2ClientSecret = getClientSecret oa2ClientSecret
                , OA2.oauth2AuthorizeEndpoint = authEndpointURI
                , OA2.oauth2TokenEndpoint = accessTokenEndpointURI
                }
          man <- getGlobalManager
          rRes <- refreshTokens tokens man oauth2
          pure (rRes <&> \newTokens -> (req, user {
                 authLoginState = encodeToken newTokens,
                 authLoginTime = fromIntegral now
               }))
        else
          pure (Just (req, user))

tokenExpired :: AuthUser -> Int64 -> OA2.OAuth2Token -> Bool
tokenExpired user now tokens =
  case OA2.expiresIn tokens of
    Nothing -> False
    Just expiresIn -> authLoginTime user + (fromIntegral expiresIn) < now

-- | Get the @AccessToken@ for the current user.
--
-- If called on a @Request@ behind the middleware, should always return a
-- @Just@ value.
--
-- @since 0.2.0.0
getAccessToken :: Request -> Maybe OA2.OAuth2Token
getAccessToken req = do
  user <- MA.getAuthUser req
  either (const Nothing) Just $ decodeToken (authLoginState user)
