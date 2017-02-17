{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
{-# LANGUAGE TupleSections     #-}
module Network.Wai.Middleware.Auth.OAuth2
  ( OAuth2(..)
  , oAuth2Parser
  ) where

import           Data.Aeson.TH                        (defaultOptions,
                                                       deriveJSON,
                                                       fieldLabelModifier)
import qualified Data.ByteString.Lazy                 as SL
import           Data.Monoid                          ((<>))
import qualified Data.Text                            as T
import           Data.Text.Encoding                   (encodeUtf8)
import           Network.HTTP.Types                   (status303, status403,
                                                       status404, status501)
import qualified Network.OAuth.OAuth2                 as OA2
import           Network.Wai                          (queryString, responseLBS)
import           Network.Wai.Auth.Tools               (toLowerUnderscore)
import           Network.Wai.Middleware.Auth.Provider


data OAuth2 = OAuth2
  { oa2ClientId            :: T.Text
  , oa2ClientSecret        :: T.Text
  , oa2AuthorizeEndpoint   :: T.Text
  , oa2AccessTokenEndpoint :: T.Text
  , oa2Scope               :: Maybe [T.Text]
  , oa2ProviderInfo        :: ProviderInfo
  --, oa2MaxLoginWait :: Maybe Int
  }


oAuth2Parser :: ProviderParser
oAuth2Parser = mkProviderParser (undefined :: OAuth2)


instance AuthProvider OAuth2 where
  getProviderName _ = "oauth2"

  getProviderInfo = oa2ProviderInfo

  handleLogin oa2@OAuth2 {..} man req renderUrl suffix onSuccess onFailure = do
    let oauth2 =
          OA2.OAuth2
          { oauthClientId = encodeUtf8 oa2ClientId
          , oauthClientSecret = encodeUtf8 oa2ClientSecret
          , oauthOAuthorizeEndpoint = encodeUtf8 oa2AuthorizeEndpoint
          , oauthAccessTokenEndpoint = encodeUtf8 oa2AccessTokenEndpoint
          , oauthCallback =
              Just $ encodeUtf8 $ renderUrl (ProviderUrl ["complete"]) []
          }
    case suffix of
      [] -> do
        let scope = (encodeUtf8 . T.intercalate ",") <$> oa2Scope
        let redirectUrl =
              OA2.appendQueryParam (OA2.authorizationUrl oauth2) $
              maybe [] ((: []) . ("scope", )) scope
        return $
          responseLBS
            status303
            [("Location", redirectUrl)]
            "Redirect to OAuth2 Authentication server"
      ["complete"] -> do
        let params = queryString req
        case lookup "code" params of
          Just (Just code) -> do
            eRes <- OA2.fetchAccessToken man oauth2 code
            case eRes of
              Left err -> onFailure status501 $ SL.toStrict err
              Right token -> onSuccess $ OA2.accessToken token
          _ ->
            case lookup "error" params of
              (Just (Just "access_denied")) ->
                onFailure status403 "User rejected access to the application."
              (Just (Just error_code)) ->
                onFailure status501 $ "Received an error: " <> error_code
              _ ->
                onFailure status501 $
                "Unknown error connecting to " <>
                encodeUtf8 (getProviderName oa2)
      _ -> onFailure status404 "Unknown Url"


$(deriveJSON defaultOptions { fieldLabelModifier = toLowerUnderscore . drop 3} ''OAuth2)
