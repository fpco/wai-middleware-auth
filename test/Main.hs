{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import qualified Data.Text                     as T
import           Hedgehog
import           Hedgehog.Gen                  as Gen
import           Hedgehog.Range                as Range
import           Network.Wai.Auth.Internal     (encodeToken, decodeToken)
import qualified Network.OAuth.OAuth2.Internal as OA2

main :: IO Bool
main =
  checkParallel $ Group "Main" [
    ("oAuth2TokenBinaryDuality", oAuth2TokenBinaryDuality)
  ]

oAuth2TokenBinaryDuality :: Property
oAuth2TokenBinaryDuality = property $ do
  token <- forAll oauth2TokenBinary
  tripping token encodeToken (Just . decodeToken)

oauth2TokenBinary :: Gen OA2.OAuth2Token
oauth2TokenBinary = do
  accessToken <- OA2.AccessToken <$> anyText
  refreshToken <- Gen.maybe $ OA2.RefreshToken <$> anyText
  expiresIn <- Gen.maybe $ Gen.int (Range.linear 0 1000)
  tokenType <- Gen.maybe $ anyText
  idToken <- Gen.maybe $ OA2.IdToken <$> anyText
  pure $ OA2.OAuth2Token accessToken refreshToken expiresIn tokenType idToken

anyText :: Gen T.Text
anyText = Gen.text (Range.linear 0 100) Gen.unicodeAll

-- The `OAuth2Token` type from the `hoauth2` library does not have a `Eq`
-- instance, and it's constituent parts don't have a `Generic` instance. Hence
-- this orphan instance here.
instance Eq OA2.OAuth2Token where
  t1 == t2 =
    all id
      [ OA2.atoken (OA2.accessToken t1) == OA2.atoken (OA2.accessToken t2)
      , (OA2.rtoken <$> OA2.refreshToken t1) == (OA2.rtoken <$> OA2.refreshToken t2)
      , OA2.expiresIn t1 == OA2.expiresIn t2
      , OA2.tokenType t1 == OA2.tokenType t2
      , (OA2.idtoken <$> OA2.idToken t1) == (OA2.idtoken <$> OA2.idToken t2)
      ]
