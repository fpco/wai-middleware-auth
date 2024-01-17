{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Spec.Network.Wai.Auth.Internal (tests) where

import           Data.Binary                   (encode, decodeOrFail)
import qualified Data.ByteString.Lazy.Char8    as BSL8
import qualified Data.Text                     as T
import           Test.Tasty                    (TestTree, testGroup)
import           Test.Tasty.Hedgehog           (testProperty)
import           Hedgehog
import           Hedgehog.Gen                  as Gen
import           Hedgehog.Range                as Range
import           Network.Wai.Auth.Internal
import qualified Network.OAuth.OAuth2          as OA2

tests :: TestTree
tests = testGroup "Network.Wai.Auth.Internal"
  [ testProperty "oAuth2TokenBinaryDuality" oAuth2TokenBinaryDuality
  ]
  
oAuth2TokenBinaryDuality :: Property
oAuth2TokenBinaryDuality = property $ do
  token <- forAll oauth2TokenBinary
  let checkUnconsumed ("", _, roundTripToken) = roundTripToken
      checkUnconsumed (unconsumed, _, _) =
        error $ "Unexpected unconsumed in bytes: " <> BSL8.unpack unconsumed
  tripping token encode (fmap checkUnconsumed . decodeOrFail)
  tripping token (encodeToken . unOAuth2TokenBinary) (fmap OAuth2TokenBinary . decodeToken)

oauth2TokenBinary :: Gen OAuth2TokenBinary
oauth2TokenBinary = do
  accessToken <- OA2.AccessToken <$> anyText
  refreshToken <- Gen.maybe $ OA2.RefreshToken <$> anyText
  expiresIn <- Gen.maybe $ Gen.int (Range.linear 0 1000)
  tokenType <- Gen.maybe anyText
  idToken <- Gen.maybe $ OA2.IdToken <$> anyText
  pure $
    OAuth2TokenBinary $
    OA2.OAuth2Token accessToken refreshToken expiresIn tokenType idToken

anyText :: Gen T.Text
anyText = Gen.text (Range.linear 0 100) Gen.unicodeAll

-- The `OAuth2Token` type from the `hoauth2` library does not have a `Eq`
-- instance, and it's constituent parts don't have a `Generic` instance. Hence
-- this orphan instance here.
instance Eq OAuth2TokenBinary where
  (OAuth2TokenBinary t1) == (OAuth2TokenBinary t2) =
    and
      [ OA2.atoken (OA2.accessToken t1) == OA2.atoken (OA2.accessToken t2)
      , (OA2.rtoken <$> OA2.refreshToken t1) == (OA2.rtoken <$> OA2.refreshToken t2)
      , OA2.expiresIn t1 == OA2.expiresIn t2
      , OA2.tokenType t1 == OA2.tokenType t2
      , (OA2.idtoken <$> OA2.idToken t1) == (OA2.idtoken <$> OA2.idToken t2)
      ]
