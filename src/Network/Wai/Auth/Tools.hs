{-# LANGUAGE BangPatterns #-}
module Network.Wai.Auth.Tools
  ( encodeKey
  , decodeKey
  , toLowerUnderscore
  , getValidEmail
  ) where

import qualified Data.ByteString        as S
import           Data.ByteString.Base64 as B64
import           Data.Char              (isLower, toLower)
import           Data.Foldable          (foldr')
import           Data.Maybe             (listToMaybe)
import           Data.Serialize         (Get, get, put, runGet, runPut)
import           Text.Regex.Posix       ((=~))
import           Web.ClientSession      (Key)


-- | Decode a `Key` that is in a base64 encoded serialized form
decodeKey :: S.ByteString -> Either String Key
decodeKey secretKeyB64 = B64.decode secretKeyB64 >>= runGet (get :: Get Key)


-- | Serialize and base64 encode a secret `Key`
encodeKey :: Key -> S.ByteString
encodeKey = B64.encode . runPut . put


-- | Prepend all but the first capital letter with underscores and convert all
-- of them to lower case.
toLowerUnderscore :: String -> String
toLowerUnderscore [] = []
toLowerUnderscore (x:xs) = toLower x : foldr' toLowerWithUnder [] xs
  where
    toLowerWithUnder !y !acc
      | isLower y = y : acc
      | otherwise = '_' : toLower y : acc


-- | Check email list against an allowlist and pick first one that matches or
-- Nothing otherwise.
getValidEmail :: [S.ByteString] -> [S.ByteString] -> Maybe S.ByteString
getValidEmail allowlist emails =
  listToMaybe $ filter (not . S.null) [e =~ w | e <- emails, w <- allowlist]
