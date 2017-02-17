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
import           Data.Serialize         (Get, get, put, runGet, runPut)
import qualified Data.Text              as T
import           Web.ClientSession      (Key)


-- | Decode a `Key` that is in a base64 encoded serialized form
decodeKey :: Monad m => S.ByteString -> m Key
decodeKey secretKeyB64 =
  case B64.decode secretKeyB64 >>= runGet (get :: Get Key) of
    Left err        -> fail err
    Right secretKey -> return secretKey


-- | Serialize and base64 encode a secret `Key`
encodeKey :: Key -> S.ByteString
encodeKey = B64.encode . runPut . put


-- | Prepend all but the first capital letter with underscores and convert all
-- of them to lower case.
toLowerUnderscore :: String -> String
toLowerUnderscore [] = []
toLowerUnderscore (x:xs) = toLower x : (foldr' toLowerWithUnder [] xs)
  where
    toLowerWithUnder !y !acc
      | isLower y = y : acc
      | otherwise = '_' : toLower y : acc


-- TODO: implement validation
-- | Check email list against a whitelist and pick first one that matches or
-- Nothing otherwise.
getValidEmail :: [T.Text] -> [T.Text] -> Maybe T.Text
getValidEmail _whitelist emails = Just $ head emails
