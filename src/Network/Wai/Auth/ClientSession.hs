{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Auth.ClientSession
  ( loadCookieValue
  , saveCookieValue
  , deleteCookieValue
  , Key
  , getDefaultKey
  ) where

import           Blaze.ByteString.Builder   (toByteString)
import           Control.Monad              (guard)
import           Data.Binary                (Binary, decodeOrFail, encode)
import qualified Data.ByteString            as S
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Lazy       as L
import           Data.Int                   (Int64)
import           Data.Maybe                 (listToMaybe)
import           Data.Time.Clock            (UTCTime(UTCTime))
import           Data.Time.Calendar         (fromGregorian)
import           Foreign.C.Types            (CTime (..))
import           GHC.Generics               (Generic)
import           Network.HTTP.Types         (Header)
import           Network.Wai                (Request, requestHeaders)
import           System.PosixCompat.Time    (epochTime)
import           Web.ClientSession          (Key, decrypt, encryptIO,
                                             getDefaultKey)
import           Web.Cookie                 (def, parseCookies, renderSetCookie,
                                             sameSiteLax, setCookieExpires,
                                             setCookieHttpOnly, setCookieMaxAge,
                                             setCookieName, setCookiePath,
                                             setCookieSameSite, setCookieValue)

data Wrapper value = Wrapper
  { contained :: value
  , expires   :: !Int64 -- ^ should really be EpochTime or CTime, but there's no Binary instance
  } deriving (Generic)
instance Binary value => Binary (Wrapper value)

loadCookieValue
  :: Binary value
  => Key
  -> S.ByteString -- ^ cookie name
  -> Request
  -> IO (Maybe value)
loadCookieValue key name req = do
  CTime now <- epochTime
  return $
    listToMaybe $ do
      (k, v) <- requestHeaders req
      guard $ k == "cookie"
      (name', v') <- parseCookies v
      guard $ name == name'
      Right v'' <- return $ B64.decode v'
      Just v''' <- return $ decrypt key v''
      Right (_, _, Wrapper res expi) <-
        return $ decodeOrFail $ L.fromStrict v'''
      guard $ expi >= fromIntegral now
      return res

saveCookieValue
  :: Binary value
  => Key
  -> S.ByteString -- ^ cookie name
  -> Int -- ^ age in seconds
  -> value
  -> IO Header
saveCookieValue key name age value = do
  CTime now <- epochTime
  value' <-
    encryptIO key $
    L.toStrict $
    encode
      Wrapper {contained = value, expires = fromIntegral now + fromIntegral age}
  return
    ( "Set-Cookie"
    , toByteString $
      renderSetCookie
        def
        { setCookieName = name
        , setCookieValue = B64.encode value'
        , setCookiePath = Just "/"
        , setCookieHttpOnly = True
        , setCookieMaxAge = Just $ fromIntegral age
        , setCookieSameSite = Just sameSiteLax
        })

deleteCookieValue
  :: S.ByteString -- ^ cookie name
  -> Header
deleteCookieValue name =
  ( "Set-Cookie"
  , toByteString $
    renderSetCookie
      def
        { setCookieName = name
        , setCookieValue = ""
        , setCookiePath = Just "/"
        , setCookieHttpOnly = True
        , setCookieExpires = Just $ UTCTime (fromGregorian 1970 01 01) 0
        , setCookieSameSite = Just sameSiteLax
        })
