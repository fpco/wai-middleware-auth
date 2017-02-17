{-# LANGUAGE OverloadedStrings #-}
module Network.Wai.Auth.AppRoot
  ( smartAppRoot
  ) where

import           Data.ByteString          (ByteString)
import           Data.CaseInsensitive     (CI, mk)
import qualified Data.Map                 as Map
import           Data.Monoid              ((<>))
import qualified Data.Text                as T
import           Data.Text.Encoding       (decodeUtf8With)
import           Data.Text.Encoding.Error (lenientDecode)
import           Network.HTTP.Types       (Header)
import           Network.Wai              (Request, isSecure, requestHeaderHost,
                                           requestHeaders)


-- | Determine approot by:
--
-- * Respect the Host header and isSecure property, together with the following de facto standards: x-forwarded-protocol, x-forwarded-ssl, x-url-scheme, x-forwarded-proto, front-end-https. (Note: this list may be updated at will in the future without doc updates.)
--
-- Normally trusting headers in this way is insecure, however in the case of approot, the worst that can happen is that the client will get an incorrect URL. Note that this does not work for some situations, e.g.:
--
-- * Reverse proxies not setting one of the above mentioned headers
--
-- * Applications hosted somewhere besides the root of the domain name
--
-- * Reverse proxies that modify the host header
--
-- Since 0.1.0
smartAppRoot :: Request -> IO T.Text
smartAppRoot req =
  return $
  let secure = isSecure req || any isSecureHeader (requestHeaders req)
      host =
        maybe "localhost" (decodeUtf8With lenientDecode) (requestHeaderHost req)
  in (if secure
        then "https://"
        else "http://") <>
     host

-- |
--
-- See: http://stackoverflow.com/a/16042648/369198
httpsHeaders :: Map.Map (CI ByteString) (CI ByteString)
httpsHeaders =
  Map.fromList
    [ ("X-Forwarded-Protocol", "https")
    , ("X-Forwarded-Ssl", "on")
    , ("X-Url-Scheme", "https")
    , ("X-Forwarded-Proto", "https")
    , ("Front-End-Https", "on")
    ]

isSecureHeader :: Header -> Bool
isSecureHeader (key, value) =
  case Map.lookup key httpsHeaders of
    Nothing     -> False
    Just value' -> valueCI == value'
  where
    valueCI = mk value
