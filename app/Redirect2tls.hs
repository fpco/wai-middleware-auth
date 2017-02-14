{-# LANGUAGE OverloadedStrings #-}
-- | Redirect2tls as a middleware
module Redirect2tls (redirect2tls) where

import qualified Data.ByteString     as S
import           Network.HTTP.Types  (status307)
import           Network.Wai
import           Network.Wai.Request

redirect2tls :: Middleware
redirect2tls app req send
    | appearsSecure req = app req send
    | otherwise =
        let dest =
                S.concat
                    [ guessApproot req {isSecure = True}
                    , rawPathInfo req
                    , rawQueryString req
                    ]
        in send $ responseLBS status307 [("Location", dest)] "Redirecting"
