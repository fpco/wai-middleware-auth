{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main (main) where

import           Test.Tasty
import qualified Spec.Network.Wai.Auth.Internal
import qualified Spec.Network.Wai.Middleware.Auth.OAuth2
import qualified Spec.Network.Wai.Middleware.Auth.OAuth2.Gitlab
import qualified Spec.Network.Wai.Middleware.Auth.OIDC

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "wai-middleware-auth"
  [ Spec.Network.Wai.Auth.Internal.tests
  , Spec.Network.Wai.Middleware.Auth.OAuth2.tests
  , Spec.Network.Wai.Middleware.Auth.OAuth2.Gitlab.tests
  , Spec.Network.Wai.Middleware.Auth.OIDC.tests
  ]
