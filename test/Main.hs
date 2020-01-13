{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main (main) where

import           Test.Tasty
import qualified Spec.Network.Wai.Auth.Internal
import qualified Spec.Network.Wai.Middleware.Auth.OAuth2

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "wai-middleware-auth"
  [ Spec.Network.Wai.Auth.Internal.tests
  , Spec.Network.Wai.Middleware.Auth.OAuth2.tests
  ]
