{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Main (main) where

import           Test.Tasty
import qualified Spec.Network.Wai.Auth.Internal

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "wai-middleware-auth"
  [ Spec.Network.Wai.Auth.Internal.tests
  ]
