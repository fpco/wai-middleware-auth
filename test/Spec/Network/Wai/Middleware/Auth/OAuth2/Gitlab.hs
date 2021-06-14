{-# LANGUAGE OverloadedLists #-}
{-# LANGUAGE OverloadedStrings #-}

module Spec.Network.Wai.Middleware.Auth.OAuth2.Gitlab (tests) where

import           Data.Aeson ((.=))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import           Data.Text (Text)
import qualified Network.Wai.Middleware.Auth.OAuth2.Gitlab as Gitlab
import           Test.Tasty (TestTree, testGroup)
import           Test.Tasty.HUnit (assertEqual, testCase)

tests :: TestTree
tests =
  testGroup
    "Network.Wai.Middleware.Auth.OAuth2.Gitlab"
    [ testCase "when the configuration uses legacy option" $
        assertEqual "test" (parse legacyConfig) (parse newConfig)
    ]
  where
    parse v = Gitlab.gitlabEmailAllowlist <$> Aeson.parse Aeson.parseJSON v
    config =
      [ "app_name" .= ("test" :: Text),
        "client_id" .= ("test" :: Text),
        "client_secret" .= ("test" :: Text)
      ]
    newConfig =
      Aeson.object
        (config <> ["email_allow_list" .= Aeson.Array ["testMail"]])
    legacyConfig =
      Aeson.object
        (config <> ["email_white_list" .= Aeson.Array ["testMail"]])
