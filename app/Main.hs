{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}
module Main where

import qualified Data.ByteString                           as S
import           Data.Serialize                            (put, runPut)
import           Network.Wai.Auth.Executable
import           Network.Wai.Handler.Warp                  (run)
import           Network.Wai.Middleware.Auth
import           Network.Wai.Middleware.Auth.OAuth2
import           Network.Wai.Middleware.Auth.OAuth2.Gitlab
import           Network.Wai.Middleware.Auth.OAuth2.Github
import           Network.Wai.Middleware.Auth.OAuth2.Google
import           Network.Wai.Middleware.RequestLogger      (logStdout)
import           Options.Applicative.Simple
import           Web.ClientSession

data BasicOptions
  = ConfigFile FilePath
  | KeyFile KeyOptions

showHelpText :: ParseError
showHelpText = ShowHelpText
#if MIN_VERSION_optparse_applicative(0,16,0)
                Nothing
#endif



basicSettingsParser :: String -> Parser BasicOptions
basicSettingsParser version =
  (ConfigFile <$>
   strOption
     (long "config-file" <> short 'c' <> metavar "CONFIG" <>
      help "File with configuration for the Auth application.") <*
   abortOption
     (InfoMsg version)
     (long "version" <> short 'v' <> help "Current version.") <*
   abortOption
     showHelpText
     (long "help" <> short 'h' <> help "Display this message.")) <|>
  (subparser
     (command
        "key"
        (info
           (KeyFile <$> keyOptionsParser)
           (progDesc
              ("Command for creating a secret key or converting one into base64 " ++
               "form, which can then be directly used inside a config file.") <>
            fullDesc))))


data KeyOptions = KeyOptions
  { keyInput  :: FilePath
  , keyOutput :: FilePath
  , keyBase64 :: Bool
  }

keyOptionsParser :: Parser KeyOptions
keyOptionsParser =
  KeyOptions <$>
  strOption
    (long "input-file" <> short 'i' <> metavar "INPUT" <> value "" <>
     help "Read key from a file, instead of generating a new one.") <*>
  strOption
    (long "output-file" <> short 'o' <> metavar "OUTPUT" <> value "" <>
     help "Write key into a file, instead of stdout. File will be overwritten.") <*>
  switch
    (long "base64" <> short 'b' <>
     help "Produce a key in a base64 encoded form.") <*
  abortOption
    showHelpText
    (long "help" <> short 'h' <> help "Display this message.")


main :: IO ()
main = do
  opts <-
    execParser
      (info
         (basicSettingsParser $(simpleVersion waiMiddlewareAuthVersion))
         (header "wai-auth - Authentication server" <>
          progDesc "Run a protected file server or reverse proxy." <>
          fullDesc))
  case opts of
    ConfigFile configFile -> do
      authConfig <- readAuthConfig configFile
      mkMain authConfig [gitlabParser, githubParser, googleParser, oAuth2Parser] $ \port app -> do
        putStrLn $ "Listening on port " ++ show port
        run port $ logStdout app
    KeyFile (KeyOptions {..}) -> do
      let key2str =
            if keyBase64
              then encodeKey
              else (runPut . put)
      key <-
        key2str <$>
        if null keyInput
          then snd <$> randomKey
          else do
            keyContent <- S.readFile keyInput
            case decodeKey keyContent of
              Left _ -> either error return (initKey keyContent)
              Right key -> pure key
      if null keyOutput
        then S.putStr key
        else S.writeFile keyOutput key
