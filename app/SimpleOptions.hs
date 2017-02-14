{-# LANGUAGE TemplateHaskell #-}
module SimpleOptions
    ( module SimpleOptions
    , module Options.Applicative
    ) where

import           Control.Monad.Trans.Writer
import           Data.Monoid                ((<>))
import           Data.Version               (showVersion)
import           Development.GitRev         (gitDirty, gitHash)
import           Language.Haskell.TH.Syntax (lift)
import           Options.Applicative

simpleVersion version =
    [|concat
        [ "Version "
        , $(lift $ showVersion version)
        , ", Git revision "
        , $gitHash
        , if $gitDirty then " (dirty)" else ""
        ]
    |]

simpleOptions :: String                          -- ^ version string
              -> String                          -- ^ header
              -> String                          -- ^ program description
              -> Parser a                        -- ^ global settings
              -> Writer (Mod CommandFields b) () -- ^ commands (use 'addCommand')
              -> IO (a, b)
simpleOptions versionString h pd globalParser commandParser =
    execParser $ info (helpOption <*> versionOption <*> config) desc
  where
    desc = fullDesc <> header h <> progDesc pd
    helpOption =
        abortOption ShowHelpText $
        long "help" <>
        help "Show this help text"
    versionOption =
        infoOption
            versionString
            (long "version" <>
             help "Show version")
    config = (,) <$> globalParser <*> subparser (execWriter commandParser)

addCommand :: String   -- ^ command string
           -> String   -- ^ title of command
           -> (a -> b) -- ^ constructor to wrap up command in common data type
           -> Parser a -- ^ command parser
           -> Writer (Mod CommandFields b) ()
addCommand cmd title constr inner = tell $ command
    cmd
    (info (constr <$> inner) (progDesc title))
