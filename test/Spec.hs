module Spec (spec) where

import Data.Aeson qualified as Aeson
import Data.ByteString.Lazy qualified as BSL
import Data.Time (UTCTime (..), fromGregorian)
import Data.UUID qualified as UUID
import Data.Vector qualified as V
import Distribution.SPDX qualified as SPDX
import Distribution.Version (mkVersion)
import Security.Advisories.SBom.CycloneDX (CycloneDXInfo (..), serializeToCycloneDX)
import Security.Advisories.SBom.Types (ComponentDependency (..), ComponentType (..), SBomMeta (..), mkHackagePurl)
import Test.Hspec

spec :: Spec
spec = describe "CycloneDX" do
  it "produces valid CycloneDX 1.7 SBOM" do
    let uuid = UUID.fromWords 0x00000001 0x00000002 0x00000003 0x00000004
        time = UTCTime (fromGregorian 2024 1 1) 0
        cdxInfo =
          MkCycloneDXInfo
            { cyclonedx'sbomVersion = 1
            , cyclonedx'freshUUID = uuid
            , cyclonedx'currentTime = time
            }
        root =
          MKSBomMeta
            { sbom'componentName = "my-app"
            , sbom'componentVersion = mkVersion [1, 0, 0]
            , sbom'componentType = Application
            , sbom'componentAuthor = "Test Author"
            , sbom'componentDescription = "A test application"
            , sbom'componentLicense = SPDX.NONE
            , sbom'supplierName = Nothing
            , sbom'componentPurl = mkHackagePurl "my-app" (Just $ mkVersion [1, 0, 0])
            , sbom'componentDependencies =
                V.fromList
                  [ MkComponentDependency
                      { dep'type = Library
                      , dep'repo = Nothing
                      , dep'name = "some-lib"
                      , dep'version = mkVersion [2, 1, 0]
                      , dep'license = Just SPDX.NONE
                      , dep'description = "A test dependency"
                      , dep'purl = mkHackagePurl "some-lib" (Just $ mkVersion [2, 1, 0])
                      }
                  ]
            }
        components =
          V.fromList
            [ MKSBomMeta
                { sbom'componentName = "some-lib"
                , sbom'componentVersion = mkVersion [2, 1, 0]
                , sbom'componentType = Library
                , sbom'componentAuthor = "Lib Author"
                , sbom'componentDescription = "A test dependency"
                , sbom'componentLicense = SPDX.NONE
                , sbom'supplierName = Nothing
                , sbom'componentPurl = mkHackagePurl "some-lib" (Just $ mkVersion [2, 1, 0])
                , sbom'componentDependencies = V.fromList []
                }
            ]
        result = Aeson.encode $ serializeToCycloneDX cdxInfo root components
    expected <- BSL.readFile "test/assets/cyclonedx-golden.json"
    result `shouldBe` expected
