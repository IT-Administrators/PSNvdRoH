Import-Module "$PSScriptRoot/PSNvdRoH.psm1" -Force

InModuleScope PSNvdRoH {

    Describe "Get-NvdCve PowerShell Function" {

        BeforeAll {
            # Mock the internal wrapper so NO real API calls occur
            Mock -CommandName Invoke-NvdApi -MockWith {
                return '{"vulnerabilities":[]}'
            }
        }

        # PARAMETER SET TESTS
        Context "Parameter Set Enforcement" {

            It "Allows CvssV2Severity alone" {
                { Get-NvdCve -CvssV2Severity HIGH } | Should -Not -Throw
            }

            It "Allows CvssV3Severity alone" {
                { Get-NvdCve -CvssV3Severity HIGH } | Should -Not -Throw
            }

            It "Prevents mixing CvssV2Severity and CvssV3Severity" {
                { Get-NvdCve -CvssV2Severity HIGH -CvssV3Severity LOW } |
                    Should -Throw
            }

            It "Prevents mixing CvssV3Metrics and CvssV4Metrics" {
                { Get-NvdCve -CvssV3Metrics "5.0" -CvssV4Metrics "6.0" } |
                    Should -Throw
            }

            It "Allows mixing CVSS parameters with global parameters like CveID" {
                { Get-NvdCve -CvssV3Severity HIGH -CveID "CVE-2024-1234" } |
                    Should -Not -Throw
            }
        }

        # REQUIRED-TOGETHER PARAMETER TESTS     
        Context "Required Parameter Pairs" {

            It "Requires PubStartDate and PubEndDate together" {
                { Get-NvdCve -PubStartDate "2024-01-01" } |
                    Should -Throw
            }

            It "Allows PubStartDate and PubEndDate together" {
                { Get-NvdCve -PubStartDate "2024-01-01" -PubEndDate "2024-01-31" } |
                    Should -Not -Throw
            }

            It "Requires LastModStartDate and LastModEndDate together" {
                { Get-NvdCve -LastModStartDate "2024-01-01" } |
                    Should -Throw
            }

            It "Requires KevStartDate and KevEndDate together" {
                { Get-NvdCve -KevStartDate "2024-01-01" } |
                    Should -Throw
            }

            It "Allows KevStartDate and KevEndDate together" {
                { Get-NvdCve -KevStartDate "2024-01-01" -KevEndDate "2024-01-31" } |
                    Should -Not -Throw
            }
        }

        # LOGICAL DEPENDENCY TESTS
        Context "Logical Parameter Dependencies" {

            It "KeywordExactMatch requires KeywordSearch" {
                { Get-NvdCve -KeywordExactMatch:$true } |
                    Should -Throw
            }

            It "IsVulnerable requires CpeName" {
                { Get-NvdCve -IsVulnerable:$true } |
                    Should -Throw
            }

            It "Allows IsVulnerable with CpeName" {
                { Get-NvdCve -IsVulnerable:$true -CpeName "cpe:2.3:a:microsoft:windows" } |
                    Should -Not -Throw
            }
        }

        # PARAMETER PASS-THROUGH TESTS
        Context "Parameter Passing to C# Object" {

            It "Passes CveID into the C# parameter object" {
                Mock -CommandName Invoke-NvdApi -MockWith {
                    param($client, $params)
                    return ($params | ConvertTo-Json)
                }

                $result = Get-NvdCve -CveID "CVE-2024-1234"
                $result.CveID | Should -Be "CVE-2024-1234"
            }

            It "Passes KeywordSearch array correctly" {
                Mock -CommandName Invoke-NvdApi -MockWith {
                    param($client, $params)
                    return ($params | ConvertTo-Json)
                }

                $result = Get-NvdCve -KeywordSearch "openssl","kernel"
                $result.KeywordSearch.Count | Should -Be 2
            }

        }

        # SUCCESSFUL EXECUTION TESTS
        Context "Execution Flow" {

            It "Returns parsed JSON" {
                Mock -CommandName Invoke-NvdApi -MockWith {
                    return '{"vulnerabilities":[{"cve":{"id":"CVE-2024-1234"}}]}'
                }

                $result = Get-NvdCve -CveID "CVE-2024-1234" 
                $result.vulnerabilities[0].cve.id | Should -Be "CVE-2024-1234"
            }

            It "Handles empty API response gracefully" {
                Mock -CommandName Invoke-NvdApi -MockWith { "" }

                $result = Get-NvdCve -CveID "CVE-2024-1234" 
                $result | Should -BeNullOrEmpty
            }
        }

        # ERROR HANDLING TESTS
        Context "Error Handling" {

            It "Handles HttpRequestException" {
                Mock -CommandName Invoke-NvdApi -MockWith {
                    throw [System.Net.Http.HttpRequestException]::new("Network error")
                }

                { Get-NvdCve -CveID "CVE-2024-1234" } |
                    Should -Throw
            }

            It "Handles InvalidOperationException from C# validation" {
                Mock -CommandName Invoke-NvdApi -MockWith {
                    throw [InvalidOperationException]::new("Invalid parameter combination")
                }

                { Get-NvdCve -CvssV2Metrics "5.0" -CvssV3Metrics "6.0" } |
                    Should -Throw
            }
        }
    }
}
