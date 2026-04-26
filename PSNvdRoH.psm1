$assembly = Join-Path -Path $PSScriptRoot -ChildPath "NvdClient/bin/Debug/net8.0/NvdClient.dll"
Add-Type -Path $assembly

function Get-NvdCve {
    param([string]$Keyword, [string]$apiKey)

    $client = [NvdClient.NvdApiClient]::new($apiKey)
    $json = $client.GetCvesAsync("?keywordSearch=$Keyword").Result
    $json | ConvertFrom-Json
}
