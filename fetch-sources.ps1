[CmdletBinding()]
param(
    [switch] $Refresh
)

$ErrorActionPreference = 'Stop'
$lock = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'sources.lock.json') | ConvertFrom-Json
$vcpkgRoot = Join-Path $PSScriptRoot '.vcpkg'
$vcpkg = Join-Path $vcpkgRoot 'vcpkg.exe'
New-Item -ItemType Directory -Force -Path $vcpkgRoot | Out-Null

if (-not $Refresh -and (Test-Path -LiteralPath $vcpkg -PathType Leaf)) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $vcpkg).Hash
    if ($actual -ne $lock.vcpkg.sha256) {
        throw "Cached vcpkg '$vcpkg' has an incorrect SHA-256. Use -Refresh to replace it from upstream."
    }
    Write-Host "Verified cached vcpkg $($lock.vcpkg.version)."
} else {
    $temporary = "$vcpkg.$([Guid]::NewGuid().ToString('N')).download"
    try {
        Write-Host "Fetching vcpkg $($lock.vcpkg.version) from upstream."
        $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol =
                $securityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $lock.vcpkg.url -OutFile $temporary -UseBasicParsing
        } finally {
            [Net.ServicePointManager]::SecurityProtocol = $securityProtocol
        }

        if (-not (Test-Path -LiteralPath $temporary -PathType Leaf)) {
            throw "The vcpkg download did not create '$temporary'."
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash
        if ($actual -ne $lock.vcpkg.sha256) {
            throw "Downloaded vcpkg '$temporary' has an incorrect SHA-256."
        }
        Move-Item -LiteralPath $temporary -Destination $vcpkg -Force
        Write-Host "Verified vcpkg $($lock.vcpkg.version) from upstream."
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

$previousVcpkgRoot = $env:VCPKG_ROOT
$previousDisableMetrics = $env:VCPKG_DISABLE_METRICS
try {
    $env:VCPKG_ROOT = $vcpkgRoot
    $env:VCPKG_DISABLE_METRICS = '1'

    $versionOutput = @(& $vcpkg version)
    $version = if ($versionOutput.Count -gt 0) { [string] $versionOutput[0] } else { '' }
    if ($LASTEXITCODE -ne 0 -or -not $version.Contains($lock.vcpkg.version)) {
        throw "Expected vcpkg tool version $($lock.vcpkg.version); got '$version'."
    }

    $downloads = Join-Path $PSScriptRoot 'downloads'
    New-Item -ItemType Directory -Force -Path $downloads | Out-Null

    foreach ($source in $lock.sources) {
        $destination = Join-Path $downloads $source.archive

        if (-not $Refresh -and (Test-Path -LiteralPath $destination -PathType Leaf)) {
            $actual = (Get-FileHash -Algorithm SHA512 -LiteralPath $destination).Hash
            if ($actual -ne $source.sha512) {
                throw "Cached archive '$destination' has an incorrect SHA-512. Use -Refresh to replace it from upstream."
            }
            Write-Host "Verified cached $($source.name) $($source.version)."
            continue
        }

        $temporary = "$destination.$([Guid]::NewGuid().ToString('N')).download"
        try {
            Write-Host "Fetching $($source.name) $($source.version) from upstream."
            & $vcpkg x-download $temporary "--sha512=$($source.sha512)" "--url=$($source.url)" '--x-asset-sources=clear'
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temporary -PathType Leaf)) {
                throw "vcpkg could not fetch $($source.name) from upstream."
            }

            $actual = (Get-FileHash -Algorithm SHA512 -LiteralPath $temporary).Hash
            if ($actual -ne $source.sha512) {
                throw "Downloaded archive '$temporary' has an incorrect SHA-512."
            }
            Move-Item -LiteralPath $temporary -Destination $destination -Force
            Write-Host "Verified $($source.name) $($source.version) from upstream."
        } finally {
            if (Test-Path -LiteralPath $temporary -PathType Leaf) {
                Remove-Item -LiteralPath $temporary -Force
            }
        }
    }
} finally {
    $env:VCPKG_ROOT = $previousVcpkgRoot
    $env:VCPKG_DISABLE_METRICS = $previousDisableMetrics
}
