# Installs the Spora CLI on Windows.
#
#   irm https://spora.to/docs/install.ps1 | iex
#
# It finds the latest release on GitHub, downloads the archive for this
# system, checks it against the release's SHA256SUMS, unpacks spora.exe and
# wintun.dll (which `spora use` loads from next to the executable) into
# %LOCALAPPDATA%\Programs\Spora and adds that folder to your user PATH.
# Run it again to upgrade.
#
# Environment:
#   SPORA_VERSION       install this release tag (say v0.3.3), not the latest
#   SPORA_INSTALL_DIR   install into this folder instead
#   SPORA_RELEASES_URL  fetch from a mirror of
#                       https://github.com/Spora-VPN/spora/releases
#
# Linux and macOS have their own script: https://spora.to/docs/install.sh
# Guide: https://spora.to/docs/quickstart.html
#
# Keep this file ASCII: Windows PowerShell 5.1 reads a script fetched with
# irm as Latin-1. Nothing here may call `exit` either, which would close the
# window of whoever pasted the command.

& {
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell draws a progress bar that slows downloads many times over.
    $ProgressPreference = 'SilentlyContinue'

    if ($env:OS -ne 'Windows_NT') {
        throw 'This script installs Spora on Windows. On Linux and macOS: curl -fsSL https://spora.to/docs/install.sh | sh'
    }

    # A 32-bit PowerShell on 64-bit Windows names the real processor in the second variable.
    $cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($cpu) {
        'AMD64' { $arch = 'x86_64' }
        'ARM64' { $arch = 'aarch64' }
        default { throw "There is no release for $cpu processors. To build from source, see https://spora.to/docs/quickstart.html" }
    }

    # Windows PowerShell on older systems does not offer TLS 1.2 by itself.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $releases = 'https://github.com/Spora-VPN/spora/releases'
    if ($env:SPORA_RELEASES_URL) { $releases = $env:SPORA_RELEASES_URL.TrimEnd('/') }

    # The release's SHA256SUMS names every archive, so it tells both which
    # release is the latest and what its archive must hash to.
    $tag = $env:SPORA_VERSION
    if ($tag) {
        if ($tag -notmatch '^[A-Za-z0-9._-]+$') { throw "SPORA_VERSION is not a release tag: $tag" }
        $sumsUrl = "$releases/download/$tag/SHA256SUMS"
        $pattern = '^spora-(' + [regex]::Escape($tag) + ')-windows-' + $arch + '\.zip$'
    } else {
        $sumsUrl = "$releases/latest/download/SHA256SUMS"
        $pattern = '^spora-(v[A-Za-z0-9._-]*)-windows-' + $arch + '\.zip$'
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('spora-install-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $sums = Join-Path $tmp 'SHA256SUMS'
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -OutFile $sums
        } catch {
            throw "Could not download ${sumsUrl}: $($_.Exception.Message)"
        }

        $asset = $null
        $expected = $null
        foreach ($line in Get-Content -LiteralPath $sums) {
            $parts = $line.Trim() -split '\s+', 2
            if ($parts.Count -ne 2) { continue }
            $name = $parts[1].TrimStart('*')
            if ($name -cmatch $pattern) {
                $asset = $name
                $tag = $Matches[1]
                $expected = $parts[0]
                break
            }
        }
        if (-not $asset) { throw "The release has no build for Windows $arch. See $releases" }

        Write-Host "Downloading spora $tag for Windows $arch"
        $zip = Join-Path $tmp 'spora.zip'
        $assetUrl = "$releases/download/$tag/$asset"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $assetUrl -OutFile $zip
        } catch {
            throw "Could not download ${assetUrl}: $($_.Exception.Message)"
        }

        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
        if ($actual -ne $expected) {
            throw "$asset does not match its checksum (expected $expected, got $actual). Nothing was installed."
        }

        $unpacked = Join-Path $tmp 'unpacked'
        Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
        foreach ($file in 'spora.exe', 'wintun.dll') {
            if (-not (Test-Path -LiteralPath (Join-Path $unpacked $file))) { throw "$asset has no $file" }
        }

        $dir = $env:SPORA_INSTALL_DIR
        if (-not $dir) { $dir = Join-Path $env:LOCALAPPDATA 'Programs\Spora' }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $dir = (Resolve-Path -LiteralPath $dir).Path
        Write-Host "Installing to $dir"
        try {
            Copy-Item -Path (Join-Path $unpacked '*') -Destination $dir -Force
        } catch {
            throw "Could not write to ${dir}: $($_.Exception.Message) If spora is running, stop it and run this again."
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $exe = Join-Path $dir 'spora.exe'
    & $exe --version | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$exe was installed but does not run on this system" }
    Write-Host "Installed spora $tag"

    # The user PATH, read and written in the registry as it is stored:
    # [Environment]::SetEnvironmentVariable would write back the expanded
    # value and freeze entries such as %USERPROFILE%\bin.
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $stored = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $listed = $false
        foreach ($entry in $stored -split ';') {
            if ([Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\') -ieq $dir.TrimEnd('\')) { $listed = $true }
        }
        if (-not $listed) {
            $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
            if ($stored) {
                $kind = $key.GetValueKind('Path')
                $stored = $stored.TrimEnd(';') + ';'
            }
            $key.SetValue('Path', $stored + $dir, $kind)
            # Setting any variable through .NET announces the change, so
            # terminals opened from now on see the new PATH.
            $marker = 'SPORA_INSTALL_' + [guid]::NewGuid().ToString('N')
            [Environment]::SetEnvironmentVariable($marker, '1', 'User')
            [Environment]::SetEnvironmentVariable($marker, $null, 'User')
            Write-Host "Added $dir to your PATH. Terminals that are already open need a restart to see it."
        }
    } finally {
        $key.Close()
    }
    # This window, so that `spora` works right away.
    if (-not (($env:Path -split ';') -contains $dir)) { $env:Path = $env:Path.TrimEnd(';') + ';' + $dir }

    Write-Host ''
    Write-Host "Next: run 'spora share' on the machine that shares its connection,"
    Write-Host "then 'spora use <link>' in an elevated terminal on the one that connects."
    Write-Host 'Guide: https://spora.to/docs/quickstart.html'
}
