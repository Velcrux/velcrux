# ==============================================================================
# Velcrux Windows Installer (PowerShell)
# Usage:
#   irm https://raw.githubusercontent.com/Velcrux/velcrux/main/install.ps1 | iex
# ==============================================================================

[CmdletBinding()]
param (
    [string]$Version = "latest",
    [string]$InstallDir = "$env:USERPROFILE\.velcrux\bin"
)

$ErrorActionPreference = "Stop"

$Repo = "Velcrux/velcrux"
Write-Host "==> Velcrux Windows Installer" -ForegroundColor Cyan

# 1. Architecture Detection
$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($Arch -ne [System.Runtime.InteropServices.Architecture]::X64) {
    Write-Warning "Detected architecture: $Arch. Currently pre-built Windows binaries are compiled for x86_64."
}

$Target = "windows-amd64"

# 2. Version Resolution
if ($Version -eq "latest") {
    Write-Host "==> Resolving latest release version..." -ForegroundColor Gray
    try {
        $ReleaseUri = "https://github.com/$Repo/releases/latest"
        $Request = [System.Net.WebRequest]::Create($ReleaseUri)
        $Request.AllowAutoRedirect = $false
        $Response = $Request.GetResponse()
        $RedirectLocation = $Response.GetResponseHeader("Location")
        $Response.Close()
        $ResolvedTag = $RedirectLocation.Substring($RedirectLocation.LastIndexOf("/") + 1)
        if (-not $ResolvedTag -or $ResolvedTag -eq "releases") {
            $ResolvedTag = "v0.1.0"
        }
        $Version = $ResolvedTag
    } catch {
        $Version = "v0.1.0"
        Write-Warning "Could not query latest release; defaulting to $Version"
    }
}

Write-Host "==> Target Version: $Version" -ForegroundColor Green

# 3. Setup Temp Folder and Download
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("velcrux-install-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    $ArchiveName = "velcrux-$Version-$Target.zip"
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$ArchiveName"
    $ChecksumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS.txt"
    $ZipPath = Join-Path $TempDir $ArchiveName

    Write-Host "==> Downloading $ArchiveName..." -ForegroundColor Gray
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing

    # 4. Checksum Verification
    try {
        $ChecksumPath = Join-Path $TempDir "SHA256SUMS.txt"
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumPath -UseBasicParsing
        $HashExpected = Select-String -Path $ChecksumPath -Pattern $ArchiveName | ForEach-Object { ($_ -split "\s+")[0] }
        if ($HashExpected) {
            $HashActual = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
            if ($HashActual -ne $HashExpected.ToLower()) {
                throw "Checksum mismatch! Expected: $HashExpected, got: $HashActual"
            }
            Write-Host "==> Checksum verified: $($HashActual.Substring(0, 16))..." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Checksum verification skipped or failed to fetch SHA256SUMS.txt"
    }

    # 5. Extract Binaries
    Write-Host "==> Extracting binaries..." -ForegroundColor Gray
    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    $BinDir = Join-Path $ExtractDir "velcrux-$Version-$Target"
    if (-not (Test-Path $BinDir)) {
        $BinDir = $ExtractDir
    }

    # 6. Install
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Copy-Item (Join-Path $BinDir "velcrux.exe") -Destination $InstallDir -Force
    Copy-Item (Join-Path $BinDir "velcruxd.exe") -Destination $InstallDir -Force

    Write-Host "==> Binaries installed to $InstallDir" -ForegroundColor Green

    # 7. Add to PATH if not already present
    $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    if ($UserPath -notlike "*$InstallDir*") {
        $NewPath = "$UserPath;$InstallDir"
        [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "==> Added $InstallDir to user PATH." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Velcrux installed successfully!" -ForegroundColor Green
    Write-Host "  velcrux.exe   : Client CLI ($InstallDir\velcrux.exe)"
    Write-Host "  velcruxd.exe  : Server Daemon ($InstallDir\velcruxd.exe)"
    Write-Host ""
    Write-Host "Restart your terminal or run '$env:Path = [Environment]::GetEnvironmentVariable(""Path"", ""User"")' to start using velcrux."
}
finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
