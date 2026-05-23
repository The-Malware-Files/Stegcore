<#
.SYNOPSIS
    Stegcore installer for Windows.

.DESCRIPTION
    Downloads and installs the Stegcore CLI, GUI, or both from GitHub Releases.
    Verifies SHA-256 checksums before installing anything.

.PARAMETER Component
    What to install: cli, gui, or both. Prompted interactively if omitted.

.PARAMETER Version
    Specific version to install (e.g. v1.0.0). Defaults to latest.

.PARAMETER Upgrade
    Replace an existing installation without prompting.

.PARAMETER Uninstall
    Remove Stegcore from this machine.

.PARAMETER DryRun
    Show what would be done without making any changes.

.PARAMETER Yes
    Skip all confirmation prompts (assume yes).

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Component both
    .\install.ps1 -Version v4.0.0-beta.1 -DryRun
    .\install.ps1 -Uninstall
#>

[CmdletBinding()]
param (
    [ValidateSet('cli', 'gui', 'both', '')]
    [string]$Component = '',

    [string]$Version = '',

    [switch]$Upgrade,
    [switch]$Uninstall,
    [switch]$DryRun,
    [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Force TLS 1.2+ for secure downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Detect if running non-interactively (piped via irm | iex)
$IsInteractive = [Environment]::UserInteractive -and -not ([Console]::IsInputRedirected)

# ── Constants ──────────────────────────────────────────────────────────────────

$Repo     = 'The-Malware-Files/Stegcore'
$ApiBase  = "https://api.github.com/repos/$Repo"
$DlBase   = "https://github.com/$Repo/releases/download"

# CLI installs to a user-writable directory — no elevation needed
if ($env:LOCALAPPDATA) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Stegcore\bin'
} elseif ($env:HOME) {
    # Non-Windows (Linux/macOS PowerShell) — use ~/.stegcore/bin
    $InstallDir = Join-Path $env:HOME '.stegcore/bin'
} else {
    Abort 'Cannot determine install directory. Set LOCALAPPDATA or HOME.'
}

# Arch — Stegcore ships x64 only on Windows for now
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Stegcore requires a 64-bit operating system.'
}
$Arch = 'x64'

# ── Output helpers ─────────────────────────────────────────────────────────────

function Write-Info    ([string]$Msg) { Write-Host "  -> $Msg"       -ForegroundColor Cyan    }
function Write-Ok      ([string]$Msg) { Write-Host "  v  $Msg"       -ForegroundColor Green   }
function Write-Warn    ([string]$Msg) { Write-Host "  !  $Msg"       -ForegroundColor Yellow  }
function Write-Err     ([string]$Msg) { Write-Host "  x  $Msg"       -ForegroundColor Red     }
function Write-Dry     ([string]$Msg) { Write-Host "  [dry-run] $Msg" -ForegroundColor Magenta }
function Abort         ([string]$Msg) { Write-Err $Msg; exit 1        }

# ── Temp dir + guaranteed cleanup ─────────────────────────────────────────────

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "stegcore-install-$([System.IO.Path]::GetRandomFileName())"
[System.IO.Directory]::CreateDirectory($TmpDir) | Out-Null

function Remove-TmpDir {
    if (Test-Path $TmpDir) {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
}

# Wrap everything so cleanup always runs
try {

# ── Version resolution ─────────────────────────────────────────────────────────

function Resolve-Version {
    if ($Version -ne '') {
        if ($Version -notmatch '^v') { $script:Version = "v$Version" }
        Write-Info "Using version: $script:Version"
        return
    }

    Write-Info 'Fetching latest release...'
    try {
        $headers  = @{ 'User-Agent' = 'stegcore-installer/1.0' }
        $response = Invoke-RestMethod -Uri "$ApiBase/releases/latest" -Headers $headers
        $script:Version = $response.tag_name
    } catch {
        Abort "Failed to reach GitHub API: $_`nCheck your internet connection or specify a version with -Version."
    }

    if (-not $script:Version) {
        Abort 'Could not determine the latest version. Use -Version to specify one.'
    }
    Write-Info "Latest version: $script:Version"
}

# ── Checksums ──────────────────────────────────────────────────────────────────

$ChecksumsPath = ''

function Get-Checksums {
    $url  = "$DlBase/$script:Version/stegcore-$script:Version-checksums.sha256"
    $dest = Join-Path $TmpDir 'checksums.sha256'

    Write-Info 'Downloading checksums...'
    if ($DryRun) { Write-Dry "GET $url"; $script:ChecksumsPath = $dest; return }

    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    } catch {
        Write-Warn "Checksum file not available — cannot verify download integrity."
        Write-Warn "This could mean the release is still being published."
        Write-Warn "Proceeding without verification."
        return
    }
    $script:ChecksumsPath = $dest
}

# ── Download + verify ──────────────────────────────────────────────────────────

function Get-Asset ([string]$Filename, [string]$Dest) {
    $url = "$DlBase/$script:Version/$Filename"
    Write-Info "Downloading $Filename..."

    if ($DryRun) { Write-Dry "GET $url -> $Dest"; return }

    try {
        Invoke-WebRequest -Uri $url -OutFile $Dest -UseBasicParsing
    } catch {
        Abort "Download failed for ${Filename}: $_"
    }

    # SHA-256 verification
    if ($script:ChecksumsPath -and (Test-Path $script:ChecksumsPath)) {
        $line = Get-Content $script:ChecksumsPath |
                Where-Object { $_ -match "\s${Filename}$" } |
                Select-Object -First 1

        if (-not $line) {
            Write-Warn "No checksum entry found for $Filename — skipping verification."
            return
        }

        $expected = ($line -split '\s+')[0].ToLower()
        $actual   = (Get-FileHash -Path $Dest -Algorithm SHA256).Hash.ToLower()

        if ($actual -ne $expected) {
            Write-Err "SHA-256 mismatch for $Filename"
            Write-Err "  Expected: $expected"
            Write-Err "  Got:      $actual"
            Abort 'Download appears corrupted or tampered with. Aborting.'
        }
        Write-Ok "SHA-256 verified: $Filename"
    }
}

# ── PATH management ────────────────────────────────────────────────────────────

function Add-ToUserPath ([string]$Dir) {
    $currentPath = [Environment]::GetEnvironmentVariable('PATH', 'User') ?? ''
    $paths = $currentPath -split ';' | Where-Object { $_ -ne '' }

    if ($paths -contains $Dir) { return }

    Write-Warn "$Dir is not on your PATH."

    if (-not $Yes -and -not $DryRun -and $IsInteractive) {
        $answer = Read-Host '  Add to User PATH? [Y/n]'
        if ($answer -and $answer -notmatch '^[Yy]') {
            Write-Warn "Skipped. Add $Dir to PATH manually to use stegcore from any terminal."
            return
        }
    }

    if ($DryRun) {
        Write-Dry "Add '$Dir' to User PATH environment variable"
        return
    }

    $newPath = (($paths + $Dir) | Where-Object { $_ -ne '' }) -join ';'
    [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
    $env:PATH = "$env:PATH;$Dir"   # update current session too
    Write-Ok "Added to User PATH. Restart your terminal for it to take effect."
}

# ── CLI install ────────────────────────────────────────────────────────────────

function Install-Cli {
    $filename = "stegcore-$script:Version-windows-$Arch.zip"
    $archive  = Join-Path $TmpDir $filename
    $binary   = Join-Path $InstallDir 'stegcore.exe'

    Get-Asset -Filename $filename -Dest $archive

    if ($DryRun) {
        Write-Dry "Extract stegcore.exe -> $binary"
        return
    }

    if ((Test-Path $binary) -and -not $Upgrade) {
        Write-Warn 'stegcore.exe is already installed.'
        Write-Warn 'Run with -Upgrade to replace the existing installation.'
        return
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    Expand-Archive -Path $archive -DestinationPath $TmpDir -Force

    $extracted = Join-Path $TmpDir 'stegcore.exe'
    if (-not (Test-Path $extracted)) {
        Abort 'Expected stegcore.exe was not found in the archive. The release asset may be malformed.'
    }

    Copy-Item -Path $extracted -Destination $binary -Force
    Write-Ok "CLI installed -> $binary"

    # Smoke test
    try {
        $ver = & $binary --version 2>&1 | Select-Object -First 1
        Write-Ok "Verified: $ver"
    } catch {
        Write-Warn 'Binary installed but --version check failed. It may require a Visual C++ runtime update.'
    }

    Add-ToUserPath -Dir $InstallDir
}

# ── GUI install ────────────────────────────────────────────────────────────────

function Install-Gui {
    $filename = "stegcore-gui-$script:Version-windows-$Arch.msi"
    $msi      = Join-Path $TmpDir $filename

    Get-Asset -Filename $filename -Dest $msi

    if ($DryRun) {
        Write-Dry "msiexec /i `"$msi`" /qn"
        return
    }

    Write-Info 'Running installer (this may take a moment)...'
    $proc = Start-Process -FilePath 'msiexec.exe' `
                          -ArgumentList "/i `"$msi`" /qn /norestart" `
                          -Wait -PassThru

    if ($proc.ExitCode -ne 0) {
        Abort "MSI installer exited with code $($proc.ExitCode). Try running the .msi manually for a detailed error."
    }
    Write-Ok 'Stegcore GUI installed.'
}

# ── Uninstall ──────────────────────────────────────────────────────────────────

function Invoke-Uninstall {
    Write-Host ''
    Write-Host 'Uninstalling Stegcore...' -ForegroundColor White
    $removed = 0

    # CLI binaries
    $targets = @(
        (Join-Path $InstallDir 'stegcore.exe')
    )
    foreach ($t in $targets) {
        if (Test-Path $t) {
            if ($DryRun) { Write-Dry "Remove $t" }
            else          { Remove-Item $t -Force; Write-Ok "Removed: $t" }
            $removed++
        }
    }

    # Remove install dir if now empty
    if (-not $DryRun -and (Test-Path $InstallDir)) {
        $remaining = Get-ChildItem $InstallDir -ErrorAction SilentlyContinue
        if (-not $remaining) {
            Remove-Item $InstallDir -Force -Recurse
            Write-Ok "Removed empty directory: $InstallDir"
        }
    }

    # MSI-installed GUI — find and run uninstaller from registry
    $regRoots = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $regRoots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = $_.GetValue('DisplayName', '')
            if ($displayName -notmatch 'Stegcore') { return }

            $productCode = $_.GetValue('ProductCode', '')
            if (-not $productCode) { return }

            Write-Info "Found MSI entry: $displayName"
            if ($DryRun) {
                Write-Dry "msiexec /x `"$productCode`" /qn"
            } else {
                $proc = Start-Process -FilePath 'msiexec.exe' `
                                      -ArgumentList "/x `"$productCode`" /qn /norestart" `
                                      -Wait -PassThru
                if ($proc.ExitCode -eq 0) {
                    Write-Ok 'Stegcore GUI uninstalled.'
                } else {
                    Write-Warn "Uninstaller exited with code $($proc.ExitCode). Try removing via Apps & Features manually."
                }
            }
            $removed++
        }
    }

    Write-Host ''
    if ($removed -eq 0) {
        Write-Warn 'No Stegcore installation found on this machine.'
    } else {
        Write-Ok 'Stegcore has been removed.'
        Write-Warn 'PATH entries are not removed automatically.'
        Write-Warn 'To remove: System > Advanced system settings > Environment Variables > User PATH.'
    }
}

# ── Interactive component selection ────────────────────────────────────────────

function Select-Component {
    if ($Component -ne '') { return }

    # Non-interactive (piped via irm | iex) — default to CLI
    if (-not $IsInteractive) {
        Write-Info "Non-interactive mode detected — installing CLI by default."
        Write-Info "Run '.\install.ps1 -Component both' for CLI + GUI."
        $script:Component = 'cli'
        return
    }

    Write-Host ''
    Write-Host 'What would you like to install?' -ForegroundColor White
    Write-Host ''
    Write-Host '  1) CLI only    -- command-line tool (stegcore.exe)'
    Write-Host '  2) GUI only    -- desktop application'
    Write-Host '  3) Both        -- CLI + GUI'
    Write-Host ''

    $choice = Read-Host '  Choice [1/2/3]'
    $script:Component = switch ($choice) {
        '1'  { 'cli' }
        '2'  { 'gui' }
        '3'  { 'both' }
        ''   { 'cli' }
        default { Abort "Invalid choice: '$choice'. Please enter 1, 2, or 3." }
    }
}

# ── Main ───────────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  +===================================+' -ForegroundColor Cyan
Write-Host '  |       STEGCORE INSTALLER          |' -ForegroundColor Cyan
Write-Host '  |   Hide . Encrypt . Deny           |' -ForegroundColor DarkCyan
Write-Host '  +===================================+' -ForegroundColor Cyan
Write-Host ''
Write-Info "Platform:     Windows $Arch"
if ($DryRun) { Write-Host '  [dry-run mode -- no changes will be made]' -ForegroundColor Magenta }
Write-Host ''

if ($Uninstall) {
    Invoke-Uninstall
    exit 0
}

Resolve-Version
Select-Component
Get-Checksums

Write-Host ''
Write-Info "Version:     $script:Version"
Write-Info "Component:   $script:Component"
Write-Info "Install dir: $InstallDir"

if (-not $Yes -and -not $DryRun -and $IsInteractive) {
    Write-Host ''
    $confirm = Read-Host '  Proceed? [Y/n]'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host 'Aborted.'
        exit 0
    }
}

Write-Host ''

switch ($script:Component) {
    'cli'  { Install-Cli }
    'gui'  { Install-Gui }
    'both' { Install-Cli; Install-Gui }
}

Write-Host ''
Write-Ok "Done. Thank you for installing Stegcore $script:Version."
Write-Host ''

} finally {
    Remove-TmpDir
}
