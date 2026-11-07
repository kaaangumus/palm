#Requires -Version 5.1
<#
.SYNOPSIS
    palm - Windows icin tek komut kurulum.

.DESCRIPTION
    GitHub Releases uzerinden palm ikili dosyasini indirir, kullanici
    klasorune kurar ve PATH'e ekler. install.sh'in Windows karsiligidir.

.EXAMPLE
    irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex

.EXAMPLE
    # Kurulum klasorunu degistirmek icin
    $env:PALM_INSTALL_DIR = "$HOME\bin"; irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex

.EXAMPLE
    # Belirli bir surumu kurmak icin
    .\install.ps1 -Version v0.3.0

.NOTES
    'irm | iex' ile calisirken 'exit' kullanilmaz; bu yuzden hatalar
    throw ile bildirilir ve PowerShell oturumu kapanmaz.
#>
param(
    [string]$InstallDir = '',
    [string]$Version = 'latest'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Parametre verilmediyse ortam degiskeni ya da varsayilan konum kullanilir.
# (param() icinde $(if ...) kullanilamaz: 'irm | iex' ile parse hatasi verir.)
if (-not $InstallDir) {
    $InstallDir = if ($env:PALM_INSTALL_DIR) {
        $env:PALM_INSTALL_DIR
    } else {
        Join-Path $env:LOCALAPPDATA 'Programs\palm'
    }
}

$repo = 'kaaangumus/palm'
$binName = 'palm.exe'

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "  ok  $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "  !   $Message" -ForegroundColor Yellow }

# Windows PowerShell 5.1 varsayilan olarak TLS 1.0 kullanir; GitHub TLS 1.2 ister.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

function Get-Arch {
    $arch = $env:PROCESSOR_ARCHITECTURE
    # 32 bit powershell, 64 bit isletim sisteminde calisiyorsa PROCESSOR_ARCHITEW6432 dolu olur
    if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }

    switch ($arch.ToUpperInvariant()) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        'X86'   { return '386' }
        default { throw "desteklenmeyen mimari: $arch" }
    }
}

function Get-DownloadUrl([string]$arch) {
    $asset = "palm_windows_${arch}.exe"
    if ($Version -and $Version -ne 'latest') {
        $tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
        return @{
            Asset = $asset
            Url   = "https://github.com/$repo/releases/download/$tag/$asset"
        }
    }
    return @{
        Asset = $asset
        Url   = "https://github.com/$repo/releases/latest/download/$asset"
    }
}

function Save-Binary([string]$url, [string]$destination) {
    try {
        if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
            & curl.exe -fsSL $url -o $destination
            if ($LASTEXITCODE -ne 0) {
                if ($LASTEXITCODE -eq 22) { throw "dosya bulunamadi (HTTP hata): $url" }
                throw "indirme basarisiz (curl exit $LASTEXITCODE)"
            }
        } elseif (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue) {
            Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing
        } else {
            throw 'Indirme icin curl.exe veya Invoke-WebRequest gerekli.'
        }
    } catch {
        $status = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
        } catch { }

        if ($status -eq 404) {
            throw "dosya bulunamadi (HTTP 404): $url"
        }
        if ($status) {
            throw "indirme basarisiz (HTTP $status): $url"
        }
        throw "indirme basarisiz: $($_.Exception.Message)"
    }
}

function Assert-IsBinary([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { throw 'indirilen dosya bulunamadi' }
    $info = Get-Item -LiteralPath $path
    if ($info.Length -lt 1MB) {
        throw "indirilen dosya cok kucuk ($($info.Length) bayt) - buyuk ihtimalle surum bulunamadi (404 sayfasi indi)."
    }
    # PE dosyalari 'MZ' ile baslar
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw 'indirilen dosya gecerli bir Windows ikili dosyasi degil (MZ imzasi yok).'
    }
}

function Add-ToUserPath([string]$directory) {
    $normalized = $directory.TrimEnd('\')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $userPath) { $userPath = '' }

    $entries = @($userPath -split ';' | Where-Object { $_ -and $_.Trim() })
    $already = $entries | Where-Object { $_.TrimEnd('\') -ieq $normalized }

    if ($already) {
        Write-Ok "PATH zaten iceriyor: $normalized"
    } else {
        $newPath = (@($entries) + $normalized) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Ok "kullanici PATH'ine eklendi: $normalized"
    }

    # Bu oturumda da hemen kullanilabilsin
    if (($env:Path -split ';') -notcontains $normalized) {
        $env:Path = "$normalized;$env:Path"
    }
}

# -- kurulum ----------------------------------------------------------------
Write-Host ''
Write-Host '  palm - Windows kurulum' -ForegroundColor White
Write-Host ''

try {
    $arch = Get-Arch
    Write-Step "mimari: $arch"

    $target = Get-DownloadUrl -arch $arch
    Write-Step "indiriliyor: $($target.Asset)"

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("palm-" + [Guid]::NewGuid().ToString('N') + '.exe')
    try {
        try {
            Save-Binary -url $target.Url -destination $tmp
        } catch {
            # arm64 icin yayinlanmis ikili yoksa x64 surumune dus (Windows ARM64 x64 emule eder)
            if ($arch -eq 'arm64') {
                Write-Warn 'arm64 surumu bulunamadi, x64 surumu denenecek.'
                $arch = 'amd64'
                $target = Get-DownloadUrl -arch $arch
                Write-Step "indiriliyor: $($target.Asset)"
                Save-Binary -url $target.Url -destination $tmp
            } else {
                throw
            }
        }

        Assert-IsBinary -path $tmp

        if (-not (Test-Path -LiteralPath $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Ok "klasor olusturuldu: $InstallDir"
        }

        $destination = Join-Path $InstallDir $binName
        if (Test-Path -LiteralPath $destination) {
            Write-Warn "mevcut kurulum guncellenecek: $destination"
        }

        Move-Item -LiteralPath $tmp -Destination $destination -Force
        # Internet'ten indirildigi icin isaretli gelebilir; calismasi icin kaldir
        Unblock-File -LiteralPath $destination -ErrorAction SilentlyContinue
        Write-Ok "kuruldu: $destination"
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    Add-ToUserPath -directory $InstallDir

    Write-Step 'dogrulaniyor'
    try {
        $versionOutput = & $destination -version 2>&1 | Out-String
        $versionOutput.Trim() | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } catch {
        Write-Warn "surum kontrolu yapilamadi: $($_.Exception.Message)"
    }

    Write-Host ''
    Write-Host '  Kurulum tamam.' -ForegroundColor Green
    Write-Host '  Yeni bir terminal actiginizda "palm" komutu hazir olur.' -ForegroundColor Gray
    Write-Host '  Bu oturumda kullanmak icin zaten PATH eklendi; dogrudan deneyin: palm -help' -ForegroundColor Gray
    Write-Host ''
} catch {
    Write-Host ''
    Write-Host "  Kurulum basarisiz: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '  Sorun devam ederse: https://github.com/kaaangumus/palm/issues' -ForegroundColor Gray
    Write-Host ''
    throw
}
