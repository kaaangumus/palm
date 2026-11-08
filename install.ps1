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
    $env:PALM_INSTALL_DIR = "$HOME\bin"
    irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex

.EXAMPLE
    # Belirli bir surumu kurmak icin
    $env:PALM_VERSION = "v0.3.0"
    irm https://raw.githubusercontent.com/kaaangumus/palm/main/install.ps1 | iex

.NOTES
    Bu script 'irm ... | iex' ile calisacak sekilde yazildi:
      - 'param()' blogu kullanilmaz (pipeline girdisinde parse hatasi verir).
        Yapilandirma PALM_INSTALL_DIR / PALM_VERSION ortam degiskenleriyle yapilir.
      - 'exit' cagrilmaz; aksi halde kullanicinin PowerShell oturumu kapanir.
        Hatalar throw ile bildirilir.
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = 'kaaangumus/palm'
$binName = 'palm.exe'

$InstallDir = if ($env:PALM_INSTALL_DIR) { $env:PALM_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\palm' }
$Version    = if ($env:PALM_VERSION) { $env:PALM_VERSION } else { 'latest' }
$tagName    = if ($Version -ne 'latest') {
    if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
} else {
    'latest'
}

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
            & curl.exe -fsSL --retry 3 --retry-delay 2 $url -o $destination
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

        if ($status -eq 404) { throw "dosya bulunamadi (HTTP 404): $url" }
        if ($status) { throw "indirme basarisiz (HTTP $status): $url" }
        throw "indirme basarisiz: $($_.Exception.Message)"
    }
}

# GitHub'in release CDN'i bazi aglarda 504 dondururken API ayni dosyayi
# sunabiliyor. Bu yol asset'i API uzerinden indirir.
function Save-BinaryViaApi([string]$assetName, [string]$destination) {
    $releaseUrl = if ($Version -and $Version -ne 'latest') {
        "https://api.github.com/repos/$repo/releases/tags/$tagName"
    } else {
        "https://api.github.com/repos/$repo/releases/latest"
    }

    Write-Step "GitHub API uzerinden cozuluyor: $assetName"
    try {
        $headers = @{ 'User-Agent' = 'palm-installer'; 'Accept' = 'application/vnd.github+json' }
        $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers -UseBasicParsing
    } catch {
        throw "surum bilgisi alinamadi: $($_.Exception.Message)"
    }

    $asset = @($release.assets) | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    if (-not $asset) { throw "yayinda '$assetName' adli dosya yok" }

    # binary icerigi icin octet-stream iste
    $assetHeaders = @{ 'User-Agent' = 'palm-installer'; 'Accept' = 'application/octet-stream' }
    $assetUrl = "https://api.github.com/repos/$repo/releases/assets/$($asset.id)"
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -fsSL --retry 3 --retry-delay 2 -H 'Accept: application/octet-stream' -H 'User-Agent: palm-installer' $assetUrl -o $destination
        if ($LASTEXITCODE -ne 0) { throw "API indirmesi basarisiz (curl exit $LASTEXITCODE)" }
    } else {
        Invoke-WebRequest -Uri $assetUrl -Headers $assetHeaders -OutFile $destination -UseBasicParsing
    }
}

function Save-BinaryViaGh([string]$assetName, [string]$destination) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { return $false }
    Write-Step "gh CLI uzerinden cozuluyor: $assetName"
    & gh release download $tagName --repo $repo --pattern $assetName --output $destination --clobber 2>&1 | Out-Host
    return ($LASTEXITCODE -eq 0)
}

function Get-ExpectedChecksum([string]$asset, [string]$checksumsPath) {
    if (-not (Test-Path -LiteralPath $checksumsPath)) { return $null }
    foreach ($line in Get-Content -LiteralPath $checksumsPath) {
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2 -and $parts[1] -eq $asset) {
            return $parts[0].ToLowerInvariant()
        }
    }
    return $null
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

# -- kurulum ---------------------------------------------------------------
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
        $downloaded = $false
        $assetName = $target.Asset

        # 1) dogrudan release URL'i
        try {
            Save-Binary -url $target.Url -destination $tmp
            $downloaded = $true
        } catch {
            Write-Warn "dogrudan indirme basarisiz: $($_.Exception.Message)"
        }

        # 2) gh CLI (oturum acmis ise kimlikli API istegi kullanir)
        if (-not $downloaded) {
            if (Save-BinaryViaGh -assetName $assetName -destination $tmp) { $downloaded = $true }
        }

        # 3) GitHub API asset endpoint'i
        if (-not $downloaded) {
            try {
                Save-BinaryViaApi -assetName $assetName -destination $tmp
                $downloaded = $true
            } catch {
                Write-Warn "API indirmesi basarisiz: $($_.Exception.Message)"
            }
        }

        # arm64 yayini yoksa x64 surumune dus (Windows ARM64 x64 emule eder)
        if (-not $downloaded -and $arch -eq 'arm64') {
            Write-Warn 'arm64 surumu bulunamadi, x64 surumu denenecek.'
            $arch = 'amd64'
            $target = Get-DownloadUrl -arch $arch
            $assetName = $target.Asset
            Write-Step "indiriliyor: $assetName"
            try {
                Save-Binary -url $target.Url -destination $tmp
                $downloaded = $true
            } catch {
                Write-Warn "dogrudan indirme basarisiz: $($_.Exception.Message)"
            }
            if (-not $downloaded) {
                if (Save-BinaryViaGh -assetName $assetName -destination $tmp) { $downloaded = $true }
            }
            if (-not $downloaded) {
                try {
                    Save-BinaryViaApi -assetName $assetName -destination $tmp
                    $downloaded = $true
                } catch {
                    Write-Warn "API indirmesi basarisiz: $($_.Exception.Message)"
                }
            }
        }

        if (-not $downloaded) {
            throw "indirme basarisiz. Biraz sonra tekrar deneyin veya Go ile kurun: go install github.com/$repo@latest"
        }

        Assert-IsBinary -path $tmp

        $checksumsUrl = $target.Url -replace '/[^/]+$', '/checksums.txt'
        $checksumsPath = Join-Path ([System.IO.Path]::GetTempPath()) ("palm-sha256-" + [Guid]::NewGuid().ToString('N') + '.txt')
        $checksumsFetched = $false
        $expected = $null
        try {
            Save-Binary -url $checksumsUrl -destination $checksumsPath
            $checksumsFetched = $true
            $expected = Get-ExpectedChecksum -asset $assetName -checksumsPath $checksumsPath
        } catch {
            Write-Warn 'checksum dosyasi alinamadi; dogrulama atlaniyor.'
        } finally {
            if (Test-Path -LiteralPath $checksumsPath) { Remove-Item -LiteralPath $checksumsPath -Force -ErrorAction SilentlyContinue }
        }

        if ($expected) {
            $actual = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) {
                throw "sha256 dogrulanamadi: $assetName"
            }
            Write-Ok 'sha256 dogrulandi'
        } elseif ($checksumsFetched) {
            Write-Warn "checksum bulunamadi: $assetName"
        }

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
    Write-Host '  Bu oturumda kullanmak icin PATH zaten eklendi; dogrudan deneyin: palm -help' -ForegroundColor Gray
    Write-Host ''
} catch {
    Write-Host ''
    Write-Host "  Kurulum basarisiz: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '  Sorun devam ederse: https://github.com/kaaangumus/palm/issues' -ForegroundColor Gray
    Write-Host ''
    throw
}
