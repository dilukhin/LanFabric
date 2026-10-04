# Сборка закреплённого сервера AWG 3.1 для Linux на Windows.
# Не меняет установленные Go, PATH, VPN и службы.
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$outDir = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outDir) { throw 'Каталог сборки уже существует; укажите новый пустой путь.' }
New-Item -ItemType Directory -Path $outDir | Out-Null
$goVersion = '1.27.1'
$goArchiveHash = 'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
$serverRevision = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
$toolsRevision = 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
function Fetch-File([string]$url, [string]$path) {
    Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing -TimeoutSec 180
}
$goZip = Join-Path $outDir 'go-windows.zip'
Fetch-File "https://go.dev/dl/go$goVersion.windows-amd64.zip" $goZip
if ((Get-FileHash -LiteralPath $goZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $goArchiveHash) {
    throw 'Контрольная сумма официального Go не совпала.'
}
Expand-Archive -LiteralPath $goZip -DestinationPath (Join-Path $outDir 'compiler')
$goExe = Join-Path $outDir 'compiler\go\bin\go.exe'
$serverZip = Join-Path $outDir 'server-source.zip'
$toolsZip = Join-Path $outDir 'tools-source.zip'
Fetch-File "https://github.com/amnezia-vpn/amneziawg-go/archive/$serverRevision.zip" $serverZip
Fetch-File "https://github.com/amnezia-vpn/amneziawg-tools/archive/$toolsRevision.zip" $toolsZip
Expand-Archive -LiteralPath $serverZip -DestinationPath (Join-Path $outDir 'source')
$sourceDir = Join-Path $outDir "source\amneziawg-go-$serverRevision"
$binary = Join-Path $outDir 'amneziawg-go'
$variables = @('GOROOT','GOOS','GOARCH','GOAMD64','CGO_ENABLED','GOTOOLCHAIN',
    'GOMODCACHE','GOCACHE','GOPATH','GOPROXY','GOSUMDB','GONOSUMDB','GOPRIVATE','GONOPROXY',
    'GOFLAGS','GOMAXPROCS','GOGC','GOWORK','GOENV','GOEXPERIMENT')
$saved = @{}
foreach ($name in $variables) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:GOROOT = Join-Path $outDir 'compiler\go'
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:GOAMD64 = 'v1'
    $env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
    $env:GOMODCACHE = Join-Path $outDir 'gomodcache'
    $env:GOCACHE = Join-Path $outDir 'gocache'
    $env:GOPATH = Join-Path $outDir 'gopath'
    $env:GOPROXY = 'https://proxy.golang.org,direct'; $env:GOSUMDB = 'sum.golang.org'
    $env:GONOSUMDB = ''; $env:GOPRIVATE = ''; $env:GONOPROXY = ''; $env:GOFLAGS = ''
    $env:GOWORK = 'off'; $env:GOENV = 'off'; $env:GOEXPERIMENT = ''
    $env:GOMAXPROCS = '2'; $env:GOGC = '50'
    Push-Location -LiteralPath $sourceDir
    try {
        & $goExe mod download
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось получить зависимости Go.' }
        & $goExe mod verify
        if ($LASTEXITCODE -ne 0) { throw 'Проверка зависимостей Go не прошла.' }
        # Только основной пакет: вспомогательный netstack здесь не нужен.
        & $goExe build -trimpath -buildvcs=false -ldflags '-s -w' -o $binary .
        if ($LASTEXITCODE -ne 0) { throw 'Сборка сервера Go завершилась ошибкой.' }
        & $goExe version -m $binary | Set-Content -LiteralPath (Join-Path $outDir 'go-build-metadata.txt') -Encoding UTF8
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось прочитать сведения сборки.' }
    } finally { Pop-Location }
} finally {
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
$stream = [IO.File]::OpenRead($binary)
try {
    $header = New-Object byte[] 20
    if ($stream.Read($header, 0, 20) -ne 20 -or
        $header[0] -ne 127 -or $header[1] -ne 69 -or $header[2] -ne 76 -or $header[3] -ne 70 -or
        $header[4] -ne 2 -or $header[5] -ne 1 -or $header[18] -ne 62 -or $header[19] -ne 0) {
        throw 'Результат не является Linux ELF x86_64.'
    }
} finally { $stream.Dispose() }
$manifest = [ordered]@{
    go_version = $goVersion; go_archive_sha256 = $goArchiveHash
    server_source_revision = $serverRevision; tools_source_revision = $toolsRevision
    server_source_zip_sha256 = (Get-FileHash -LiteralPath $serverZip -Algorithm SHA256).Hash.ToLowerInvariant()
    tools_source_zip_sha256 = (Get-FileHash -LiteralPath $toolsZip -Algorithm SHA256).Hash.ToLowerInvariant()
    server_binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $outDir 'build-manifest.json') -Encoding UTF8
Write-Output "Сборка готова: $outDir"
