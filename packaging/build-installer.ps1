param([Parameter(Mandatory=$true)][string]$Compiler)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repoRoot 'dist\校园网连接守护.exe'
if (!(Test-Path -LiteralPath $exe)) { throw '请先按 README 构建主程序。' }
if (!(Test-Path -LiteralPath $Compiler)) { throw '找不到 ISCC.exe，请检查 -Compiler 参数。' }
Copy-Item -LiteralPath $exe -Destination (Join-Path $PSScriptRoot 'payload\校园网连接守护.exe') -Force
& $Compiler (Join-Path $PSScriptRoot 'CampusNetGuardian.iss')
if ($LASTEXITCODE -ne 0) { throw "安装包编译失败：$LASTEXITCODE" }
