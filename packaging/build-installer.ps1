param(
    [Parameter(Mandatory=$true)][string]$Compiler,
    [string]$Python = (Join-Path $PSScriptRoot '..\.venv\Scripts\python.exe')
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $repoRoot 'dist\校园网连接守护.exe'
if (!(Test-Path -LiteralPath $exe)) { throw '请先按 README 构建主程序。' }
if (!(Test-Path -LiteralPath $Compiler)) { throw '找不到 ISCC.exe，请检查 -Compiler 参数。' }
if (!(Test-Path -LiteralPath $Python)) { throw '找不到构建用的 Python，请检查 -Python 参数。' }
& $Python (Join-Path $PSScriptRoot 'prepare-source.py')
if ($LASTEXITCODE -ne 0) { throw '生成源码包失败。' }
Copy-Item -LiteralPath $exe -Destination (Join-Path $PSScriptRoot 'payload\校园网连接守护.exe') -Force
& $Compiler (Join-Path $PSScriptRoot 'CampusNetGuardian.iss')
if ($LASTEXITCODE -ne 0) { throw "安装包编译失败：$LASTEXITCODE" }
& $Python (Join-Path $PSScriptRoot 'publish-files.py')
if ($LASTEXITCODE -ne 0) { throw '生成 GitHub 更新文件失败。' }
