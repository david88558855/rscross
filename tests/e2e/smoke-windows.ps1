# Windows 冒烟：真实启动内嵌控制台，并验证「浏览器打开页面」所需的 HTTP 行为。
#
# 为什么单独成文件：变量名 `$home` 曾撞上 PowerShell 的只读自动变量，
# 把「服务已就绪」误报成失败；独立文件便于本地复现与审阅。
#
# 本地自测（解压产物后在同目录执行）：
#   pwsh -File tests/e2e/smoke-windows.ps1 -Dist .
#
# 注意：不要用 $home / $host / $input / $pid / $pwd / $error 等自动变量名。

[CmdletBinding()]
param(
    # rscross-server.exe 所在目录
    [string]$Dist = ".",
    # 控制台端口（与 console.bind 的默认值一致）
    [int]$Port = 7800,
    # 等待控制台就绪的上限（秒）
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = "Stop"

$script:Failures = New-Object System.Collections.Generic.List[string]
$script:Checks = 0

function Assert-That {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Detail = ""
    )
    $script:Checks++
    if ($Ok) {
        Write-Host "[PASS] $Name"
    } else {
        Write-Host "[FAIL] $Name  |  $Detail"
        $script:Failures.Add("$Name -> $Detail")
    }
}

function Resolve-ServerExe {
    param([string]$Dir)
    foreach ($name in @("rscross-server.exe", "rscross-server")) {
        $candidate = Join-Path $Dir $name
        if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
    }
    throw "未在 $Dir 找到 rscross-server 可执行文件"
}

# 返回 HTTP 状态码；网络错误返回 0（404 等已应答状态照常返回）。
function Get-StatusCode {
    param([string]$Url)
    try {
        return (Invoke-WebRequest -Uri $Url -TimeoutSec 5 -UseBasicParsing).StatusCode
    } catch {
        $resp = $_.Exception.Response
        if ($resp) { return [int]$resp.StatusCode }
        return 0
    }
}

function Get-ContentType {
    param($Response)
    $value = $Response.Headers["Content-Type"]
    if ($value -is [array]) { return ($value -join "; ") }
    return [string]$value
}

$exe = Resolve-ServerExe -Dir $Dist
$work = Join-Path ([System.IO.Path]::GetTempPath()) ("rscross-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null

$cfg = Join-Path $work "rscross-server.toml"
$state = Join-Path $work "state"
$stdout = Join-Path $work "server.out.log"
$stderr = Join-Path $work "server.err.log"
$base = "http://127.0.0.1:$Port"

Write-Host "==> 启动 $exe"
Write-Host "    控制台地址 $base ，状态目录 $state"

$proc = Start-Process -FilePath $exe `
    -ArgumentList @("--embedded", "--config", $cfg, "--state-dir", $state, "--name", "smoke") `
    -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr

function Stop-Server {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

function Show-ServerLog {
    Write-Host "---- 服务端 stdout（末尾 40 行）----"
    Get-Content $stdout -ErrorAction SilentlyContinue | Select-Object -Last 40
    Write-Host "---- 服务端 stderr（末尾 40 行，含初始管理员密码）----"
    Get-Content $stderr -ErrorAction SilentlyContinue | Select-Object -Last 40
}

try {
    # ---- 1) 就绪 ----
    $ready = $false
    for ($i = 0; $i -lt $TimeoutSec; $i++) {
        if ($proc.HasExited) { break }
        if ((Get-StatusCode "$base/api/v1/health") -eq 200) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    # 注意：不能写 ($proc.HasExited, "$($proc.ExitCode)") 这样的组合 ——
    # 进程尚未退出时访问 .ExitCode 会抛 InvalidOperationException。
    if ($proc.HasExited) {
        Show-ServerLog
        throw "服务端在控制台就绪前已退出（退出码=$($proc.ExitCode)）"
    }
    Assert-That "服务端保持运行" $true
    if (-not $ready) {
        Show-ServerLog
        throw "控制台在 $TimeoutSec 秒内未就绪（$base/api/v1/health）"
    }
    Assert-That "/api/v1/health 返回 200" $true

    # ---- 2) 首页 ----
    try {
        $index = Invoke-WebRequest -Uri "$base/" -UseBasicParsing
        $indexType = Get-ContentType $index
        Assert-That "首页返回 HTML 200" `
            ($index.StatusCode -eq 200 -and $indexType -match "text/html") `
            "status=$($index.StatusCode) content-type=$indexType"
        Assert-That "首页包含 SPA 挂载点 #app" ($index.Content -match 'id="app"') `
            ($index.Content.Substring(0, [Math]::Min(160, $index.Content.Length)))
    } catch {
        Assert-That "首页可访问" $false $_.Exception.Message
    }

    # ---- 3) 静态资源 ----
    try {
        $js = Invoke-WebRequest -Uri "$base/app.js" -UseBasicParsing
        $jsType = Get-ContentType $js
        Assert-That "/app.js 可加载且为 JavaScript" `
            ($js.StatusCode -eq 200 -and $jsType -match "javascript" -and $js.Content.Length -gt 1000) `
            "status=$($js.StatusCode) content-type=$jsType len=$($js.Content.Length)"
        Assert-That "app.js 确实调用控制台 API" ($js.Content -match "/api/v1/") ""
    } catch {
        Assert-That "/app.js 可访问" $false $_.Exception.Message
    }

    try {
        $css = Invoke-WebRequest -Uri "$base/app.css" -UseBasicParsing
        $cssType = Get-ContentType $css
        Assert-That "/app.css 可加载且为 CSS" `
            ($css.StatusCode -eq 200 -and $cssType -match "css" -and $css.Content.Length -gt 200) `
            "status=$($css.StatusCode) content-type=$cssType len=$($css.Content.Length)"
    } catch {
        Assert-That "/app.css 可访问" $false $_.Exception.Message
    }

    # ---- 4) 路由语义 ----
    $deep = Get-StatusCode "$base/tunnels"
    Assert-That "SPA 深链接回落到首页（200）" ($deep -eq 200) "status=$deep"

    $missing = Get-StatusCode "$base/does-not-exist.js"
    Assert-That "缺失的静态资源返回 404（不用 HTML 冒充 JS）" ($missing -eq 404) "status=$missing"

    $unknownApi = Get-StatusCode "$base/api/v1/definitely-not-here"
    Assert-That "未知 API 返回 404" ($unknownApi -eq 404) "status=$unknownApi"
} finally {
    Stop-Server
}

Write-Host ""
if ($script:Failures.Count -gt 0) {
    Write-Host "失败 $($script:Failures.Count)/$($script:Checks) 项："
    foreach ($item in $script:Failures) { Write-Host "  - $item" }
    throw "Windows 冒烟未通过"
}

Write-Host "Windows 版内嵌控制台可正常提供页面（$($script:Checks) 项断言全部通过）"
