<#
.SYNOPSIS
    Run Loupe over every file in a directory tree and report the results.

.DESCRIPTION
    Lists every file under -Path, feeds the list to `loupe --batch` (one
    process, every file parsed with all sections enabled, output discarded)
    and prints Loupe's summary. Files that are not PE or ELF are counted and
    skipped. Use the AddressSanitizer build to catch memory errors as well as
    crashes.

.EXAMPLE
    .\build.bat asan
    .\scripts\sweep.ps1                        # C:\Windows\System32, top level
    .\scripts\sweep.ps1 -Recurse               # and every subdirectory
    .\scripts\sweep.ps1 -Path C:\Windows\SysWOW64
#>
param(
    [string[]]$Path = @("$env:SystemRoot\System32"),
    [switch]$Recurse,
    [string]$Loupe = (Join-Path $PSScriptRoot '..\build\asan\loupe.exe'),
    [switch]$ListAll
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Loupe)) {
    throw "Loupe not found at $Loupe. Build it first: .\build.bat asan"
}
$Loupe = (Resolve-Path $Loupe).Path

$files = Get-ChildItem -LiteralPath $Path -File -Force -Recurse:$Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName }

$list = [IO.Path]::GetTempFileName()
try {
    [IO.File]::WriteAllLines($list, [string[]]$files)
    Write-Host ("{0:N0} files under {1}{2}" -f $files.Count, ($Path -join ', '),
        $(if ($Recurse) { ' (recursive)' } else { '' }))
    $verbose = if ($ListAll) { '-v' } else { '' }
    # cmd redirection keeps the bytes of the list intact; piping through
    # PowerShell 5.1 would re-encode the paths.
    cmd /c "`"$Loupe`" --batch $verbose < `"$list`""
    exit $LASTEXITCODE
}
finally {
    Remove-Item -LiteralPath $list -ErrorAction SilentlyContinue
}
