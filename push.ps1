<#
.SYNOPSIS
    One-step Push & Sync: Updates local folder version and changelog, then pushes to remote.
.EXAMPLE
    .\push.ps1
    .\push.ps1 -Message "feat: add copy button"
    .\push.ps1 -Bump minor
#>
param(
    [string]$Message,
    [ValidateSet("major", "minor", "patch", "none")]
    [string]$Bump
)

$argsList = @("scripts/push.py")
if ($Message) {
    $argsList += @("-m", $Message)
}
if ($Bump) {
    $argsList += @("--bump", $Bump)
}

python @argsList
