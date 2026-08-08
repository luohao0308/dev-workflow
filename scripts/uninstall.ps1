[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [string[]]$Packs = @(),

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Resolve-FullPath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Target directory does not exist: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Test-IsWithin([string]$Parent, [string]$Candidate) {
    $prefix = $Parent.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    return $Candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-TargetFile([string]$Root, [string]$RelativePath) {
    $normalized = $RelativePath.Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($normalized) -or [IO.Path]::IsPathRooted($normalized) -or $normalized -match '(^|/)\.\.(/|$)') {
        throw "Unsafe manifest path: $RelativePath"
    }
    $resolved = [IO.Path]::GetFullPath((Join-Path $Root $normalized))
    if (-not (Test-IsWithin -Parent $Root -Candidate $resolved)) {
        throw "Manifest path escapes the target directory: $RelativePath"
    }
    return $resolved
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-NormalizedPacks([string[]]$Requested) {
    $result = [Collections.Generic.List[string]]::new()
    foreach ($item in $Requested) {
        foreach ($name in ($item -split ',')) {
            $normalized = $name.Trim().ToLowerInvariant()
            if ($normalized -and -not $result.Contains($normalized)) {
                $result.Add($normalized)
            }
        }
    }
    return @($result)
}

function Read-ManagedManifest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing dev-workflow manifest: $Path"
    }
    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Cannot parse dev-workflow manifest: $Path"
    }
    if ($manifest.managedBy -ne 'dev-workflow') {
        throw "Manifest is not managed by dev-workflow: $Path"
    }
    if ([string]$manifest.schemaVersion -notin @('1', '2')) {
        throw "Unsupported dev-workflow manifest schema: $Path"
    }
    if (([string]$manifest.workflowVersion) -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw "Manifest has an invalid workflowVersion: $Path"
    }
    $installedPacksProperty = $manifest.PSObject.Properties['installedPacks']
    if (
        $null -eq $installedPacksProperty -or
        $null -eq $installedPacksProperty.Value -or
        $installedPacksProperty.Value -is [string] -or
        $installedPacksProperty.Value -isnot [Collections.IEnumerable]
    ) {
        throw "Manifest installedPacks must be an array: $Path"
    }
    if ($null -eq $manifest.onboarding -or [string]$manifest.onboarding.status -notin @('pending', 'ready', 'blocked')) {
        throw "Manifest has an invalid onboarding status: $Path"
    }
    return $manifest
}

function New-InventoryEntry([string]$Path, [string]$Source, [string]$Action, [AllowNull()][string]$Hash) {
    return [pscustomobject]@{
        path = $Path.Replace('\', '/')
        source = $Source.Trim().ToLowerInvariant()
        action = $Action.Trim().ToLowerInvariant()
        installedSha256 = if ([string]::IsNullOrWhiteSpace($Hash)) { $null } else { $Hash.Trim().ToLowerInvariant() }
    }
}

function Get-Inventory([object]$Manifest, [string]$SourceRoot, [string]$TargetRoot) {
    $entries = [Collections.Generic.List[object]]::new()
    $seen = @{}
    if ([string]$Manifest.schemaVersion -eq '2') {
        $filesProperty = $Manifest.PSObject.Properties['files']
        if (
            $null -eq $filesProperty -or
            $null -eq $filesProperty.Value -or
            $filesProperty.Value -is [string] -or
            $filesProperty.Value -isnot [Collections.IEnumerable]
        ) {
            throw 'Schema 2 manifest is missing a valid files array.'
        }
        foreach ($entry in @($filesProperty.Value)) {
            $normalized = ([string]$entry.path).Replace('\', '/')
            $action = ([string]$entry.action).Trim().ToLowerInvariant()
            $hash = ([string]$entry.installedSha256).Trim().ToLowerInvariant()
            if ($seen.ContainsKey($normalized)) {
                throw "Manifest contains a duplicate file entry: $normalized"
            }
            if ($action -notin @('created', 'appended', 'managed-block', 'preserved', 'legacy')) {
                throw "Manifest contains an invalid action for '$normalized': $action"
            }
            if ($action -eq 'created' -and $hash -notmatch '^[0-9a-f]{64}$') {
                throw "Manifest contains an invalid installedSha256 for '$normalized'."
            }
            if ($action -ne 'created' -and -not [string]::IsNullOrWhiteSpace($hash)) {
                throw "Manifest contains an unexpected installedSha256 for '$normalized'."
            }
            Resolve-TargetFile -Root $TargetRoot -RelativePath $normalized | Out-Null
            $entries.Add((New-InventoryEntry -Path $normalized -Source ([string]$entry.source) -Action $action -Hash $hash))
            $seen[$normalized] = $true
        }
        return @($entries)
    }

    $overlays = [Collections.Generic.List[object]]::new()
    $overlays.Add([pscustomobject]@{ Name = 'core'; Root = (Join-Path $SourceRoot 'core') })
    foreach ($pack in @($Manifest.installedPacks)) {
        $packName = ([string]$pack).Trim().ToLowerInvariant()
        $packRoot = Join-Path $SourceRoot "packs/$packName"
        if (-not (Test-Path -LiteralPath $packRoot -PathType Container)) {
            throw "Legacy manifest references an unavailable workflow pack: $packName"
        }
        $overlays.Add([pscustomobject]@{ Name = $packName; Root = $packRoot })
    }
    foreach ($overlay in $overlays) {
        if (-not (Test-Path -LiteralPath $overlay.Root -PathType Container)) {
            throw "Workflow overlay is missing: $($overlay.Root)"
        }
        $prefix = $overlay.Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        foreach ($file in Get-ChildItem -LiteralPath $overlay.Root -Recurse -File | Sort-Object FullName) {
            $relative = $file.FullName.Substring($prefix.Length).Replace('\', '/')
            if ($seen.ContainsKey($relative)) {
                throw "Workflow overlays contain a duplicate path: $relative"
            }
            $action = if ($relative -eq 'AGENTS.md') { 'managed-block' } else { 'legacy' }
            $entries.Add((New-InventoryEntry -Path $relative -Source $overlay.Name -Action $action -Hash $null))
            $seen[$relative] = $true
        }
    }
    return @($entries)
}

function Remove-EmptyParents([string[]]$Paths, [string]$Root) {
    $directories = @(
        $Paths |
            ForEach-Object { Split-Path -Parent $_ } |
            Where-Object { $_ -and (Test-IsWithin -Parent $Root -Candidate $_) } |
            Sort-Object Length -Descending -Unique
    )
    foreach ($directory in $directories) {
        $current = $directory
        while ($current -and (Test-IsWithin -Parent $Root -Candidate $current)) {
            if (-not (Test-Path -LiteralPath $current -PathType Container)) { break }
            if (@(Get-ChildItem -LiteralPath $current -Force).Count -gt 0) { break }
            Remove-Item -LiteralPath $current
            $current = Split-Path -Parent $current
        }
    }
}

$sourceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$targetRoot = Resolve-FullPath $TargetPath
if (
    [StringComparer]::OrdinalIgnoreCase.Equals($sourceRoot, $targetRoot) -or
    (Test-IsWithin -Parent $sourceRoot -Candidate $targetRoot)
) {
    throw 'The target directory cannot be the dev-workflow distribution repository or one of its subdirectories.'
}

$manifestPath = Join-Path $targetRoot '.dev-workflow/manifest.json'
$manifest = Read-ManagedManifest $manifestPath
$distributionVersion = (Get-Content -LiteralPath (Join-Path $sourceRoot 'VERSION') -Raw -Encoding UTF8).Trim()
if ([string]$manifest.schemaVersion -eq '2' -and $distributionVersion -ne [string]$manifest.workflowVersion) {
    throw "Uninstall requires dev-workflow version $($manifest.workflowVersion), but this distribution is $distributionVersion."
}
$installedPacks = @(
    $manifest.installedPacks |
        ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
        Where-Object { $_ }
)
$requestedPacks = Get-NormalizedPacks $Packs
$fullUninstall = $requestedPacks.Count -eq 0
foreach ($pack in $requestedPacks) {
    if ($installedPacks -notcontains $pack) {
        throw "Pack '$pack' is not installed. Installed packs: $($installedPacks -join ', ')"
    }
}

$inventory = @(Get-Inventory -Manifest $manifest -SourceRoot $sourceRoot -TargetRoot $targetRoot)
$sourceHashes = @{}
foreach ($entry in $inventory) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.source)) {
        throw "Manifest contains an empty source for '$($entry.path)'."
    }
    if ($entry.source -ne 'core' -and $installedPacks -notcontains $entry.source) {
        throw "Manifest assigns '$($entry.path)' to uninstalled pack '$($entry.source)'."
    }
    $ownerRoot = if ($entry.source -eq 'core') {
        Join-Path $sourceRoot 'core'
    } else {
        Join-Path $sourceRoot "packs/$($entry.source)"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $ownerRoot $entry.path) -PathType Leaf)) {
        throw "Manifest file '$($entry.path)' does not belong to workflow source '$($entry.source)'."
    }
    $sourceHash = Get-Sha256 (Join-Path $ownerRoot $entry.path)
    $sourceHashes[$entry.path] = $sourceHash
    if ($entry.action -eq 'created' -and $entry.installedSha256 -ne $sourceHash) {
        throw "Manifest created-file hash does not match workflow source for '$($entry.path)'."
    }
}
$selectedEntries = if ($fullUninstall) {
    @($inventory)
} else {
    @($inventory | Where-Object { $requestedPacks -contains $_.source })
}

$plans = [Collections.Generic.List[object]]::new()
$removedPaths = [Collections.Generic.List[string]]::new()
$coreStart = '<!-- AI-WORKFLOW:CORE:START -->'
$coreEnd = '<!-- AI-WORKFLOW:CORE:END -->'

foreach ($entry in $selectedEntries | Sort-Object path) {
    $targetFile = Resolve-TargetFile -Root $targetRoot -RelativePath $entry.path
    if (-not (Test-Path -LiteralPath $targetFile -PathType Leaf)) {
        $plans.Add([pscustomobject]@{ Kind = 'missing'; Entry = $entry; Target = $targetFile })
        continue
    }

    $currentHash = Get-Sha256 $targetFile
    if ($entry.path -eq 'AGENTS.md') {
        $content = Get-Content -LiteralPath $targetFile -Raw -Encoding UTF8
        $startCount = ([regex]::Matches($content, [regex]::Escape($coreStart))).Count
        $endCount = ([regex]::Matches($content, [regex]::Escape($coreEnd))).Count
        if (($startCount -ne $endCount) -or $startCount -gt 1) {
            throw 'AGENTS.md contains incomplete or duplicate AI-WORKFLOW core markers; uninstall stopped before making changes.'
        }
        if (
            $entry.action -eq 'created' -and
            $currentHash -eq $entry.installedSha256 -and
            $entry.installedSha256 -eq $sourceHashes[$entry.path]
        ) {
            $plans.Add([pscustomobject]@{ Kind = 'delete'; Entry = $entry; Target = $targetFile })
        } elseif ($startCount -eq 1) {
            $plans.Add([pscustomobject]@{ Kind = 'remove-block'; Entry = $entry; Target = $targetFile })
        } else {
            $plans.Add([pscustomobject]@{ Kind = 'keep'; Entry = $entry; Target = $targetFile; Reason = 'managed core block is already absent' })
        }
        continue
    }

    if (
        $entry.action -eq 'created' -and
        $currentHash -eq $entry.installedSha256 -and
        $entry.installedSha256 -eq $sourceHashes[$entry.path]
    ) {
        $plans.Add([pscustomobject]@{ Kind = 'delete'; Entry = $entry; Target = $targetFile })
    } elseif ($entry.action -eq 'created') {
        $plans.Add([pscustomobject]@{ Kind = 'keep'; Entry = $entry; Target = $targetFile; Reason = 'file was modified after installation' })
    } else {
        $plans.Add([pscustomobject]@{ Kind = 'keep'; Entry = $entry; Target = $targetFile; Reason = "ownership is $($entry.action)" })
    }
}

if ($DryRun) {
    Write-Output 'dev-workflow uninstall dry-run (no files written)'
} else {
    Write-Output 'dev-workflow uninstall'
}
Write-Output "target: $targetRoot"
Write-Output $(if ($fullUninstall) { 'scope: core and all installed packs' } else { "scope: packs $($requestedPacks -join ', ')" })
foreach ($plan in $plans) {
    switch ($plan.Kind) {
        'delete' { Write-Output "[delete] $($plan.Entry.path)" }
        'remove-block' { Write-Output '[edit] AGENTS.md (remove managed AI-WORKFLOW core block)' }
        'missing' { Write-Output "[skip] $($plan.Entry.path) (already missing)" }
        'keep' { Write-Output "[keep] $($plan.Entry.path) ($($plan.Reason))" }
    }
}

if ($DryRun) {
    Write-Output $(if ($fullUninstall) { '[delete] .dev-workflow/manifest.json' } else { '[update] .dev-workflow/manifest.json' })
    return
}

foreach ($plan in $plans) {
    if ($plan.Kind -eq 'delete') {
        Remove-Item -LiteralPath $plan.Target
        $removedPaths.Add($plan.Target)
        continue
    }
    if ($plan.Kind -eq 'remove-block') {
        $content = Get-Content -LiteralPath $plan.Target -Raw -Encoding UTF8
        $pattern = '(?s)' + [regex]::Escape($coreStart) + '.*?' + [regex]::Escape($coreEnd)
        $updated = ([regex]::new($pattern)).Replace($content, '', 1)
        Write-Utf8NoBom -Path $plan.Target -Content $updated
    }
}

if ($fullUninstall) {
    Remove-Item -LiteralPath $manifestPath
    $metadataRoot = Split-Path -Parent $manifestPath
    if ((Test-Path -LiteralPath $metadataRoot -PathType Container) -and @(Get-ChildItem -LiteralPath $metadataRoot -Force).Count -eq 0) {
        Remove-Item -LiteralPath $metadataRoot
    }
} else {
    $remainingPacks = @($installedPacks | Where-Object { $requestedPacks -notcontains $_ })
    $remainingFiles = @($inventory | Where-Object { $requestedPacks -notcontains $_.source } | Sort-Object path)
    $now = [DateTime]::UtcNow.ToString('o')
    $updatedManifest = [ordered]@{
        schemaVersion = 2
        managedBy = 'dev-workflow'
        workflowVersion = [string]$manifest.workflowVersion
        installedPacks = $remainingPacks
        files = $remainingFiles
        installedAt = [string]$manifest.installedAt
        updatedAt = $now
        onboarding = [ordered]@{
            status = [string]$manifest.onboarding.status
            lastAuditAt = if ($manifest.onboarding.lastAuditAt) { [string]$manifest.onboarding.lastAuditAt } else { $null }
        }
    }
    Write-Utf8NoBom -Path $manifestPath -Content (($updatedManifest | ConvertTo-Json -Depth 8) + "`r`n")
}

Remove-EmptyParents -Paths @($removedPaths) -Root $targetRoot
Write-Output 'result: complete'
