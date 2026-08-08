[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [string[]]$Packs = @(),

    [switch]$AllPacks,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Resolve-FullPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CoreBlock([string]$Path) {
    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $match = [regex]::Match(
        $content,
        '(?s)<!-- AI-WORKFLOW:CORE:START -->.*?<!-- AI-WORKFLOW:CORE:END -->'
    )
    if (-not $match.Success) {
        throw "Template is missing the AI-WORKFLOW core markers: $Path"
    }
    return $match.Value.Trim()
}

function Get-WorkflowVersion([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Workflow VERSION file does not exist: $Path"
    }
    $version = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8).Trim()
    if ($version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw "Invalid dev-workflow version '$version' in $Path"
    }
    return $version
}

function Read-ManagedManifest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Manifest path is not a file: $Path"
    }

    try {
        $manifest = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Cannot parse dev-workflow manifest: $Path"
    }
    if ($manifest.managedBy -ne 'dev-workflow') {
        throw "Manifest exists but is not managed by dev-workflow: $Path"
    }
    $schemaVersion = [string]$manifest.schemaVersion
    if ($schemaVersion -notin @('1', '2')) {
        throw "Unsupported dev-workflow manifest schema in $Path"
    }
    if (([string]$manifest.workflowVersion) -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
        throw "Manifest has an invalid workflowVersion: $Path"
    }
    $installedPacksProperty = $manifest.PSObject.Properties['installedPacks']
    if ($null -eq $installedPacksProperty) {
        throw "Manifest is missing installedPacks: $Path"
    }
    $installedPacksValue = $installedPacksProperty.Value
    if (
        $null -ne $installedPacksValue -and
        ($installedPacksValue -is [string] -or $installedPacksValue -isnot [Collections.IEnumerable])
    ) {
        throw "Manifest installedPacks must be an array: $Path"
    }
    if ($null -eq $manifest.onboarding -or ([string]$manifest.onboarding.status) -notin @('pending', 'ready', 'blocked')) {
        throw "Manifest has an invalid onboarding.status: $Path"
    }
    if ($schemaVersion -eq '2') {
        $filesProperty = $manifest.PSObject.Properties['files']
        if (
            $null -eq $filesProperty -or
            $null -eq $filesProperty.Value -or
            $filesProperty.Value -is [string] -or
            $filesProperty.Value -isnot [Collections.IEnumerable]
        ) {
            throw "Manifest files must be an array: $Path"
        }
        $seenPaths = @{}
        foreach ($entry in @($filesProperty.Value)) {
            $entryPath = ([string]$entry.path).Replace('\', '/')
            $source = ([string]$entry.source).Trim().ToLowerInvariant()
            $action = ([string]$entry.action).Trim().ToLowerInvariant()
            $hash = ([string]$entry.installedSha256).Trim().ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($entryPath) -or [IO.Path]::IsPathRooted($entryPath) -or $entryPath -match '(^|/)\.\.(/|$)') {
                throw "Manifest contains an unsafe file path: $Path"
            }
            if ([string]::IsNullOrWhiteSpace($source) -or $action -notin @('created', 'appended', 'managed-block', 'preserved', 'legacy')) {
                throw "Manifest contains an invalid file entry for '$entryPath': $Path"
            }
            if ($action -eq 'created' -and $hash -notmatch '^[0-9a-f]{64}$') {
                throw "Manifest contains an invalid installedSha256 for '$entryPath': $Path"
            }
            if ($action -ne 'created' -and -not [string]::IsNullOrWhiteSpace($hash)) {
                throw "Manifest contains an unexpected installedSha256 for '$entryPath': $Path"
            }
            if ($seenPaths.ContainsKey($entryPath)) {
                throw "Manifest contains a duplicate file entry for '$entryPath': $Path"
            }
            $seenPaths[$entryPath] = $true
        }
    }
    return $manifest
}

function New-ManifestPlan(
    [string]$Path,
    [string]$Version,
    [string[]]$InstalledPacks,
    [object[]]$Files,
    [object]$Existing
) {
    $now = [DateTime]::UtcNow.ToString('o')
    $installedAt = $now
    $onboardingStatus = 'pending'
    $lastAuditAt = $null
    $oldVersion = $null
    $oldUpdatedAt = $null
    if ($null -ne $Existing) {
        $oldVersion = [string]$Existing.workflowVersion
        $oldUpdatedAt = [string]$Existing.updatedAt
        if ($Existing.installedAt) { $installedAt = [string]$Existing.installedAt }
        if ($Existing.onboarding -and $Existing.onboarding.status) {
            $onboardingStatus = [string]$Existing.onboarding.status
        }
        if ($Existing.onboarding -and $Existing.onboarding.lastAuditAt) {
            $lastAuditAt = [string]$Existing.onboarding.lastAuditAt
        }
    }

    $normalizedFiles = @(
        $Files |
            Sort-Object { ([string]$_.path).ToLowerInvariant() } |
            ForEach-Object {
                [ordered]@{
                    path = ([string]$_.path).Replace('\', '/')
                    source = ([string]$_.source).Trim().ToLowerInvariant()
                    action = ([string]$_.action).Trim().ToLowerInvariant()
                    installedSha256 = if ([string]::IsNullOrWhiteSpace([string]$_.installedSha256)) { $null } else { ([string]$_.installedSha256).Trim().ToLowerInvariant() }
                }
            }
    )
    $oldPackSummary = if ($null -eq $Existing) { '' } else { @($Existing.installedPacks) -join ',' }
    $newPackSummary = @($InstalledPacks) -join ','
    $oldFileSummary = if ($null -eq $Existing -or [string]$Existing.schemaVersion -ne '2') {
        ''
    } else {
        @($Existing.files | ForEach-Object {
            "$(([string]$_.path).Replace('\', '/'))|$(([string]$_.source).ToLowerInvariant())|$(([string]$_.action).ToLowerInvariant())|$(([string]$_.installedSha256).ToLowerInvariant())"
        } | Sort-Object) -join "`n"
    }
    $newFileSummary = @($normalizedFiles | ForEach-Object {
        "$($_.path)|$($_.source)|$($_.action)|$($_.installedSha256)"
    } | Sort-Object) -join "`n"
    $changed = (
        ($null -eq $Existing) -or
        ([string]$Existing.schemaVersion -ne '2') -or
        ($oldVersion -ne $Version) -or
        ($oldPackSummary -ne $newPackSummary) -or
        ($oldFileSummary -ne $newFileSummary)
    )
    $updatedAt = if ($changed -or [string]::IsNullOrWhiteSpace($oldUpdatedAt)) { $now } else { $oldUpdatedAt }

    $manifest = [ordered]@{
        schemaVersion = 2
        managedBy = 'dev-workflow'
        workflowVersion = $Version
        installedPacks = @($InstalledPacks)
        files = $normalizedFiles
        installedAt = $installedAt
        updatedAt = $updatedAt
        onboarding = [ordered]@{
            status = $onboardingStatus
            lastAuditAt = $lastAuditAt
        }
    }

    [pscustomobject]@{
        Content = ($manifest | ConvertTo-Json -Depth 8)
        Changed = $changed
        Action = if ($null -eq $Existing) { '[create] .dev-workflow/manifest.json' } else { '[update] .dev-workflow/manifest.json' }
    }
}

function Test-IsWithin([string]$Parent, [string]$Candidate) {
    $separator = [IO.Path]::DirectorySeparatorChar
    $parentPrefix = $Parent.TrimEnd('\', '/') + $separator
    return $Candidate.StartsWith($parentPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Get-NormalizedPacks([string[]]$Requested, [string[]]$Available, [bool]$SelectAll) {
    $normalized = [Collections.Generic.List[string]]::new()
    foreach ($item in $Requested) {
        foreach ($name in ($item -split ',')) {
            $trimmed = $name.Trim().ToLowerInvariant()
            if ($trimmed) {
                $normalized.Add($trimmed)
            }
        }
    }

    if ($SelectAll -or $normalized.Contains('all')) {
        return @($Available)
    }

    $result = [Collections.Generic.List[string]]::new()
    foreach ($name in $normalized) {
        if ($Available -notcontains $name) {
            throw "Unknown pack '$name'. Available packs: $($Available -join ', ')"
        }
        if (-not $result.Contains($name)) {
            $result.Add($name)
        }
    }
    return @($result)
}

function Set-InventoryEntry(
    [hashtable]$Map,
    [string]$RelativePath,
    [string]$Source,
    [string]$Action,
    [AllowNull()][string]$InstalledSha256
) {
    $normalizedPath = $RelativePath.Replace('\', '/')
    $Map[$normalizedPath] = [pscustomobject]@{
        path = $normalizedPath
        source = $Source.ToLowerInvariant()
        action = $Action.ToLowerInvariant()
        installedSha256 = if ([string]::IsNullOrWhiteSpace($InstalledSha256)) { $null } else { $InstalledSha256.ToLowerInvariant() }
    }
}

$sourceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$coreRoot = Join-Path $sourceRoot 'core'
$packsRoot = Join-Path $sourceRoot 'packs'
$workflowVersion = Get-WorkflowVersion (Join-Path $sourceRoot 'VERSION')
$targetRoot = Resolve-FullPath $TargetPath

if (-not (Test-Path -LiteralPath $targetRoot -PathType Container)) {
    throw "Target directory does not exist: $targetRoot"
}
if (
    [StringComparer]::OrdinalIgnoreCase.Equals($sourceRoot, $targetRoot) -or
    (Test-IsWithin -Parent $sourceRoot -Candidate $targetRoot)
) {
    throw 'The target directory cannot be the dev-workflow distribution repository or one of its subdirectories.'
}
if (-not (Test-Path -LiteralPath $coreRoot -PathType Container)) {
    throw "Core overlay does not exist: $coreRoot"
}
if (-not (Test-Path -LiteralPath $packsRoot -PathType Container)) {
    throw "Packs directory does not exist: $packsRoot"
}

$metadataRoot = Join-Path $targetRoot '.dev-workflow'
$manifestPath = Join-Path $metadataRoot 'manifest.json'
if ((Test-Path -LiteralPath $metadataRoot) -and -not (Test-Path -LiteralPath $metadataRoot -PathType Container)) {
    throw "The .dev-workflow metadata path is not a directory: $metadataRoot"
}
if (Test-Path -LiteralPath $metadataRoot -PathType Container) {
    $metadataEntries = @(Get-ChildItem -LiteralPath $metadataRoot -Force)
    if ($metadataEntries.Count -gt 0 -and -not (Test-Path -LiteralPath $manifestPath)) {
        throw "The .dev-workflow directory contains unmanaged files but no manifest: $metadataRoot"
    }
}
$existingManifest = Read-ManagedManifest $manifestPath

$availablePacks = @(
    Get-ChildItem -LiteralPath $packsRoot -Directory |
        Sort-Object Name |
        ForEach-Object { $_.Name.ToLowerInvariant() }
)
$selectedPacks = Get-NormalizedPacks -Requested $Packs -Available $availablePacks -SelectAll $AllPacks.IsPresent

$existingPacks = [Collections.Generic.List[string]]::new()
if ($null -ne $existingManifest) {
    foreach ($pack in @($existingManifest.installedPacks)) {
        $name = ([string]$pack).Trim().ToLowerInvariant()
        if ($name -and $availablePacks -notcontains $name) {
            throw "Manifest references unavailable workflow pack '$name': $manifestPath"
        }
        if ($name -and -not $existingPacks.Contains($name)) {
            $existingPacks.Add($name)
        }
    }
}

$installedPacks = [Collections.Generic.List[string]]::new()
foreach ($pack in $availablePacks) {
    if ($existingPacks.Contains($pack) -or $selectedPacks -contains $pack) {
        $installedPacks.Add($pack)
    }
}

$inventoryByPath = @{}
if ($null -ne $existingManifest -and [string]$existingManifest.schemaVersion -eq '2') {
    foreach ($entry in @($existingManifest.files)) {
        Set-InventoryEntry `
            -Map $inventoryByPath `
            -RelativePath ([string]$entry.path) `
            -Source ([string]$entry.source) `
            -Action ([string]$entry.action) `
            -InstalledSha256 ([string]$entry.installedSha256)
    }
}
foreach ($entry in $inventoryByPath.Values) {
    if ($entry.source -ne 'core' -and -not $existingPacks.Contains([string]$entry.source)) {
        throw "Manifest assigns '$($entry.path)' to uninstalled workflow pack '$($entry.source)'."
    }
    $ownerRoot = if ($entry.source -eq 'core') { $coreRoot } else { Join-Path $packsRoot $entry.source }
    if (-not (Test-Path -LiteralPath (Join-Path $ownerRoot $entry.path) -PathType Leaf)) {
        throw "Manifest file '$($entry.path)' does not belong to workflow source '$($entry.source)'."
    }
    if ($entry.action -eq 'created') {
        $sourceHash = Get-Sha256 (Join-Path $ownerRoot $entry.path)
        if ($entry.installedSha256 -ne $sourceHash) {
            if ([string]$existingManifest.workflowVersion -eq $workflowVersion) {
                throw "Manifest created-file hash does not match workflow source for '$($entry.path)'."
            }
            $entry.action = 'legacy'
            $entry.installedSha256 = $null
        }
    }
}
$isLegacyManifest = $null -ne $existingManifest -and [string]$existingManifest.schemaVersion -eq '1'
if ($isLegacyManifest) {
    foreach ($pack in $existingPacks) {
        $legacyPackRoot = Join-Path $packsRoot $pack
        $legacyPrefix = $legacyPackRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        foreach ($file in Get-ChildItem -LiteralPath $legacyPackRoot -Recurse -File | Sort-Object FullName) {
            $relativePath = $file.FullName.Substring($legacyPrefix.Length).Replace('\', '/')
            if ($inventoryByPath.ContainsKey($relativePath)) {
                throw "Legacy workflow pack ownership collision for '$relativePath'."
            }
            Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $pack -Action 'legacy' -InstalledSha256 $null
        }
    }
}

$overlays = [Collections.Generic.List[object]]::new()
$overlays.Add([pscustomobject]@{ Name = 'core'; Root = $coreRoot })
foreach ($pack in $selectedPacks) {
    $overlays.Add([pscustomobject]@{ Name = $pack; Root = (Join-Path $packsRoot $pack) })
}

$coreTemplate = Join-Path $coreRoot 'AGENTS.md'
$coreBlock = Get-CoreBlock $coreTemplate
$actions = [Collections.Generic.List[string]]::new()
$seenPaths = @{}

foreach ($overlay in $overlays) {
    $overlayPrefix = $overlay.Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $files = Get-ChildItem -LiteralPath $overlay.Root -Recurse -File | Sort-Object FullName

    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($overlayPrefix.Length).Replace('\', '/')
        if ($seenPaths.ContainsKey($relativePath)) {
            throw "Overlay collision for '$relativePath': $($seenPaths[$relativePath]) and $($overlay.Name)"
        }
        $seenPaths[$relativePath] = $overlay.Name

        if ($inventoryByPath.ContainsKey($relativePath) -and $inventoryByPath[$relativePath].source -ne $overlay.Name) {
            throw "Manifest ownership collision for '$relativePath': $($inventoryByPath[$relativePath].source) and $($overlay.Name)"
        }

        $targetPathResolved = Join-Path $targetRoot $relativePath
        if ((Test-Path -LiteralPath $targetPathResolved) -and -not (Test-Path -LiteralPath $targetPathResolved -PathType Leaf)) {
            throw "Cannot install file because the target path is not a file: $targetPathResolved"
        }

        if ($relativePath -eq 'AGENTS.md' -and (Test-Path -LiteralPath $targetPathResolved -PathType Leaf)) {
            $existing = Get-Content -LiteralPath $targetPathResolved -Raw -Encoding UTF8
            $startCount = ([regex]::Matches($existing, '<!-- AI-WORKFLOW:CORE:START -->')).Count
            $endCount = ([regex]::Matches($existing, '<!-- AI-WORKFLOW:CORE:END -->')).Count
            $hasValidCoreBlock = (
                $startCount -eq 1 -and
                $endCount -eq 1 -and
                $existing.IndexOf('<!-- AI-WORKFLOW:CORE:START -->') -lt $existing.IndexOf('<!-- AI-WORKFLOW:CORE:END -->')
            )
            if ($hasValidCoreBlock) {
                $actions.Add("[skip] $relativePath (managed core block already exists)")
                if (-not $inventoryByPath.ContainsKey($relativePath)) {
                    Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $overlay.Name -Action 'managed-block' -InstalledSha256 $null
                }
            } elseif ($startCount -gt 0 -or $endCount -gt 0) {
                throw "Existing AGENTS.md contains incomplete or duplicate AI-WORKFLOW core markers: $targetPathResolved"
            } elseif ($DryRun) {
                $actions.Add("[append] $relativePath (preserved existing content; appended core block)")
                Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $overlay.Name -Action 'appended' -InstalledSha256 $null
            } else {
                $separator = if ($existing.EndsWith("`n") -or $existing.EndsWith("`r")) { "`n" } else { "`r`n`r`n" }
                Write-Utf8NoBom -Path $targetPathResolved -Content ($existing + $separator + $coreBlock + "`r`n")
                $actions.Add("[append] $relativePath (preserved existing content; appended core block)")
                Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $overlay.Name -Action 'appended' -InstalledSha256 $null
            }
            continue
        }

        if (Test-Path -LiteralPath $targetPathResolved -PathType Leaf) {
            $actions.Add("[skip] $relativePath (existing file was not overwritten)")
            if (-not $inventoryByPath.ContainsKey($relativePath)) {
                $ownershipAction = if ($isLegacyManifest) { 'legacy' } else { 'preserved' }
                Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $overlay.Name -Action $ownershipAction -InstalledSha256 $null
            }
            continue
        }

        if ($DryRun) {
            $actions.Add("[create] $relativePath [$($overlay.Name)]")
            Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $overlay.Name -Action 'created' -InstalledSha256 (Get-Sha256 $file.FullName)
            continue
        }

        $parent = Split-Path -Parent $targetPathResolved
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $targetPathResolved
        $actions.Add("[create] $relativePath [$($overlay.Name)]")
        Set-InventoryEntry -Map $inventoryByPath -RelativePath $relativePath -Source $overlay.Name -Action 'created' -InstalledSha256 (Get-Sha256 $targetPathResolved)
    }
}

$manifestPlan = New-ManifestPlan `
    -Path $manifestPath `
    -Version $workflowVersion `
    -InstalledPacks @($installedPacks) `
    -Files @($inventoryByPath.Values) `
    -Existing $existingManifest

if ($manifestPlan.Changed) {
    if ($DryRun) {
        $actions.Add("$($manifestPlan.Action) (dry-run; version $workflowVersion)")
    } else {
        New-Item -ItemType Directory -Path $metadataRoot -Force | Out-Null
        Write-Utf8NoBom -Path $manifestPath -Content ($manifestPlan.Content + "`r`n")
        $actions.Add("$($manifestPlan.Action) (version $workflowVersion)")
    }
} else {
    $actions.Add('[skip] .dev-workflow/manifest.json (already current)')
}

$packSummary = if ($selectedPacks.Count -eq 0) { 'none' } else { $selectedPacks -join ', ' }
if ($DryRun) {
    "dev-workflow dry-run (no files written; packs: $packSummary)"
} else {
    "dev-workflow installation complete (packs: $packSummary)"
}
$actions | ForEach-Object { $_ }
