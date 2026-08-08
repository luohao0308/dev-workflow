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
    if (([string]$manifest.schemaVersion) -ne '1') {
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
    return $manifest
}

function New-ManifestPlan(
    [string]$Path,
    [string]$Version,
    [string[]]$Selected,
    [string[]]$Available,
    [object]$Existing
) {
    $existingPacks = [Collections.Generic.List[string]]::new()
    if ($null -ne $Existing -and $null -ne $Existing.installedPacks) {
        foreach ($pack in @($Existing.installedPacks)) {
            $name = ([string]$pack).Trim().ToLowerInvariant()
            if ($name -and $Available -notcontains $name) {
                throw "Manifest references unavailable workflow pack '$name': $Path"
            }
            if ($name -and -not $existingPacks.Contains($name)) {
                $existingPacks.Add($name)
            }
        }
    }

    $installedPacks = [Collections.Generic.List[string]]::new()
    foreach ($pack in $Available) {
        if ($existingPacks.Contains($pack) -or $Selected -contains $pack) {
            $installedPacks.Add($pack)
        }
    }

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

    $oldPackSummary = if ($null -eq $Existing) { '' } else { @($Existing.installedPacks) -join ',' }
    $newPackSummary = @($installedPacks) -join ','
    $changed = ($null -eq $Existing) -or ($oldVersion -ne $Version) -or ($oldPackSummary -ne $newPackSummary)
    $updatedAt = if ($changed -or [string]::IsNullOrWhiteSpace($oldUpdatedAt)) { $now } else { $oldUpdatedAt }

    $manifest = [ordered]@{
        schemaVersion = 1
        managedBy = 'dev-workflow'
        workflowVersion = $Version
        installedPacks = @($installedPacks)
        installedAt = $installedAt
        updatedAt = $updatedAt
        onboarding = [ordered]@{
            status = $onboardingStatus
            lastAuditAt = $lastAuditAt
        }
    }

    [pscustomobject]@{
        Content = ($manifest | ConvertTo-Json -Depth 5)
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

$overlays = [Collections.Generic.List[object]]::new()
$overlays.Add([pscustomobject]@{ Name = 'core'; Root = $coreRoot })
foreach ($pack in $selectedPacks) {
    $overlays.Add([pscustomobject]@{ Name = $pack; Root = (Join-Path $packsRoot $pack) })
}

$coreTemplate = Join-Path $coreRoot 'AGENTS.md'
$coreBlock = Get-CoreBlock $coreTemplate
$manifestPlan = New-ManifestPlan -Path $manifestPath -Version $workflowVersion -Selected $selectedPacks -Available $availablePacks -Existing $existingManifest
$actions = [Collections.Generic.List[string]]::new()
$seenPaths = @{}

foreach ($overlay in $overlays) {
    $overlayPrefix = $overlay.Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $files = Get-ChildItem -LiteralPath $overlay.Root -Recurse -File | Sort-Object FullName

    foreach ($file in $files) {
        $relativePath = $file.FullName.Substring($overlayPrefix.Length)
        if ($seenPaths.ContainsKey($relativePath)) {
            throw "Overlay collision for '$relativePath': $($seenPaths[$relativePath]) and $($overlay.Name)"
        }
        $seenPaths[$relativePath] = $overlay.Name

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
            } elseif ($startCount -gt 0 -or $endCount -gt 0) {
                throw "Existing AGENTS.md contains incomplete or duplicate AI-WORKFLOW core markers: $targetPathResolved"
            } elseif ($DryRun) {
                $actions.Add("[append] $relativePath (preserved existing content; appended core block)")
            } else {
                $separator = if ($existing.EndsWith("`n") -or $existing.EndsWith("`r")) { "`n" } else { "`r`n`r`n" }
                Write-Utf8NoBom -Path $targetPathResolved -Content ($existing + $separator + $coreBlock + "`r`n")
                $actions.Add("[append] $relativePath (preserved existing content; appended core block)")
            }
            continue
        }

        if (Test-Path -LiteralPath $targetPathResolved -PathType Leaf) {
            $actions.Add("[skip] $relativePath (existing file was not overwritten)")
            continue
        }

        if ($DryRun) {
            $actions.Add("[create] $relativePath [$($overlay.Name)]")
            continue
        }

        $parent = Split-Path -Parent $targetPathResolved
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $targetPathResolved
        $actions.Add("[create] $relativePath [$($overlay.Name)]")
    }
}

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
