[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [switch]$Strict
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

function Add-Error([Collections.Generic.List[string]]$Items, [string]$Message) {
    $Items.Add($Message)
}

function Add-Warning([Collections.Generic.List[string]]$Items, [string]$Message) {
    $Items.Add($Message)
}

$sourceRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$targetRoot = Resolve-FullPath $TargetPath
if (
    [StringComparer]::OrdinalIgnoreCase.Equals($sourceRoot, $targetRoot) -or
    (Test-IsWithin -Parent $sourceRoot -Candidate $targetRoot)
) {
    throw 'The target directory cannot be the dev-workflow distribution repository or one of its subdirectories.'
}

$errors = [Collections.Generic.List[string]]::new()
$warnings = [Collections.Generic.List[string]]::new()
$coreFiles = @(
    'AGENTS.md',
    'docs/README.md',
    'docs/TASKS.md',
    'docs/WORKING-CONTEXT.md',
    'docs/WORKFLOW-ADOPTION.md',
    'docs/PROJECT-SUMMARY.md',
    'docs/project-memory/README.md'
)

foreach ($relativePath in $coreFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $targetRoot $relativePath) -PathType Leaf)) {
        Add-Error $errors "Missing Core file: $relativePath"
    }
}

$agentsPath = Join-Path $targetRoot 'AGENTS.md'
if (Test-Path -LiteralPath $agentsPath -PathType Leaf) {
    $agents = Get-Content -LiteralPath $agentsPath -Raw -Encoding UTF8
    $startCount = ([regex]::Matches($agents, '<!-- AI-WORKFLOW:CORE:START -->')).Count
    $endCount = ([regex]::Matches($agents, '<!-- AI-WORKFLOW:CORE:END -->')).Count
    $hasValidCoreBlock = (
        $startCount -eq 1 -and
        $endCount -eq 1 -and
        $agents.IndexOf('<!-- AI-WORKFLOW:CORE:START -->') -lt $agents.IndexOf('<!-- AI-WORKFLOW:CORE:END -->')
    )
    if (-not $hasValidCoreBlock) {
        Add-Error $errors 'AGENTS.md must contain exactly one complete AI-WORKFLOW core marker pair.'
    }
}

$manifestPath = Join-Path $targetRoot '.dev-workflow/manifest.json'
$manifest = $null
$manifestStatus = 'missing'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    Add-Error $errors 'Missing .dev-workflow/manifest.json; run the installer again.'
} else {
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Add-Error $errors 'manifest.json is not valid JSON.'
    }

    if ($null -ne $manifest) {
        if ($manifest.managedBy -ne 'dev-workflow') {
            Add-Error $errors 'manifest.json is not managed by dev-workflow.'
        }
        if (([string]$manifest.schemaVersion) -ne '1') {
            Add-Error $errors 'manifest.json uses an unsupported schemaVersion.'
        }
        if (([string]$manifest.workflowVersion) -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
            Add-Error $errors "Invalid manifest workflowVersion: $($manifest.workflowVersion)"
        }
        $manifestStatus = [string]$manifest.onboarding.status
        if ($manifestStatus -notin @('pending', 'ready', 'blocked')) {
            Add-Error $errors "Invalid manifest onboarding.status: $manifestStatus"
        }
        if ($manifestStatus -eq 'ready' -and [string]::IsNullOrWhiteSpace([string]$manifest.onboarding.lastAuditAt)) {
            Add-Warning $warnings 'Ready onboarding state has no recorded onboarding.lastAuditAt timestamp.'
        }

        $sourceVersionPath = Join-Path $sourceRoot 'VERSION'
        $sourceVersion = (Get-Content -LiteralPath $sourceVersionPath -Raw -Encoding UTF8).Trim()
        if ($manifest.workflowVersion -ne $sourceVersion) {
            Add-Warning $warnings "Manifest version $($manifest.workflowVersion) differs from distribution version $sourceVersion; run the installer in dry-run mode before upgrading."
        }

        $packNames = @()
        $installedPacksProperty = $manifest.PSObject.Properties['installedPacks']
        if ($null -eq $installedPacksProperty) {
            Add-Error $errors 'manifest.json is missing installedPacks.'
        } elseif (
            $null -ne $installedPacksProperty.Value -and
            ($installedPacksProperty.Value -is [string] -or $installedPacksProperty.Value -isnot [Collections.IEnumerable])
        ) {
            Add-Error $errors 'manifest installedPacks must be an array.'
        } else {
            $packNames = @($installedPacksProperty.Value | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
        }
        $duplicatePacks = @($packNames | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
        foreach ($pack in $duplicatePacks) {
            Add-Error $errors "manifest installedPacks contains a duplicate: $pack"
        }
        foreach ($pack in $packNames) {
            $packRoot = Join-Path $sourceRoot "packs/$pack"
            if (-not (Test-Path -LiteralPath $packRoot -PathType Container)) {
                Add-Error $errors "Manifest references an unavailable workflow pack: $pack"
                continue
            }
            $overlayPrefix = $packRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
            foreach ($sourceFile in Get-ChildItem -LiteralPath $packRoot -Recurse -File) {
                $relativePath = $sourceFile.FullName.Substring($overlayPrefix.Length).Replace('\', '/')
                if (-not (Test-Path -LiteralPath (Join-Path $targetRoot $relativePath) -PathType Leaf)) {
                    Add-Error $errors "Workflow pack $pack is missing file: $relativePath"
                }
            }
        }
    }
}

$adoptionPath = Join-Path $targetRoot 'docs/WORKFLOW-ADOPTION.md'
$adoptionStatus = 'missing'
if (Test-Path -LiteralPath $adoptionPath -PathType Leaf) {
    $adoption = Get-Content -LiteralPath $adoptionPath -Raw -Encoding UTF8
    $statusMatch = [regex]::Match($adoption, '(?m)^status:\s*(pending|ready|blocked)\s*$')
    if ($statusMatch.Success) {
        $adoptionStatus = $statusMatch.Groups[1].Value
    } else {
        Add-Error $errors 'WORKFLOW-ADOPTION.md is missing a valid status.'
    }
    if ($adoptionStatus -eq 'ready' -and $adoption -match '(?m)^- \[ \] ') {
        Add-Warning $warnings 'WORKFLOW-ADOPTION.md is ready but still contains unchecked onboarding items.'
    }
} else {
    Add-Error $errors 'Missing docs/WORKFLOW-ADOPTION.md.'
}

if ($manifestStatus -ne 'missing' -and $adoptionStatus -ne 'missing' -and $manifestStatus -ne $adoptionStatus) {
    Add-Error $errors "Manifest and WORKFLOW-ADOPTION status differ: $manifestStatus / $adoptionStatus"
}

$contextPath = Join-Path $targetRoot 'docs/WORKING-CONTEXT.md'
if (Test-Path -LiteralPath $contextPath -PathType Leaf) {
    $context = Get-Content -LiteralPath $contextPath -Raw -Encoding UTF8
    $contextMatch = [regex]::Match($context, '(?m)^status:\s*(active|inactive)\s*$')
    if (-not $contextMatch.Success) {
        Add-Error $errors 'WORKING-CONTEXT.md is missing a valid active/inactive status.'
    }
}

$initializationFiles = @('docs/PROJECT-SUMMARY.md', 'docs/WORKFLOW-ADOPTION.md')
foreach ($relativePath in $initializationFiles) {
    $path = Join-Path $targetRoot $relativePath
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        if ($content -match 'YYYY-MM-DD|\u5F85\u521D\u59CB\u5316|<!--\s*(\u586B\u5199|path|command|repo/path)') {
            Add-Warning $warnings "Onboarding placeholders remain in: $relativePath"
        }
    }
}

Write-Output 'dev-workflow audit'
Write-Output "target: $targetRoot"
if ($null -ne $manifest) {
    Write-Output "workflowVersion: $($manifest.workflowVersion)"
    Write-Output "installedPacks: $(@($manifest.installedPacks) -join ', ')"
    Write-Output "onboarding: $manifestStatus"
}
foreach ($message in $errors) { Write-Output "[error] $message" }
foreach ($message in $warnings) { Write-Output "[warn] $message" }

if ($errors.Count -gt 0) {
    Write-Output 'result: invalid'
    exit 1
}
if ($manifestStatus -eq 'pending' -or $adoptionStatus -eq 'pending') {
    Write-Output 'result: pending (complete project onboarding before coding against project facts)'
    exit 2
}
if ($manifestStatus -eq 'blocked' -or $adoptionStatus -eq 'blocked') {
    Write-Output 'result: blocked (resolve onboarding blockers, then run the audit again)'
    exit 2
}
if ($Strict -and $warnings.Count -gt 0) {
    Write-Output 'result: warning (strict mode treats warnings as failure)'
    exit 1
}

Write-Output 'result: ready'
exit 0
