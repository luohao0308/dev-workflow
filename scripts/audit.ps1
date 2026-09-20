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

function ConvertTo-GitExcludeLiteral([string]$Value) {
    if ($Value.IndexOf("`r") -ge 0 -or $Value.IndexOf("`n") -ge 0) {
        throw 'Git exclude paths cannot contain line breaks.'
    }
    $builder = [Text.StringBuilder]::new()
    foreach ($character in $Value.ToCharArray()) {
        if ('\ #![]*?'.IndexOf([string]$character) -ge 0) {
            [void]$builder.Append('\')
        }
        [void]$builder.Append($character)
    }
    return $builder.ToString()
}

function Check-GitExcludeBlock(
    [string]$TargetRoot,
    [hashtable]$InventoryActions,
    [string[]]$InventoryPaths,
    [Collections.Generic.List[string]]$Warnings
) {
    if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) { return }
    $repoRootOutput = @(& git -C $TargetRoot rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or $repoRootOutput.Count -eq 0) { return }
    $gitPathOutput = @(& git -C $TargetRoot rev-parse --git-path info/exclude 2>$null)
    if ($LASTEXITCODE -ne 0 -or $gitPathOutput.Count -eq 0) { return }
    $gitPath = ($gitPathOutput -join "`n").Trim()
    $excludePath = if ([IO.Path]::IsPathRooted($gitPath)) { $gitPath } else { [IO.Path]::GetFullPath((Join-Path $TargetRoot $gitPath)) }
    if (-not (Test-Path -LiteralPath $excludePath -PathType Leaf)) {
        Add-Warning $Warnings "Git info/exclude is missing the dev-workflow managed block: $excludePath"
        return
    }
    $lines = @(Get-Content -LiteralPath $excludePath -Encoding UTF8)
    $begin = '# BEGIN dev-workflow managed excludes'
    $end = '# END dev-workflow managed excludes'
    $beginIndexes = @()
    $endIndexes = @()
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -eq $begin) { $beginIndexes += $index }
        if ($lines[$index] -eq $end) { $endIndexes += $index }
    }
    if ($beginIndexes.Count -ne 1 -or $endIndexes.Count -ne 1 -or $beginIndexes[0] -ge $endIndexes[0]) {
        Add-Warning $Warnings "Git info/exclude contains an incomplete, duplicate, or misordered dev-workflow managed block: $excludePath"
        return
    }
    $inside = $false
    $managed = [Collections.Generic.HashSet[string]]::new()
    foreach ($line in $lines) {
        if ($line -eq $begin) { $inside = $true; continue }
        if ($line -eq $end) { $inside = $false; continue }
        if ($inside) { [void]$managed.Add([string]$line) }
    }
    $prefixOutput = @(& git -C $TargetRoot rev-parse --show-prefix 2>$null)
    if ($LASTEXITCODE -ne 0) { return }
    $prefix = ($prefixOutput -join "`n").Trim().TrimEnd('/')
    $prefixValue = if ($prefix) { "/$(ConvertTo-GitExcludeLiteral $prefix)" } else { '' }
    $expected = [Collections.Generic.List[string]]::new()
    $expected.Add("$prefixValue/.dev-workflow/")
    & git -C $TargetRoot check-ignore --no-index -q -- '.dev-workflow/manifest.json'
    if ($LASTEXITCODE -ne 0) {
        Add-Warning $Warnings 'Git final ignore rules do not exclude dev-workflow metadata: .dev-workflow/manifest.json'
    }
    $metadataPrefix = if ($prefix) { "$prefix/.dev-workflow/" } else { '.dev-workflow/' }
    $trackedMetadata = @(& git -C (($repoRootOutput -join "`n").Trim()) ls-files -- ":(literal)$metadataPrefix" 2>$null)
    if ($trackedMetadata.Count -gt 0) {
        Add-Warning $Warnings 'Git already tracks dev-workflow metadata; info/exclude cannot prevent upload: .dev-workflow/'
    }
    foreach ($path in $InventoryPaths) {
        $action = [string]$InventoryActions[$path]
        if ($action -eq 'created') {
            $expected.Add("$prefixValue/$(ConvertTo-GitExcludeLiteral $path)")
            & git -C $TargetRoot check-ignore --no-index -q -- $path
            if ($LASTEXITCODE -ne 0) {
                Add-Warning $Warnings "Git final ignore rules do not exclude a dev-workflow file: $path"
            }
        }
        if ($action -in @('created', 'appended', 'managed-block')) {
            $repoRelative = if ($prefix) { "$prefix/$path" } else { $path }
            & git -C (($repoRootOutput -join "`n").Trim()) ls-files --error-unmatch -- ":(literal)$repoRelative" *> $null
            if ($LASTEXITCODE -eq 0) {
                Add-Warning $Warnings "Git already tracks a file containing dev-workflow content; info/exclude cannot prevent upload: $path"
            }
        }
    }
    foreach ($pattern in $expected) {
        if (-not $managed.Contains($pattern)) {
            Add-Warning $Warnings "Git info/exclude is missing a dev-workflow exclusion: $pattern"
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

$coreSourcePath = Join-Path $sourceRoot 'core/AGENTS.md'
$coreSourceContent = if (Test-Path -LiteralPath $coreSourcePath -PathType Leaf) {
    Get-Content -LiteralPath $coreSourcePath -Raw -Encoding UTF8
} else { '' }
if ($coreSourceContent -notmatch '## 大型计划拆分与确认门' -or $coreSourceContent -notmatch 'awaiting_user_confirmation') {
    Add-Error $errors 'Distribution Core is missing the large-plan decomposition approval contract.'
}
if ($coreSourceContent -notmatch '## Git 交付权限策略' -or $coreSourceContent -notmatch 'gitPolicy') {
    Add-Error $errors 'Distribution Core is missing the Git delivery permission policy contract.'
}
$deliveryReadmeSource = Join-Path $sourceRoot 'packs/delivery/docs/plans/README.md'
$deliveryTemplateSource = Join-Path $sourceRoot 'packs/delivery/docs/plans/TEMPLATE.md'
$deliveryReadmeContent = if (Test-Path -LiteralPath $deliveryReadmeSource -PathType Leaf) {
    Get-Content -LiteralPath $deliveryReadmeSource -Raw -Encoding UTF8
} else { '' }
if ($deliveryReadmeContent -notmatch '大型计划确认门') {
    Add-Error $errors 'Distribution delivery plan index is missing the large-plan approval contract.'
}
$deliveryTemplateContent = if (Test-Path -LiteralPath $deliveryTemplateSource -PathType Leaf) {
    Get-Content -LiteralPath $deliveryTemplateSource -Raw -Encoding UTF8
} else { '' }
if ($deliveryTemplateContent -notmatch 'awaiting_user_confirmation' -or $deliveryTemplateContent -notmatch '## 7\. 偏移控制') {
    Add-Error $errors 'Distribution delivery plan template is missing confirmation or drift-control fields.'
}

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
    if ($agents -notmatch '## Git 交付权限策略') {
        Add-Warning $warnings 'AGENTS.md has not merged the Git delivery permission policy; upgraded projects must merge the current Core block.'
    }
}

$manifestPath = Join-Path $targetRoot '.dev-workflow/manifest.json'
$manifest = $null
$manifestStatus = 'missing'
$schemaVersion = ''
$inventoryPaths = @{}
$inventoryActions = @{}
$inventoryHashes = @{}
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
        $schemaVersion = [string]$manifest.schemaVersion
        if ($schemaVersion -notin @('1', '2', '3')) {
            Add-Error $errors 'manifest.json uses an unsupported schemaVersion.'
        } elseif ($schemaVersion -eq '1') {
            Add-Warning $warnings 'manifest.json uses legacy schemaVersion 1; reinstall with the current distribution to add safe uninstall ownership metadata.'
        } elseif ($schemaVersion -eq '2') {
            Add-Warning $warnings 'manifest.json uses legacy schemaVersion 2; reinstall with the current distribution and confirm Git delivery permissions.'
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
        if ($null -eq $manifest.gitPolicy) {
            if ($schemaVersion -eq '3') {
                Add-Error $errors 'schemaVersion 3 manifest is missing gitPolicy.'
            } else {
                Add-Warning $warnings 'manifest.json is missing gitPolicy; rerun the current installer to confirm push/merge policy.'
            }
        } else {
            $pushMode = ([string]$manifest.gitPolicy.pushMode).Trim().ToLowerInvariant()
            $pushActor = ([string]$manifest.gitPolicy.pushActor).Trim().ToLowerInvariant()
            $mergeMode = ([string]$manifest.gitPolicy.mergeMode).Trim().ToLowerInvariant()
            $mergeActor = ([string]$manifest.gitPolicy.mergeActor).Trim().ToLowerInvariant()
            if ($pushMode -notin @('manual', 'auto')) { Add-Error $errors "Invalid manifest gitPolicy.pushMode: $pushMode" }
            if ($pushActor -notin @('user', 'ai')) { Add-Error $errors "Invalid manifest gitPolicy.pushActor: $pushActor" }
            if ($mergeMode -notin @('manual', 'auto')) { Add-Error $errors "Invalid manifest gitPolicy.mergeMode: $mergeMode" }
            if ($mergeActor -notin @('user', 'ai')) { Add-Error $errors "Invalid manifest gitPolicy.mergeActor: $mergeActor" }
            if ($pushMode -eq 'auto' -and $pushActor -ne 'ai') { Add-Error $errors 'manifest gitPolicy push auto mode requires actor ai.' }
            if ($mergeMode -eq 'auto' -and $mergeActor -ne 'ai') { Add-Error $errors 'manifest gitPolicy merge auto mode requires actor ai.' }
            if ($manifest.gitPolicy.deleteAllowed -ne $false) { Add-Error $errors 'manifest gitPolicy.deleteAllowed must be false.' }
        }

        $sourceVersionPath = Join-Path $sourceRoot 'VERSION'
        $sourceVersion = (Get-Content -LiteralPath $sourceVersionPath -Raw -Encoding UTF8).Trim()
        if ($manifest.workflowVersion -ne $sourceVersion) {
            Add-Warning $warnings "Manifest version $($manifest.workflowVersion) differs from distribution version $sourceVersion; run the installer in dry-run mode before upgrading."
        }

        if ($schemaVersion -in @('2', '3')) {
            $filesProperty = $manifest.PSObject.Properties['files']
            if (
                $null -eq $filesProperty -or
                $null -eq $filesProperty.Value -or
                $filesProperty.Value -is [string] -or
                $filesProperty.Value -isnot [Collections.IEnumerable]
            ) {
                Add-Error $errors "manifest schemaVersion $schemaVersion requires a files array."
            } else {
                foreach ($entry in @($filesProperty.Value)) {
                    $entryPath = ([string]$entry.path).Replace('\', '/')
                    $entrySource = ([string]$entry.source).Trim().ToLowerInvariant()
                    $action = ([string]$entry.action).Trim().ToLowerInvariant()
                    $hash = ([string]$entry.installedSha256).Trim().ToLowerInvariant()
                    if ([string]::IsNullOrWhiteSpace($entryPath) -or [IO.Path]::IsPathRooted($entryPath) -or $entryPath -match '(^|/)\.\.(/|$)') {
                        Add-Error $errors 'manifest files contains an unsafe or empty path.'
                        continue
                    }
                    if ($inventoryPaths.ContainsKey($entryPath)) {
                        Add-Error $errors "manifest files contains a duplicate path: $entryPath"
                        continue
                    }
                    if ([string]::IsNullOrWhiteSpace($entrySource)) {
                        Add-Error $errors "manifest files contains an empty source for: $entryPath"
                    }
                    if ($action -notin @('created', 'appended', 'managed-block', 'preserved', 'legacy')) {
                        Add-Error $errors "manifest files contains an invalid action for ${entryPath}: $action"
                    }
                    if ($action -eq 'created' -and $hash -notmatch '^[0-9a-f]{64}$') {
                        Add-Error $errors "manifest files contains an invalid installedSha256 for: $entryPath"
                    }
                    if ($action -ne 'created' -and -not [string]::IsNullOrWhiteSpace($hash)) {
                        Add-Error $errors "manifest files contains an unexpected installedSha256 for: $entryPath"
                    }
                    $inventoryPaths[$entryPath] = $entrySource
                    $inventoryActions[$entryPath] = $action
                    $inventoryHashes[$entryPath] = $hash
                }
            }
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
        if ($schemaVersion -in @('2', '3')) {
            foreach ($entryPath in $inventoryPaths.Keys) {
                $entrySource = $inventoryPaths[$entryPath]
                if ($entrySource -ne 'core' -and $packNames -notcontains $entrySource) {
                    Add-Error $errors "Manifest file '$entryPath' belongs to uninstalled workflow pack '$entrySource'."
                    continue
                }
                $ownerRoot = if ($entrySource -eq 'core') {
                    Join-Path $sourceRoot 'core'
                } else {
                    Join-Path $sourceRoot "packs/$entrySource"
                }
                if (-not (Test-Path -LiteralPath (Join-Path $ownerRoot $entryPath) -PathType Leaf)) {
                    Add-Error $errors "Manifest file '$entryPath' does not belong to workflow source '$entrySource'."
                } elseif (
                    $inventoryActions[$entryPath] -eq 'created' -and
                    $manifest.workflowVersion -eq $sourceVersion
                ) {
                    $sourceHash = (Get-FileHash -LiteralPath (Join-Path $ownerRoot $entryPath) -Algorithm SHA256).Hash.ToLowerInvariant()
                    if ($inventoryHashes[$entryPath] -ne $sourceHash) {
                        Add-Error $errors "Manifest created-file hash does not match workflow source for '$entryPath'."
                    }
                }
            }
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
                if ($schemaVersion -in @('2', '3') -and -not $inventoryPaths.ContainsKey($relativePath)) {
                    Add-Error $errors "Manifest ownership inventory is missing workflow pack file: $relativePath"
                } elseif ($schemaVersion -in @('2', '3') -and $inventoryPaths[$relativePath] -ne $pack) {
                    Add-Error $errors "Manifest ownership inventory assigns '$relativePath' to '$($inventoryPaths[$relativePath])' instead of '$pack'."
                }
            }
        }

        if ($schemaVersion -in @('2', '3')) {
            foreach ($relativePath in $coreFiles) {
                if (-not $inventoryPaths.ContainsKey($relativePath)) {
                    Add-Error $errors "Manifest ownership inventory is missing Core file: $relativePath"
                } elseif ($inventoryPaths[$relativePath] -ne 'core') {
                    Add-Error $errors "Manifest ownership inventory assigns Core file '$relativePath' to '$($inventoryPaths[$relativePath])'."
                }
            }
        }
    }
}

$auditInventoryPaths = if ($null -ne $manifest -and $schemaVersion -in @('2', '3')) {
    @($inventoryPaths.Keys)
} else {
    @()
}
Check-GitExcludeBlock `
    -TargetRoot $targetRoot `
    -InventoryActions $inventoryActions `
    -InventoryPaths $auditInventoryPaths `
    -Warnings $warnings

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

function Add-FeatureCatalogIssue([string]$Message) {
    if ($manifestStatus -eq 'ready' -and $adoptionStatus -eq 'ready') {
        Add-Error $errors $Message
    } else {
        Add-Warning $warnings $Message
    }
}

$featureCatalogInstalled = $false
if ($null -ne $manifest) {
    $featureCatalogInstalled = @($manifest.installedPacks) -contains 'feature-catalog'
}
if ($featureCatalogInstalled) {
    $featureCatalogTool = Join-Path $targetRoot 'scripts/feature_catalog.py'
    $featureCatalogPath = Join-Path $targetRoot 'docs/development/ai/feature-catalog.json'
    $featureMatrixPath = Join-Path $targetRoot 'docs/FEATURE-MATRIX.md'
    $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) {
        $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path -LiteralPath $featureCatalogPath -PathType Leaf)) {
        Add-FeatureCatalogIssue 'feature-catalog active catalog is missing; run python3 scripts/feature_catalog.py --init.'
    } elseif (-not (Test-Path -LiteralPath $featureMatrixPath -PathType Leaf)) {
        Add-FeatureCatalogIssue 'feature-catalog generated matrix is missing; run python3 scripts/feature_catalog.py --generate.'
    } elseif ($null -eq $pythonCommand) {
        Add-FeatureCatalogIssue 'feature-catalog requires Python 3 for validation and drift checks.'
    } elseif (-not (Test-Path -LiteralPath $featureCatalogTool -PathType Leaf)) {
        Add-FeatureCatalogIssue 'feature-catalog validator script is missing from the target project.'
    } else {
        & $pythonCommand.Name $featureCatalogTool --check *> $null
        if ($LASTEXITCODE -ne 0) {
            Add-FeatureCatalogIssue 'feature-catalog validation or generated-matrix drift check failed.'
        }
    }
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
