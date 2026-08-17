[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$installScript = Join-Path $repoRoot 'scripts/install.ps1'
$uninstallScript = Join-Path $repoRoot 'scripts/uninstall.ps1'
$auditScript = Join-Path $repoRoot 'scripts/audit.ps1'
$workflowVersion = (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw -Encoding UTF8).Trim()
$tempBase = [IO.Path]::GetTempPath()
$tempRoot = Join-Path $tempBase ("dev-workflow-integration-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $freshTarget = Join-Path $tempRoot 'fresh'
    New-Item -ItemType Directory -Path $freshTarget | Out-Null

    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $freshManifestPath = Join-Path $freshTarget '.dev-workflow/manifest.json'
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$manifest.schemaVersion -eq '2') 'new installs use manifest schema 2'
    Assert-True (@($manifest.files).Count -gt 20) 'new installs record a file ownership inventory'
    Assert-True (@($manifest.files | Where-Object action -eq 'created').Count -gt 20) 'new files record created ownership'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 大型计划拆分与确认门') 'Core install includes the large-plan approval gate'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/README.md') -Raw -Encoding UTF8) -match 'awaiting_user_confirmation') 'delivery plans expose the approval state'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -Raw -Encoding UTF8) -match '## 7\. 偏移控制') 'delivery plan template includes drift control'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/development/GIT-WORKTREE-WORKFLOW.md') -Raw -Encoding UTF8) -match 'codex/\*') 'delivery workflow protects local Codex branches'
    Assert-True (@($manifest.files | Where-Object { $_.path -eq 'scripts/feature_catalog.py' -and $_.source -eq 'feature-catalog' }).Count -eq 1) 'all-packs installs feature-catalog ownership'

    $pythonCommand = Get-Command python3 -ErrorAction SilentlyContinue
    if ($null -eq $pythonCommand) { $pythonCommand = Get-Command python -ErrorAction SilentlyContinue }
    Assert-True ($null -ne $pythonCommand) 'feature-catalog integration requires Python 3'
    $featureCatalogTool = Join-Path $freshTarget 'scripts/feature_catalog.py'
    & $pythonCommand.Name $featureCatalogTool --root $freshTarget --init | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'feature-catalog initializes project data'
    & $pythonCommand.Name $featureCatalogTool --root $freshTarget --generate | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'feature-catalog generates the matrix'
    & $pythonCommand.Name $featureCatalogTool --root $freshTarget --check | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'feature-catalog generated matrix is current'
    $activeCatalogPath = Join-Path $freshTarget 'docs/development/ai/feature-catalog.json'
    $catalogHashBeforeReinstall = (Get-FileHash -LiteralPath $activeCatalogPath -Algorithm SHA256).Hash
    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $catalogHashAfterReinstall = (Get-FileHash -LiteralPath $activeCatalogPath -Algorithm SHA256).Hash
    Assert-True ($catalogHashBeforeReinstall -eq $catalogHashAfterReinstall) 'reinstall does not overwrite active feature catalog'

    $firstUpdatedAt = [string]$manifest.updatedAt
    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$manifest.updatedAt -eq $firstUpdatedAt) 'idempotent reinstall preserves updatedAt'

    $powerShellExe = if ($PSVersionTable.PSEdition -eq 'Core') {
        Join-Path $PSHOME 'pwsh.exe'
    } else {
        Join-Path $PSHOME 'powershell.exe'
    }
    & $powerShellExe -NoProfile -File $auditScript -TargetPath $freshTarget *> $null
    Assert-True ($LASTEXITCODE -eq 2) 'a structurally valid pending install returns audit exit code 2'

    $manifest.onboarding.status = 'ready'
    $manifest.onboarding.lastAuditAt = '2026-01-01T00:00:00Z'
    Write-Utf8NoBom -Path $freshManifestPath -Content (($manifest | ConvertTo-Json -Depth 8) + "`n")
    Write-Utf8NoBom -Path (Join-Path $freshTarget 'docs/PROJECT-SUMMARY.md') -Content "# Project summary`n`nVerified project facts.`n"
    Write-Utf8NoBom -Path (Join-Path $freshTarget 'docs/WORKFLOW-ADOPTION.md') -Content "---`nworkflow: dev-workflow`nstatus: ready`nupdated: 2026-01-01`n---`n`n# Adoption`n`nVerified.`n"
    [IO.File]::AppendAllText((Join-Path $freshTarget 'docs/FEATURE-MATRIX.md'), "`nmanual matrix drift`n", [Text.UTF8Encoding]::new($false))
    & $powerShellExe -NoProfile -File $auditScript -TargetPath $freshTarget -Strict *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'strict audit rejects feature matrix drift'
    & $pythonCommand.Name $featureCatalogTool --root $freshTarget --generate | Out-Null
    Assert-True ($LASTEXITCODE -eq 0) 'feature-catalog regeneration repairs matrix drift'
    & $powerShellExe -NoProfile -File $auditScript -TargetPath $freshTarget -Strict *> $null
    Assert-True ($LASTEXITCODE -eq 0) 'a completed schema 2 install passes strict audit'

    $modifiedDeliveryFile = Join-Path $freshTarget 'docs/development/README.md'
    [IO.File]::AppendAllText($modifiedDeliveryFile, "`n项目自定义内容。`n", [Text.UTF8Encoding]::new($false))
    & $uninstallScript -TargetPath $freshTarget -Packs delivery -DryRun | Out-Null
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -PathType Leaf) 'dry-run does not delete files'

    & $uninstallScript -TargetPath $freshTarget -Packs delivery | Out-Null
    Assert-True (Test-Path -LiteralPath $modifiedDeliveryFile -PathType Leaf) 'modified managed files are preserved'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md'))) 'unchanged pack files are deleted'
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True (@($manifest.installedPacks) -notcontains 'delivery') 'partial uninstall removes the pack from manifest'
    Assert-True (@($manifest.files | Where-Object source -eq 'delivery').Count -eq 0) 'partial uninstall removes pack inventory entries'

    & $uninstallScript -TargetPath $freshTarget | Out-Null
    Assert-True (-not (Test-Path -LiteralPath $freshManifestPath)) 'full uninstall removes the manifest'
    Assert-True (Test-Path -LiteralPath $modifiedDeliveryFile -PathType Leaf) 'project-modified content remains after full uninstall'
    Assert-True (Test-Path -LiteralPath $activeCatalogPath -PathType Leaf) 'full uninstall preserves active feature catalog'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/FEATURE-MATRIX.md') -PathType Leaf) 'full uninstall preserves generated feature matrix'

    $featurePackTarget = Join-Path $tempRoot 'feature-pack'
    New-Item -ItemType Directory -Path $featurePackTarget | Out-Null
    & $installScript -TargetPath $featurePackTarget -Packs feature-catalog | Out-Null
    $featurePackManifestPath = Join-Path $featurePackTarget '.dev-workflow/manifest.json'
    $featurePackTool = Join-Path $featurePackTarget 'scripts/feature_catalog.py'
    & $pythonCommand.Name $featurePackTool --root $featurePackTarget --init | Out-Null
    & $pythonCommand.Name $featurePackTool --root $featurePackTarget --generate | Out-Null
    & $uninstallScript -TargetPath $featurePackTarget -Packs feature-catalog | Out-Null
    $featurePackManifest = Get-Content -LiteralPath $featurePackManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True (@($featurePackManifest.installedPacks).Count -eq 0) 'removing feature-catalog leaves a Core-only manifest'
    Assert-True (-not (Test-Path -LiteralPath $featurePackTool)) 'partial uninstall removes unchanged feature-catalog tool'
    Assert-True (Test-Path -LiteralPath (Join-Path $featurePackTarget 'docs/development/ai/feature-catalog.json') -PathType Leaf) 'partial uninstall preserves active feature catalog'
    Assert-True (Test-Path -LiteralPath (Join-Path $featurePackTarget 'docs/FEATURE-MATRIX.md') -PathType Leaf) 'partial uninstall preserves generated feature matrix'
    & $uninstallScript -TargetPath $featurePackTarget | Out-Null
    Assert-True (-not (Test-Path -LiteralPath $featurePackManifestPath)) 'full uninstall removes Core manifest after feature pack removal'
    Assert-True (Test-Path -LiteralPath (Join-Path $featurePackTarget 'docs/development/ai/feature-catalog.json') -PathType Leaf) 'Core uninstall still preserves active feature catalog'

    $existingTarget = Join-Path $tempRoot 'existing'
    New-Item -ItemType Directory -Path $existingTarget | Out-Null
    Write-Utf8NoBom -Path (Join-Path $existingTarget 'AGENTS.md') -Content "# Existing project rules`n"
    Write-Utf8NoBom -Path (Join-Path $existingTarget 'docs/TASKS.md') -Content "# Existing tasks`n"

    & $installScript -TargetPath $existingTarget | Out-Null
    $existingManifest = Get-Content -LiteralPath (Join-Path $existingTarget '.dev-workflow/manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True (($existingManifest.files | Where-Object path -eq 'AGENTS.md').action -eq 'appended') 'existing AGENTS.md records appended ownership'
    Assert-True (($existingManifest.files | Where-Object path -eq 'docs/TASKS.md').action -eq 'preserved') 'pre-existing files record preserved ownership'
    Assert-True ((Get-Content -LiteralPath (Join-Path $existingTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 大型计划拆分与确认门') 'existing AGENTS.md receives the large-plan approval gate'

    & $uninstallScript -TargetPath $existingTarget | Out-Null
    $remainingAgents = Get-Content -LiteralPath (Join-Path $existingTarget 'AGENTS.md') -Raw -Encoding UTF8
    Assert-True ($remainingAgents -match '# Existing project rules') 'existing AGENTS.md content is preserved'
    Assert-True ($remainingAgents -notmatch 'AI-WORKFLOW:CORE:START') 'managed AGENTS.md core block is removed'
    Assert-True (Test-Path -LiteralPath (Join-Path $existingTarget 'docs/TASKS.md') -PathType Leaf) 'pre-existing files survive uninstall'

    $blankAgentsTarget = Join-Path $tempRoot 'blank-agents'
    New-Item -ItemType Directory -Path $blankAgentsTarget | Out-Null
    Write-Utf8NoBom -Path (Join-Path $blankAgentsTarget 'AGENTS.md') -Content "`n"
    & $installScript -TargetPath $blankAgentsTarget | Out-Null
    & $uninstallScript -TargetPath $blankAgentsTarget | Out-Null
    Assert-True (Test-Path -LiteralPath (Join-Path $blankAgentsTarget 'AGENTS.md') -PathType Leaf) 'a pre-existing blank AGENTS.md is not deleted'

    $tamperedTarget = Join-Path $tempRoot 'tampered'
    New-Item -ItemType Directory -Path $tamperedTarget | Out-Null
    & $installScript -TargetPath $tamperedTarget | Out-Null
    $tamperedManifestPath = Join-Path $tamperedTarget '.dev-workflow/manifest.json'
    $tamperedManifest = Get-Content -LiteralPath $tamperedManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    ($tamperedManifest.files | Where-Object path -eq 'docs/TASKS.md').source = 'uninstalled-pack'
    Write-Utf8NoBom -Path $tamperedManifestPath -Content (($tamperedManifest | ConvertTo-Json -Depth 8) + "`n")

    & $powerShellExe -NoProfile -File $auditScript -TargetPath $tamperedTarget *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'audit rejects inventory assigned to an uninstalled pack'
    $installFailed = $false
    try { & $installScript -TargetPath $tamperedTarget | Out-Null } catch { $installFailed = $true }
    Assert-True $installFailed 'installer rejects inventory assigned to an uninstalled pack'
    $uninstallFailed = $false
    try { & $uninstallScript -TargetPath $tamperedTarget | Out-Null } catch { $uninstallFailed = $true }
    Assert-True $uninstallFailed 'uninstaller rejects inventory assigned to an uninstalled pack'
    Assert-True (Test-Path -LiteralPath (Join-Path $tamperedTarget 'docs/TASKS.md') -PathType Leaf) 'rejected uninstall leaves managed files untouched'

    $extraPathTarget = Join-Path $tempRoot 'extra-paths'
    New-Item -ItemType Directory -Path $extraPathTarget | Out-Null
    & $installScript -TargetPath $extraPathTarget -Packs architecture | Out-Null
    $extraCorePath = Join-Path $extraPathTarget 'USER-NOTES.md'
    $extraPackPath = Join-Path $extraPathTarget 'PACK-NOTES.md'
    Write-Utf8NoBom -Path $extraCorePath -Content "User-owned core note.`n"
    Write-Utf8NoBom -Path $extraPackPath -Content "User-owned pack note.`n"
    $extraManifestPath = Join-Path $extraPathTarget '.dev-workflow/manifest.json'
    $extraManifest = Get-Content -LiteralPath $extraManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $extraManifest.files = @($extraManifest.files) + @(
        [pscustomobject]@{ path = 'USER-NOTES.md'; source = 'core'; action = 'created'; installedSha256 = (Get-FileHash -LiteralPath $extraCorePath -Algorithm SHA256).Hash.ToLowerInvariant() },
        [pscustomobject]@{ path = 'PACK-NOTES.md'; source = 'architecture'; action = 'created'; installedSha256 = (Get-FileHash -LiteralPath $extraPackPath -Algorithm SHA256).Hash.ToLowerInvariant() }
    )
    Write-Utf8NoBom -Path $extraManifestPath -Content (($extraManifest | ConvertTo-Json -Depth 8) + "`n")

    & $powerShellExe -NoProfile -File $auditScript -TargetPath $extraPathTarget *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'audit rejects inventory paths outside their workflow overlays'
    $installFailed = $false
    try { & $installScript -TargetPath $extraPathTarget | Out-Null } catch { $installFailed = $true }
    Assert-True $installFailed 'installer rejects inventory paths outside their workflow overlays'
    $uninstallFailed = $false
    try { & $uninstallScript -TargetPath $extraPathTarget | Out-Null } catch { $uninstallFailed = $true }
    Assert-True $uninstallFailed 'uninstaller rejects inventory paths outside their workflow overlays'
    Assert-True (Test-Path -LiteralPath $extraCorePath -PathType Leaf) 'rejected uninstall preserves a forged Core-owned user file'
    Assert-True (Test-Path -LiteralPath $extraPackPath -PathType Leaf) 'rejected uninstall preserves a forged pack-owned user file'

    $forgedOwnershipTarget = Join-Path $tempRoot 'forged-ownership'
    New-Item -ItemType Directory -Path $forgedOwnershipTarget | Out-Null
    $forgedCorePath = Join-Path $forgedOwnershipTarget 'docs/TASKS.md'
    $forgedPackPath = Join-Path $forgedOwnershipTarget 'docs/architecture/SYSTEM.md'
    Write-Utf8NoBom -Path $forgedCorePath -Content "Pre-existing tasks.`n"
    Write-Utf8NoBom -Path $forgedPackPath -Content "Pre-existing architecture.`n"
    & $installScript -TargetPath $forgedOwnershipTarget -Packs architecture | Out-Null
    $forgedManifestPath = Join-Path $forgedOwnershipTarget '.dev-workflow/manifest.json'
    $forgedManifest = Get-Content -LiteralPath $forgedManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $forgedCoreEntry = $forgedManifest.files | Where-Object path -eq 'docs/TASKS.md'
    $forgedPackEntry = $forgedManifest.files | Where-Object path -eq 'docs/architecture/SYSTEM.md'
    Assert-True ($forgedCoreEntry.action -eq 'preserved') 'pre-existing Core files start as preserved'
    Assert-True ($forgedPackEntry.action -eq 'preserved') 'pre-existing pack files start as preserved'
    $forgedCoreEntry.action = 'created'
    $forgedCoreEntry.installedSha256 = (Get-FileHash -LiteralPath $forgedCorePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $forgedPackEntry.action = 'created'
    $forgedPackEntry.installedSha256 = (Get-FileHash -LiteralPath $forgedPackPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Utf8NoBom -Path $forgedManifestPath -Content (($forgedManifest | ConvertTo-Json -Depth 8) + "`n")

    & $powerShellExe -NoProfile -File $auditScript -TargetPath $forgedOwnershipTarget *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'audit rejects forged created ownership for real overlay paths'
    $installFailed = $false
    try { & $installScript -TargetPath $forgedOwnershipTarget | Out-Null } catch { $installFailed = $true }
    Assert-True $installFailed 'installer rejects forged created ownership for real overlay paths'
    $uninstallFailed = $false
    try { & $uninstallScript -TargetPath $forgedOwnershipTarget | Out-Null } catch { $uninstallFailed = $true }
    Assert-True $uninstallFailed 'uninstaller rejects forged created ownership for real overlay paths'
    Assert-True (Test-Path -LiteralPath $forgedCorePath -PathType Leaf) 'forged Core ownership cannot delete a pre-existing user file'
    Assert-True (Test-Path -LiteralPath $forgedPackPath -PathType Leaf) 'forged pack ownership cannot delete a pre-existing user file'

    $upgradeTarget = Join-Path $tempRoot 'schema2-upgrade'
    New-Item -ItemType Directory -Path $upgradeTarget | Out-Null
    & $installScript -TargetPath $upgradeTarget | Out-Null
    $upgradeManifestPath = Join-Path $upgradeTarget '.dev-workflow/manifest.json'
    $upgradeManifest = Get-Content -LiteralPath $upgradeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $upgradeManifest.workflowVersion = '0.1.9'
    ($upgradeManifest.files | Where-Object path -eq 'docs/TASKS.md').installedSha256 = ('0' * 64)
    Write-Utf8NoBom -Path $upgradeManifestPath -Content (($upgradeManifest | ConvertTo-Json -Depth 8) + "`n")
    & $installScript -TargetPath $upgradeTarget | Out-Null
    $upgradeManifest = Get-Content -LiteralPath $upgradeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $upgradedEntry = $upgradeManifest.files | Where-Object path -eq 'docs/TASKS.md'
    Assert-True ($upgradedEntry.action -eq 'legacy') 'changed created ownership becomes legacy during a version upgrade'
    Assert-True ($null -eq $upgradedEntry.installedSha256) 'legacy upgrade ownership clears the deletion hash'
    Assert-True ($upgradeManifest.workflowVersion -eq $workflowVersion) 'schema 2 upgrade records the current workflow version'

    $legacyTarget = Join-Path $tempRoot 'legacy'
    New-Item -ItemType Directory -Path $legacyTarget | Out-Null
    & $installScript -TargetPath $legacyTarget -Packs architecture | Out-Null
    $legacyManifestPath = Join-Path $legacyTarget '.dev-workflow/manifest.json'
    $legacyManifest = Get-Content -LiteralPath $legacyManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $legacyManifest.schemaVersion = 1
    $legacyManifest.PSObject.Properties.Remove('files')
    Write-Utf8NoBom -Path $legacyManifestPath -Content (($legacyManifest | ConvertTo-Json -Depth 6) + "`n")

    & $installScript -TargetPath $legacyTarget | Out-Null
    $migratedManifest = Get-Content -LiteralPath $legacyManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$migratedManifest.schemaVersion -eq '2') 'legacy manifests migrate to schema 2'
    Assert-True (($migratedManifest.files | Where-Object path -eq 'docs/architecture/SYSTEM.md').action -eq 'legacy') 'legacy pack files remain conservatively owned'

    Write-Output 'PowerShell integration tests passed.'
} finally {
    $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot)
    $resolvedTempBase = [IO.Path]::GetFullPath($tempBase)
    if ($resolvedTempRoot.StartsWith($resolvedTempBase, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTempRoot)) {
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
