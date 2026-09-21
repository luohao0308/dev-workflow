[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$env:DEV_WORKFLOW_NON_INTERACTIVE = '1'

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
$installParameters = (Get-Command $installScript).Parameters.Keys
$powerShellExe = if ($PSVersionTable.PSEdition -eq 'Core') {
    Join-Path $PSHOME 'pwsh.exe'
} else {
    Join-Path $PSHOME 'powershell.exe'
}
Assert-True (@($installParameters | Where-Object { $_ -match 'delete' }).Count -eq 0) 'installer does not expose a delete permission option'
$tempBase = [IO.Path]::GetTempPath()
$tempRoot = Join-Path $tempBase ("dev-workflow-integration-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $freshTarget = Join-Path $tempRoot 'fresh'
    New-Item -ItemType Directory -Path $freshTarget | Out-Null
    & git -C $freshTarget init -q | Out-Null
    Add-Content -LiteralPath (Join-Path $freshTarget '.git/info/exclude') -Value @('# user exclude', '/user-local-only/') -Encoding UTF8
    Write-Utf8NoBom -Path (Join-Path $freshTarget '.gitignore') -Content "/project-local-only/`n"
    $gitignoreHashBeforeInstall = (Get-FileHash -LiteralPath (Join-Path $freshTarget '.gitignore') -Algorithm SHA256).Hash

    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $freshManifestPath = Join-Path $freshTarget '.dev-workflow/manifest.json'
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$manifest.schemaVersion -eq '3') 'new installs use manifest schema 3'
    Assert-True ([string]$manifest.gitPolicy.pushMode -eq 'manual') 'push defaults to manual approval'
    Assert-True ([string]$manifest.gitPolicy.pushActor -eq 'user') 'push defaults to user execution'
    Assert-True ([string]$manifest.gitPolicy.mergeMode -eq 'manual') 'merge defaults to manual approval'
    Assert-True ([string]$manifest.gitPolicy.mergeActor -eq 'user') 'merge defaults to user execution'
    Assert-True ($manifest.gitPolicy.deleteAllowed -eq $false) 'delete is always denied'
    Assert-True (@($manifest.files).Count -gt 20) 'new installs record a file ownership inventory'
    Assert-True (@($manifest.files | Where-Object action -eq 'created').Count -gt 20) 'new files record created ownership'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 大型计划拆分与确认门') 'Core install includes the large-plan approval gate'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 默认开发闭环（轻量核心 \+ 风险插件）') 'Core install includes the lightweight development loop'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## Git 交付权限策略') 'Core install includes the Git delivery permission policy'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '一次性人工授权') 'Core install permits explicit one-time AI push or merge authorization'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/README.md') -Raw -Encoding UTF8) -match 'awaiting_user_confirmation') 'delivery plans expose the approval state'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -Raw -Encoding UTF8) -match '## 7\. 偏移控制') 'delivery plan template includes drift control'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -Raw -Encoding UTF8) -match 'Test/Eval/Check') 'delivery plan template maps claims to executable checks'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/development/GIT-WORKTREE-WORKFLOW.md') -Raw -Encoding UTF8) -match 'codex/\*') 'delivery workflow protects local Codex branches'
    Assert-True (@($manifest.files | Where-Object { $_.path -eq 'scripts/feature_catalog.py' -and $_.source -eq 'feature-catalog' }).Count -eq 1) 'all-packs installs feature-catalog ownership'
    $freshExcludePath = Join-Path $freshTarget '.git/info/exclude'
    $freshExclude = Get-Content -LiteralPath $freshExcludePath -Raw -Encoding UTF8
    Assert-True ($freshExclude -match '# BEGIN dev-workflow managed excludes') 'install adds a managed Git exclude block'
    Assert-True ($freshExclude -match '/\.dev-workflow/') 'Git exclude hides dev-workflow metadata'
    Assert-True ($freshExclude -match '/docs/README\.md') 'Git exclude hides a created Core file'
    Assert-True ($freshExclude -match '# user exclude') 'install preserves user Git excludes'
    & git -C $freshTarget check-ignore -q -- .dev-workflow/manifest.json
    Assert-True ($LASTEXITCODE -eq 0) 'Git check-ignore matches dev-workflow metadata'
    & git -C $freshTarget check-ignore -q -- docs/README.md
    Assert-True ($LASTEXITCODE -eq 0) 'Git check-ignore matches created workflow files'
    foreach ($entry in @($manifest.files | Where-Object action -eq 'created')) {
        & git -C $freshTarget check-ignore -q -- ([string]$entry.path)
        Assert-True ($LASTEXITCODE -eq 0) "Git excludes installer-created path: $($entry.path)"
    }
    Assert-True ($gitignoreHashBeforeInstall -eq (Get-FileHash -LiteralPath (Join-Path $freshTarget '.gitignore') -Algorithm SHA256).Hash) 'install does not modify project .gitignore'

    $automatedGitTarget = Join-Path $tempRoot 'automated-git'
    New-Item -ItemType Directory -Path $automatedGitTarget | Out-Null
    & $installScript `
        -TargetPath $automatedGitTarget `
        -PushMode auto `
        -PushActor ai `
        -MergeMode auto `
        -MergeActor ai | Out-Null
    $automatedGitManifest = Get-Content -LiteralPath (Join-Path $automatedGitTarget '.dev-workflow/manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$automatedGitManifest.gitPolicy.pushMode -eq 'auto') 'explicit push automation is recorded'
    Assert-True ([string]$automatedGitManifest.gitPolicy.pushActor -eq 'ai') 'explicit AI push actor is recorded'
    Assert-True ([string]$automatedGitManifest.gitPolicy.mergeMode -eq 'auto') 'explicit merge automation is recorded'
    Assert-True ([string]$automatedGitManifest.gitPolicy.mergeActor -eq 'ai') 'explicit AI merge actor is recorded'
    Assert-True ($automatedGitManifest.gitPolicy.deleteAllowed -eq $false) 'delete remains denied when Git automation is enabled'
    & $installScript -TargetPath $automatedGitTarget | Out-Null
    $automatedGitManifest = Get-Content -LiteralPath (Join-Path $automatedGitTarget '.dev-workflow/manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$automatedGitManifest.gitPolicy.pushMode -eq 'auto') 'reinstall preserves explicit push automation'
    Assert-True ([string]$automatedGitManifest.gitPolicy.mergeMode -eq 'auto') 'reinstall preserves explicit merge automation'

    $invalidGitTarget = Join-Path $tempRoot 'invalid-git'
    New-Item -ItemType Directory -Path $invalidGitTarget | Out-Null
    $invalidGitFailed = $false
    try {
        & $installScript -TargetPath $invalidGitTarget -PushMode auto -PushActor user | Out-Null
    } catch {
        $invalidGitFailed = $true
    }
    Assert-True $invalidGitFailed 'automatic push with a user actor is rejected'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $invalidGitTarget '.dev-workflow/manifest.json'))) 'invalid Git policy does not write a manifest'

    $dryRunGitTarget = Join-Path $tempRoot 'dry-run-git'
    New-Item -ItemType Directory -Path $dryRunGitTarget | Out-Null
    & git -C $dryRunGitTarget init -q | Out-Null
    Add-Content -LiteralPath (Join-Path $dryRunGitTarget '.git/info/exclude') -Value '# dry-run user exclude' -Encoding UTF8
    $dryRunExcludePath = Join-Path $dryRunGitTarget '.git/info/exclude'
    $dryRunExcludeHash = (Get-FileHash -LiteralPath $dryRunExcludePath -Algorithm SHA256).Hash
    & $installScript -TargetPath $dryRunGitTarget -AllPacks -DryRun | Out-Null
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $dryRunGitTarget '.dev-workflow/manifest.json'))) 'install dry-run does not write the manifest'
    Assert-True ($dryRunExcludeHash -eq (Get-FileHash -LiteralPath $dryRunExcludePath -Algorithm SHA256).Hash) 'install dry-run does not modify Git exclude'

    $trackedTarget = Join-Path $tempRoot 'tracked'
    New-Item -ItemType Directory -Path $trackedTarget | Out-Null
    & git -C $trackedTarget init -q | Out-Null
    Write-Utf8NoBom -Path (Join-Path $trackedTarget 'AGENTS.md') -Content "# Existing tracked project rules`n"
    & git -C $trackedTarget add AGENTS.md
    $trackedInstallWarnings = @(& $installScript -TargetPath $trackedTarget 3>&1 | ForEach-Object { $_.ToString() })
    Assert-True (($trackedInstallWarnings -join "`n") -match 'info/exclude cannot prevent upload: AGENTS\.md') 'install warns when a tracked file receives dev-workflow content'
    $trackedExclude = Get-Content -LiteralPath (Join-Path $trackedTarget '.git/info/exclude') -Raw -Encoding UTF8
    Assert-True ($trackedExclude -notmatch '(?m)^/AGENTS\.md$') 'install does not hide an existing tracked project file as a whole'
    & git -C $trackedTarget add -f .dev-workflow/manifest.json
    $trackedReinstallWarnings = @(& $installScript -TargetPath $trackedTarget 3>&1 | ForEach-Object { $_.ToString() })
    Assert-True (($trackedReinstallWarnings -join "`n") -match 'info/exclude cannot prevent upload: \.dev-workflow/') 'install warns when Git already tracks dev-workflow metadata'
    $trackedAuditOutput = @(& $powerShellExe -NoProfile -File $auditScript -TargetPath $trackedTarget 2>&1 | ForEach-Object { $_.ToString() })
    $trackedAuditCode = $LASTEXITCODE
    Assert-True ($trackedAuditCode -eq 2) 'tracked-file audit still reports the pending onboarding state'
    Assert-True (($trackedAuditOutput -join "`n") -match 'info/exclude cannot prevent upload: AGENTS\.md') 'audit warns when Git tracks a file containing dev-workflow content'
    Assert-True (($trackedAuditOutput -join "`n") -match 'info/exclude cannot prevent upload: \.dev-workflow/') 'audit warns when Git tracks dev-workflow metadata'

    $specialRepo = Join-Path $tempRoot 'special-repo'
    $specialRelative = '[local] space#bang!star*question?'
    $specialTarget = Join-Path $specialRepo $specialRelative
    New-Item -ItemType Directory -Path $specialTarget -Force | Out-Null
    & git -C $specialRepo init -q | Out-Null
    & $installScript -TargetPath $specialTarget | Out-Null
    & git -C $specialRepo check-ignore -q -- "$specialRelative/.dev-workflow/manifest.json"
    Assert-True ($LASTEXITCODE -eq 0) 'Git exclude escapes special characters in nested target paths'
    & git -C $specialRepo check-ignore -q -- "$specialRelative/docs/README.md"
    Assert-True ($LASTEXITCODE -eq 0) 'Git exclude protects created files under a special-character target path'

    $misorderedInstallTarget = Join-Path $tempRoot 'misordered-install'
    New-Item -ItemType Directory -Path $misorderedInstallTarget | Out-Null
    & git -C $misorderedInstallTarget init -q | Out-Null
    $misorderedInstallExclude = Join-Path $misorderedInstallTarget '.git/info/exclude'
    Write-Utf8NoBom -Path $misorderedInstallExclude -Content "# END dev-workflow managed excludes`n/keep-between/`n# BEGIN dev-workflow managed excludes`n/keep-after/`n"
    $misorderedInstallExcludeHash = (Get-FileHash -LiteralPath $misorderedInstallExclude -Algorithm SHA256).Hash
    $misorderedInstallFailed = $false
    try {
        & $installScript -TargetPath $misorderedInstallTarget | Out-Null
    } catch {
        $misorderedInstallFailed = $true
    }
    Assert-True $misorderedInstallFailed 'install rejects a misordered managed Git exclude block'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $misorderedInstallTarget '.dev-workflow/manifest.json'))) 'Git exclude preflight fails before install mutations'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $misorderedInstallTarget 'AGENTS.md'))) 'Git exclude preflight prevents partial Core installation'
    Assert-True ($misorderedInstallExcludeHash -eq (Get-FileHash -LiteralPath $misorderedInstallExclude -Algorithm SHA256).Hash) 'failed install preserves a misordered user exclude file byte-for-byte'

    $misorderedUninstallTarget = Join-Path $tempRoot 'misordered-uninstall'
    New-Item -ItemType Directory -Path $misorderedUninstallTarget | Out-Null
    & git -C $misorderedUninstallTarget init -q | Out-Null
    & $installScript -TargetPath $misorderedUninstallTarget | Out-Null
    $misorderedUninstallAgents = Join-Path $misorderedUninstallTarget 'AGENTS.md'
    $misorderedUninstallAgentsHash = (Get-FileHash -LiteralPath $misorderedUninstallAgents -Algorithm SHA256).Hash
    $misorderedUninstallExclude = Join-Path $misorderedUninstallTarget '.git/info/exclude'
    Write-Utf8NoBom -Path $misorderedUninstallExclude -Content "# END dev-workflow managed excludes`n/keep-between/`n# BEGIN dev-workflow managed excludes`n/keep-after/`n"
    $misorderedUninstallFailed = $false
    try {
        & $uninstallScript -TargetPath $misorderedUninstallTarget | Out-Null
    } catch {
        $misorderedUninstallFailed = $true
    }
    Assert-True $misorderedUninstallFailed 'uninstall rejects a misordered managed Git exclude block'
    Assert-True (Test-Path -LiteralPath (Join-Path $misorderedUninstallTarget '.dev-workflow/manifest.json') -PathType Leaf) 'Git exclude preflight fails before uninstall removes the manifest'
    Assert-True ($misorderedUninstallAgentsHash -eq (Get-FileHash -LiteralPath $misorderedUninstallAgents -Algorithm SHA256).Hash) 'Git exclude preflight prevents partial Core uninstall'
    Assert-True ((Get-Content -LiteralPath $misorderedUninstallExclude -Raw -Encoding UTF8) -match '/keep-after/') 'failed uninstall preserves user exclude content after a misordered marker'

    $negatedTarget = Join-Path $tempRoot 'negated-ignore'
    New-Item -ItemType Directory -Path $negatedTarget | Out-Null
    & git -C $negatedTarget init -q | Out-Null
    Write-Utf8NoBom -Path (Join-Path $negatedTarget '.gitignore') -Content "!/.dev-workflow/`n!/.dev-workflow/**`n"
    $negatedInstallWarnings = @(& $installScript -TargetPath $negatedTarget 3>&1 | ForEach-Object { $_.ToString() })
    Assert-True (($negatedInstallWarnings -join "`n") -match 'final ignore rules do not exclude dev-workflow metadata') 'install warns when project .gitignore overrides the local metadata exclude'
    & git -C $negatedTarget check-ignore --no-index -q -- .dev-workflow/manifest.json
    Assert-True ($LASTEXITCODE -ne 0) 'negating .gitignore fixture exposes dev-workflow metadata'
    $negatedAuditOutput = @(& $powerShellExe -NoProfile -File $auditScript -TargetPath $negatedTarget 2>&1 | ForEach-Object { $_.ToString() })
    $negatedAuditCode = $LASTEXITCODE
    Assert-True ($negatedAuditCode -eq 2) 'negated-exclude audit still reports the pending onboarding state'
    Assert-True (($negatedAuditOutput -join "`n") -match 'final ignore rules do not exclude dev-workflow metadata') 'audit warns when the final Git ignore result is ineffective'

    $worktreeRepo = Join-Path $tempRoot 'worktree-repo'
    $worktreeTarget = Join-Path $tempRoot 'worktree-target'
    New-Item -ItemType Directory -Path $worktreeRepo | Out-Null
    & git -C $worktreeRepo init -q | Out-Null
    Write-Utf8NoBom -Path (Join-Path $worktreeRepo 'base.txt') -Content "base`n"
    & git -C $worktreeRepo add base.txt
    & git -C $worktreeRepo -c user.name=dev-workflow -c user.email=dev-workflow@example.invalid commit -qm init
    & git -C $worktreeRepo worktree add -q -b dev-workflow-test $worktreeTarget
    & $installScript -TargetPath $worktreeTarget -Packs architecture | Out-Null
    $worktreeExcludeOutput = (& git -C $worktreeTarget rev-parse --git-path info/exclude).Trim()
    $worktreeExclude = if ([IO.Path]::IsPathRooted($worktreeExcludeOutput)) {
        $worktreeExcludeOutput
    } else {
        [IO.Path]::GetFullPath((Join-Path $worktreeTarget $worktreeExcludeOutput))
    }
    Assert-True ((Get-Content -LiteralPath $worktreeExclude -Raw -Encoding UTF8) -match '# BEGIN dev-workflow managed excludes') 'worktree install uses the Git-resolved info/exclude path'
    & git -C $worktreeTarget check-ignore -q -- docs/architecture/SYSTEM.md
    Assert-True ($LASTEXITCODE -eq 0) 'worktree Git exclude applies to installed files'

    $nonGitTarget = Join-Path $tempRoot 'non-git'
    New-Item -ItemType Directory -Path $nonGitTarget | Out-Null
    & $installScript -TargetPath $nonGitTarget | Out-Null
    Assert-True (Test-Path -LiteralPath (Join-Path $nonGitTarget '.dev-workflow/manifest.json')) 'non-Git directories still install'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $nonGitTarget '.git/info/exclude'))) 'non-Git install does not fabricate a Git exclude file'

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
    $excludeHashBeforeReinstall = (Get-FileHash -LiteralPath $freshExcludePath -Algorithm SHA256).Hash
    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $catalogHashAfterReinstall = (Get-FileHash -LiteralPath $activeCatalogPath -Algorithm SHA256).Hash
    Assert-True ($catalogHashBeforeReinstall -eq $catalogHashAfterReinstall) 'reinstall does not overwrite active feature catalog'
    Assert-True (([regex]::Matches((Get-Content -LiteralPath $freshExcludePath -Raw -Encoding UTF8), '# BEGIN dev-workflow managed excludes')).Count -eq 1) 'reinstall does not duplicate the managed Git exclude block'
    Assert-True ($excludeHashBeforeReinstall -eq (Get-FileHash -LiteralPath $freshExcludePath -Algorithm SHA256).Hash) 'reinstall leaves the Git exclude file byte-stable'

    $firstUpdatedAt = [string]$manifest.updatedAt
    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$manifest.updatedAt -eq $firstUpdatedAt) 'idempotent reinstall preserves updatedAt'

    $automatedGitManifest.gitPolicy.deleteAllowed = $true
    Write-Utf8NoBom -Path (Join-Path $automatedGitTarget '.dev-workflow/manifest.json') -Content (($automatedGitManifest | ConvertTo-Json -Depth 8) + "`n")
    & $powerShellExe -NoProfile -File $auditScript -TargetPath $automatedGitTarget *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'audit rejects granted delete permission'
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
    Assert-True ($LASTEXITCODE -eq 0) 'a completed schema 3 install passes strict audit'

    $excludeWithoutCore = @(
        Get-Content -LiteralPath $freshExcludePath -Encoding UTF8 |
            Where-Object { $_ -ne '/docs/README.md' }
    )
    Write-Utf8NoBom -Path $freshExcludePath -Content (($excludeWithoutCore -join "`n") + "`n")
    & $powerShellExe -NoProfile -File $auditScript -TargetPath $freshTarget -Strict *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'strict audit rejects a missing created-file Git exclude'
    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null

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
    Assert-True ([string]$manifest.gitPolicy.pushMode -eq 'manual') 'partial uninstall preserves push policy'
    Assert-True ([string]$manifest.gitPolicy.mergeActor -eq 'user') 'partial uninstall preserves merge policy'
    Assert-True ($manifest.gitPolicy.deleteAllowed -eq $false) 'partial uninstall preserves denied delete permission'
    $partialExclude = Get-Content -LiteralPath $freshExcludePath -Raw -Encoding UTF8
    Assert-True ($partialExclude -match '/docs/README\.md') 'partial uninstall preserves Core Git excludes'
    Assert-True ($partialExclude -notmatch '/docs/plans/TEMPLATE\.md') 'partial uninstall removes pack Git excludes'
    Assert-True (([regex]::Matches($partialExclude, '# BEGIN dev-workflow managed excludes')).Count -eq 1) 'partial uninstall keeps one managed Git exclude block'

    & $uninstallScript -TargetPath $freshTarget | Out-Null
    Assert-True (-not (Test-Path -LiteralPath $freshManifestPath)) 'full uninstall removes the manifest'
    Assert-True (Test-Path -LiteralPath $modifiedDeliveryFile -PathType Leaf) 'project-modified content remains after full uninstall'
    Assert-True (Test-Path -LiteralPath $activeCatalogPath -PathType Leaf) 'full uninstall preserves active feature catalog'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/FEATURE-MATRIX.md') -PathType Leaf) 'full uninstall preserves generated feature matrix'
    $fullExclude = Get-Content -LiteralPath $freshExcludePath -Raw -Encoding UTF8
    Assert-True ($fullExclude -notmatch 'dev-workflow managed excludes') 'full uninstall removes the managed Git exclude block'
    Assert-True ($fullExclude -match '# user exclude') 'full uninstall preserves user Git excludes'
    Assert-True ($gitignoreHashBeforeInstall -eq (Get-FileHash -LiteralPath (Join-Path $freshTarget '.gitignore') -Algorithm SHA256).Hash) 'uninstall does not modify project .gitignore'

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
    $upgradeManifest.schemaVersion = 2
    $upgradeManifest.workflowVersion = '0.1.9'
    $upgradeManifest.PSObject.Properties.Remove('gitPolicy')
    ($upgradeManifest.files | Where-Object path -eq 'docs/TASKS.md').installedSha256 = ('0' * 64)
    Write-Utf8NoBom -Path $upgradeManifestPath -Content (($upgradeManifest | ConvertTo-Json -Depth 8) + "`n")
    & $installScript -TargetPath $upgradeTarget | Out-Null
    $upgradeManifest = Get-Content -LiteralPath $upgradeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $upgradedEntry = $upgradeManifest.files | Where-Object path -eq 'docs/TASKS.md'
    Assert-True ($upgradedEntry.action -eq 'legacy') 'changed created ownership becomes legacy during a version upgrade'
    Assert-True ($null -eq $upgradedEntry.installedSha256) 'legacy upgrade ownership clears the deletion hash'
    Assert-True ([string]$upgradeManifest.schemaVersion -eq '3') 'schema 2 manifests upgrade to schema 3'
    Assert-True ($upgradeManifest.workflowVersion -eq $workflowVersion) 'schema 2 upgrade records the current workflow version'
    Assert-True ([string]$upgradeManifest.gitPolicy.pushMode -eq 'manual') 'upgrade adds safe push policy when missing'
    Assert-True ([string]$upgradeManifest.gitPolicy.mergeActor -eq 'user') 'upgrade adds safe merge actor when missing'

    $legacyTarget = Join-Path $tempRoot 'legacy'
    New-Item -ItemType Directory -Path $legacyTarget | Out-Null
    & $installScript -TargetPath $legacyTarget -Packs architecture | Out-Null
    $legacyManifestPath = Join-Path $legacyTarget '.dev-workflow/manifest.json'
    $legacyManifest = Get-Content -LiteralPath $legacyManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $legacyManifest.schemaVersion = 1
    $legacyManifest.PSObject.Properties.Remove('files')
    $legacyManifest.PSObject.Properties.Remove('gitPolicy')
    Write-Utf8NoBom -Path $legacyManifestPath -Content (($legacyManifest | ConvertTo-Json -Depth 6) + "`n")

    & $installScript -TargetPath $legacyTarget | Out-Null
    $migratedManifest = Get-Content -LiteralPath $legacyManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$migratedManifest.schemaVersion -eq '3') 'legacy manifests migrate to schema 3'
    Assert-True (($migratedManifest.files | Where-Object path -eq 'docs/architecture/SYSTEM.md').action -eq 'legacy') 'legacy pack files remain conservatively owned'

    Write-Output 'PowerShell integration tests passed.'
} finally {
    $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot)
    $resolvedTempBase = [IO.Path]::GetFullPath($tempBase)
    if ($resolvedTempRoot.StartsWith($resolvedTempBase, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTempRoot)) {
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
