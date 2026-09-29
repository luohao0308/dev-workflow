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
Assert-True ($installParameters -contains 'PullRequestMode') 'installer exposes pull-request mode configuration'
Assert-True ($installParameters -contains 'PullRequestActor') 'installer exposes pull-request actor configuration'
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
    Assert-True ([string]$manifest.schemaVersion -eq '4') 'new installs use manifest schema 4'
    Assert-True ([string]$manifest.gitPolicy.pushMode -eq 'manual') 'push defaults to manual approval'
    Assert-True ([string]$manifest.gitPolicy.pushActor -eq 'user') 'push defaults to user execution'
    Assert-True ([string]$manifest.gitPolicy.pullRequestMode -eq 'manual') 'pull requests default to manual approval'
    Assert-True ([string]$manifest.gitPolicy.pullRequestActor -eq 'user') 'pull requests default to user execution'
    Assert-True ([string]$manifest.gitPolicy.mergeMode -eq 'manual') 'merge defaults to manual approval'
    Assert-True ([string]$manifest.gitPolicy.mergeActor -eq 'user') 'merge defaults to user execution'
    Assert-True ($manifest.gitPolicy.pullRequestRequired -eq $true) 'pull requests are required by default'
    Assert-True ($manifest.gitPolicy.ciRequired -eq $true) 'CI is required by default'
    Assert-True ($manifest.gitPolicy.independentReviewRequired -eq $true) 'independent review is required by default'
    Assert-True ($manifest.gitPolicy.forcePushAllowed -eq $false) 'force push is denied by default'
    Assert-True ($manifest.gitPolicy.directProtectedBranchPushAllowed -eq $false) 'direct protected-branch push is denied by default'
    Assert-True ([string]$manifest.gitPolicy.privilegedOperationsDefault -eq 'deny') 'privileged operations default to deny'
    Assert-True ($manifest.gitPolicy.deleteAllowed -eq $false) 'delete is always denied'
    Assert-True ([string]$manifest.gitPolicy.policyChangedBy -eq 'default') 'safe defaults record their policy origin'
    $policyChangedAt = [DateTime]::MinValue
    Assert-True ([DateTime]::TryParse([string]$manifest.gitPolicy.policyChangedAt, [ref]$policyChangedAt)) 'safe defaults record a valid policy timestamp'
    Assert-True (@($manifest.files).Count -gt 20) 'new installs record a file ownership inventory'
    Assert-True (@($manifest.files | Where-Object action -eq 'created').Count -gt 20) 'new files record created ownership'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 大型计划拆分与确认门') 'Core install includes the large-plan approval gate'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 默认开发闭环（轻量核心 \+ 风险插件）') 'Core install includes the lightweight development loop'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 自适应技术决策门') 'Core install includes the adaptive technical decision gate'
    $installedCore = Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8
    Assert-True (($installedCore -match 'L0') -and ($installedCore -match 'L1') -and ($installedCore -match 'L2')) 'Core install includes all decision levels'
    Assert-True ($installedCore -match '技术分析本身不构成授权门') 'decision levels do not add redundant approval gates'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '## 交付治理与权限策略') 'Core install includes the delivery governance and permission policy'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'AGENTS.md') -Raw -Encoding UTF8) -match '一次性授权必须绑定') 'Core install scopes one-time delivery authorization'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/README.md') -Raw -Encoding UTF8) -match 'awaiting_user_confirmation') 'delivery plans expose the approval state'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -Raw -Encoding UTF8) -match '## 7\. 偏移控制') 'delivery plan template includes drift control'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -Raw -Encoding UTF8) -match 'Test/Eval/Check') 'delivery plan template maps claims to executable checks'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/development/GIT-WORKTREE-WORKFLOW.md') -Raw -Encoding UTF8) -match 'codex/\*') 'delivery workflow protects local Codex branches'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/development/DELIVERY-DECISION-MATRIX.md') -PathType Leaf) 'delivery install includes the single decision authority'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/development/GIT-WORKTREE-WORKFLOW.md') -Raw -Encoding UTF8) -match 'DELIVERY-DECISION-MATRIX\.md') 'worktree workflow references the single decision authority'
    Assert-True ((Get-Content -LiteralPath (Join-Path $freshTarget 'docs/development/README.md') -Raw -Encoding UTF8) -match 'DELIVERY-DECISION-MATRIX\.md') 'development README references the single decision authority'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'scripts/delivery_guard.py') -PathType Leaf) 'Core installs the delivery preflight guard'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'scripts/check-git-boundaries.py') -PathType Leaf) 'delivery installs the Git boundary check'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'scripts/report-worktrees.py') -PathType Leaf) 'delivery installs the read-only worktree report'
    Assert-True (@($manifest.files | Where-Object { $_.path -eq 'scripts/report-worktrees.py' -and $_.source -eq 'delivery' }).Count -eq 1) 'manifest records worktree report ownership'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/development/CI-BOUNDARY-CHECK.md') -PathType Leaf) 'delivery documents CI enforcement for Git boundaries'
    Assert-True (@($manifest.files | Where-Object { $_.path -eq 'scripts/check-git-boundaries.py' -and $_.source -eq 'delivery' }).Count -eq 1) 'manifest records Git boundary check ownership'
    Assert-True (@($manifest.files | Where-Object { $_.path -eq 'scripts/delivery_guard.py' -and $_.source -eq 'core' }).Count -eq 1) 'manifest records delivery guard ownership'
    Assert-True (@($manifest.files | Where-Object { $_.path -eq 'scripts/feature_catalog.py' -and $_.source -eq 'feature-catalog' }).Count -eq 1) 'all-packs installs feature-catalog ownership'

    $guardCollisionTarget = Join-Path $tempRoot 'guard-collision'
    New-Item -ItemType Directory -Path (Join-Path $guardCollisionTarget 'scripts') -Force | Out-Null
    Write-Utf8NoBom -Path (Join-Path $guardCollisionTarget 'scripts/delivery_guard.py') -Content "untrusted guard`n"
    $guardCollisionFailed = $false
    try { & $installScript -TargetPath $guardCollisionTarget -NonInteractiveInstall | Out-Null } catch { $guardCollisionFailed = $true }
    Assert-True $guardCollisionFailed 'install rejects an untrusted pre-existing delivery guard'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $guardCollisionTarget '.dev-workflow/manifest.json'))) 'guard collision fails before manifest creation'

    $guardTamperTarget = Join-Path $tempRoot 'guard-tamper'
    New-Item -ItemType Directory -Path $guardTamperTarget | Out-Null
    & $installScript -TargetPath $guardTamperTarget -NonInteractiveInstall | Out-Null
    Write-Utf8NoBom -Path (Join-Path $guardTamperTarget 'scripts/delivery_guard.py') -Content "tampered guard`n"
    $guardTamperManifestPath = Join-Path $guardTamperTarget '.dev-workflow/manifest.json'
    $guardTamperManifestHash = (Get-FileHash -LiteralPath $guardTamperManifestPath -Algorithm SHA256).Hash
    & $powerShellExe -NoProfile -File $auditScript -TargetPath $guardTamperTarget *> $null
    Assert-True ($LASTEXITCODE -eq 1) 'audit rejects a modified managed delivery guard'
    $guardTamperFailed = $false
    try { & $installScript -TargetPath $guardTamperTarget -NonInteractiveInstall | Out-Null } catch { $guardTamperFailed = $true }
    Assert-True $guardTamperFailed 'reinstall rejects a modified managed delivery guard'
    Assert-True ($guardTamperManifestHash -eq (Get-FileHash -LiteralPath $guardTamperManifestPath -Algorithm SHA256).Hash) 'rejected guard tamper leaves manifest unchanged'
    $freshExcludePath = Join-Path $freshTarget '.git/info/exclude'
    $freshExclude = Get-Content -LiteralPath $freshExcludePath -Raw -Encoding UTF8
    Assert-True ($freshExclude -match '# BEGIN dev-workflow managed excludes') 'install adds a managed Git exclude block'
    Assert-True ($freshExclude -match '/\.dev-workflow/') 'Git exclude hides dev-workflow metadata'
    Assert-True ($freshExclude -match '/docs/README\.md') 'Git exclude hides a created Core file'
    Assert-True ($freshExclude -match '/docs/project-memory/') 'Git exclude hides the complete long-term memory directory'
    Assert-True ($freshExclude -match '/docs/working-context/') 'Git exclude hides the complete working-context directory'
    Assert-True ($freshExclude -match '/docs/工作日志/') 'Git exclude hides the complete workflow journal directory'
    Assert-True ($freshExclude -match '# user exclude') 'install preserves user Git excludes'
    & git -C $freshTarget check-ignore -q -- .dev-workflow/manifest.json
    Assert-True ($LASTEXITCODE -eq 0) 'Git check-ignore matches dev-workflow metadata'
    & git -C $freshTarget check-ignore -q -- docs/README.md
    Assert-True ($LASTEXITCODE -eq 0) 'Git check-ignore matches created workflow files'
    New-Item -ItemType Directory -Path (Join-Path $freshTarget 'docs/project-memory/runbooks'), (Join-Path $freshTarget 'docs/working-context'), (Join-Path $freshTarget 'docs/工作日志') -Force | Out-Null
    Write-Utf8NoBom -Path (Join-Path $freshTarget 'docs/project-memory/runbooks/future-memory.md') -Content "local memory`n"
    Write-Utf8NoBom -Path (Join-Path $freshTarget 'docs/working-context/future-task.md') -Content "local context`n"
    Write-Utf8NoBom -Path (Join-Path $freshTarget 'docs/工作日志/future-session.md') -Content "local journal`n"
    & git -C $freshTarget check-ignore -q -- docs/project-memory/runbooks/future-memory.md
    Assert-True ($LASTEXITCODE -eq 0) 'Git ignores future long-term memory files'
    & git -C $freshTarget check-ignore -q -- docs/working-context/future-task.md
    Assert-True ($LASTEXITCODE -eq 0) 'Git ignores future working-context files'
    & git -C $freshTarget check-ignore -q -- 'docs/工作日志/future-session.md'
    Assert-True ($LASTEXITCODE -eq 0) 'Git ignores future workflow journal files'
    foreach ($entry in @($manifest.files | Where-Object action -eq 'created')) {
        & git -C $freshTarget check-ignore -q -- ([string]$entry.path)
        if ([string]$entry.path -like 'docs/operations/runbooks/*') {
            Assert-True ($LASTEXITCODE -ne 0) "Git keeps shared runbook visible: $($entry.path)"
        } else {
            Assert-True ($LASTEXITCODE -eq 0) "Git excludes installer-created path: $($entry.path)"
        }
    }
    & git -C $freshTarget check-ignore -q -- docs/operations/runbooks/RUNBOOK-TEMPLATE.md
    Assert-True ($LASTEXITCODE -ne 0) 'Git does not ignore the shared runbook template'
    Assert-True ($gitignoreHashBeforeInstall -eq (Get-FileHash -LiteralPath (Join-Path $freshTarget '.gitignore') -Algorithm SHA256).Hash) 'install does not modify project .gitignore'

    foreach ($nonInteractiveAuthorization in @(
        @{ Name = 'push'; Arguments = @('-PushMode', 'auto', '-PushActor', 'ai') },
        @{ Name = 'pull-request'; Arguments = @('-PullRequestMode', 'auto', '-PullRequestActor', 'ai') },
        @{ Name = 'merge'; Arguments = @('-MergeMode', 'auto', '-MergeActor', 'ai') }
    )) {
        $authorizationTarget = Join-Path $tempRoot ("non-interactive-$($nonInteractiveAuthorization.Name)")
        New-Item -ItemType Directory -Path $authorizationTarget | Out-Null
        $authorizationFailed = $false
        try {
            $authorizationArguments = @('-TargetPath', $authorizationTarget) + @($nonInteractiveAuthorization.Arguments)
            & $installScript @authorizationArguments | Out-Null
        } catch {
            $authorizationFailed = $true
        }
        Assert-True $authorizationFailed "non-interactive install cannot self-authorize $($nonInteractiveAuthorization.Name) auto/ai"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $authorizationTarget '.dev-workflow/manifest.json'))) "rejected $($nonInteractiveAuthorization.Name) self-authorization does not write a manifest"
    }

    foreach ($existingPolicyChange in @(
        @{ Name = 'push-mode'; ModeField = 'pushMode'; ActorField = 'pushActor'; InitialMode = 'auto'; Parameter = '-PushMode'; Value = 'manual' },
        @{ Name = 'push-actor'; ModeField = 'pushMode'; ActorField = 'pushActor'; InitialMode = 'manual'; Parameter = '-PushActor'; Value = 'user' },
        @{ Name = 'pull-request-mode'; ModeField = 'pullRequestMode'; ActorField = 'pullRequestActor'; InitialMode = 'auto'; Parameter = '-PullRequestMode'; Value = 'manual' },
        @{ Name = 'pull-request-actor'; ModeField = 'pullRequestMode'; ActorField = 'pullRequestActor'; InitialMode = 'manual'; Parameter = '-PullRequestActor'; Value = 'user' },
        @{ Name = 'merge-mode'; ModeField = 'mergeMode'; ActorField = 'mergeActor'; InitialMode = 'auto'; Parameter = '-MergeMode'; Value = 'manual' },
        @{ Name = 'merge-actor'; ModeField = 'mergeMode'; ActorField = 'mergeActor'; InitialMode = 'manual'; Parameter = '-MergeActor'; Value = 'user' }
    )) {
        $existingPolicyTarget = Join-Path $tempRoot ("existing-policy-$($existingPolicyChange.Name)")
        New-Item -ItemType Directory -Path $existingPolicyTarget | Out-Null
        & $installScript -TargetPath $existingPolicyTarget | Out-Null
        $existingPolicyManifestPath = Join-Path $existingPolicyTarget '.dev-workflow/manifest.json'
        $existingPolicyManifest = Get-Content -LiteralPath $existingPolicyManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $existingPolicyManifest.gitPolicy.($existingPolicyChange.ModeField) = $existingPolicyChange.InitialMode
        $existingPolicyManifest.gitPolicy.($existingPolicyChange.ActorField) = 'ai'
        $existingPolicyManifest.gitPolicy.policyChangedBy = 'user'
        Write-Utf8NoBom -Path $existingPolicyManifestPath -Content (($existingPolicyManifest | ConvertTo-Json -Depth 8) + "`n")
        $existingPolicyHash = (Get-FileHash -LiteralPath $existingPolicyManifestPath -Algorithm SHA256).Hash
        $existingPolicyChangeFailed = $false
        try {
            $existingPolicyArguments = @('-TargetPath', $existingPolicyTarget, $existingPolicyChange.Parameter, $existingPolicyChange.Value)
            & $installScript @existingPolicyArguments | Out-Null
        } catch {
            $existingPolicyChangeFailed = $true
        }
        Assert-True $existingPolicyChangeFailed "non-interactive install cannot narrow existing $($existingPolicyChange.Name) policy"
        Assert-True ($existingPolicyHash -eq (Get-FileHash -LiteralPath $existingPolicyManifestPath -Algorithm SHA256).Hash) "rejected $($existingPolicyChange.Name) policy change preserves the manifest"
    }

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

    $invalidMergeTarget = Join-Path $tempRoot 'invalid-merge'
    New-Item -ItemType Directory -Path $invalidMergeTarget | Out-Null
    $invalidMergeFailed = $false
    try {
        & $installScript -TargetPath $invalidMergeTarget -MergeMode auto -MergeActor user | Out-Null
    } catch {
        $invalidMergeFailed = $true
    }
    Assert-True $invalidMergeFailed 'automatic merge with a user actor is rejected'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $invalidMergeTarget '.dev-workflow/manifest.json'))) 'invalid merge policy does not write a manifest'

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
    & git -C $freshTarget check-ignore -q -- docs/project-memory/runbooks/future-memory.md
    Assert-True ($LASTEXITCODE -eq 0) 'reinstall keeps future long-term memory ignored'

    $firstUpdatedAt = [string]$manifest.updatedAt
    & $installScript -TargetPath $freshTarget -AllPacks | Out-Null
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$manifest.updatedAt -eq $firstUpdatedAt) 'idempotent reinstall preserves updatedAt'

    $auditPolicyTarget = Join-Path $tempRoot 'audit-policy'
    New-Item -ItemType Directory -Path $auditPolicyTarget | Out-Null
    & $installScript -TargetPath $auditPolicyTarget | Out-Null
    $auditPolicyManifestPath = Join-Path $auditPolicyTarget '.dev-workflow/manifest.json'
    $auditPolicyBaseline = Get-Content -LiteralPath $auditPolicyManifestPath -Raw -Encoding UTF8
    foreach ($auditPolicyCase in @(
        @{ Message = 'audit rejects an invalid pull-request mode'; Changes = @{ pullRequestMode = 'sometimes' }; Remove = @() },
        @{ Message = 'audit rejects automatic pull requests with a user actor'; Changes = @{ pullRequestMode = 'auto'; pullRequestActor = 'user' }; Remove = @() },
        @{ Message = 'audit rejects a missing pull-request actor'; Changes = @{}; Remove = @('pullRequestActor') },
        @{ Message = 'audit rejects a missing required safety gate'; Changes = @{}; Remove = @('ciRequired') },
        @{ Message = 'audit rejects automatic merge with a user actor'; Changes = @{ mergeMode = 'auto'; mergeActor = 'user' }; Remove = @() },
        @{ Message = 'audit rejects a disabled pull-request requirement'; Changes = @{ pullRequestRequired = $false }; Remove = @() },
        @{ Message = 'audit rejects a disabled CI requirement'; Changes = @{ ciRequired = $false }; Remove = @() },
        @{ Message = 'audit rejects a disabled independent-review requirement'; Changes = @{ independentReviewRequired = $false }; Remove = @() },
        @{ Message = 'audit rejects allowed force push'; Changes = @{ forcePushAllowed = $true }; Remove = @() },
        @{ Message = 'audit rejects direct protected-branch push'; Changes = @{ directProtectedBranchPushAllowed = $true }; Remove = @() },
        @{ Message = 'audit rejects privileged operations enabled by default'; Changes = @{ privilegedOperationsDefault = 'allow' }; Remove = @() },
        @{ Message = 'audit rejects granted delete permission'; Changes = @{ deleteAllowed = $true }; Remove = @() }
    )) {
        $auditPolicyManifest = $auditPolicyBaseline | ConvertFrom-Json
        foreach ($field in $auditPolicyCase.Changes.Keys) {
            $auditPolicyManifest.gitPolicy.$field = $auditPolicyCase.Changes[$field]
        }
        foreach ($field in $auditPolicyCase.Remove) {
            $auditPolicyManifest.gitPolicy.PSObject.Properties.Remove($field)
        }
        Write-Utf8NoBom -Path $auditPolicyManifestPath -Content (($auditPolicyManifest | ConvertTo-Json -Depth 8) + "`n")
        & $powerShellExe -NoProfile -File $auditScript -TargetPath $auditPolicyTarget *> $null
        Assert-True ($LASTEXITCODE -eq 1) $auditPolicyCase.Message
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
    Assert-True ($LASTEXITCODE -eq 0) 'a completed schema 4 install passes strict audit'

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
    $policyManifestBeforeUninstall = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $policyChangedAtBeforeUninstall = [string]$policyManifestBeforeUninstall.gitPolicy.policyChangedAt
    $policyChangedByBeforeUninstall = [string]$policyManifestBeforeUninstall.gitPolicy.policyChangedBy
    & $uninstallScript -TargetPath $freshTarget -Packs delivery -DryRun | Out-Null
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md') -PathType Leaf) 'dry-run does not delete files'

    & $uninstallScript -TargetPath $freshTarget -Packs delivery | Out-Null
    Assert-True (Test-Path -LiteralPath $modifiedDeliveryFile -PathType Leaf) 'modified managed files are preserved'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $freshTarget 'docs/plans/TEMPLATE.md'))) 'unchanged pack files are deleted'
    Assert-True (Test-Path -LiteralPath (Join-Path $freshTarget 'scripts/delivery_guard.py') -PathType Leaf) 'partial delivery uninstall preserves the Core guard'
    $manifest = Get-Content -LiteralPath $freshManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True (@($manifest.installedPacks) -notcontains 'delivery') 'partial uninstall removes the pack from manifest'
    Assert-True (@($manifest.files | Where-Object source -eq 'delivery').Count -eq 0) 'partial uninstall removes pack inventory entries'
    Assert-True ([string]$manifest.gitPolicy.pushMode -eq 'manual') 'partial uninstall preserves push policy'
    Assert-True ([string]$manifest.gitPolicy.pushActor -eq 'user') 'partial uninstall preserves push actor'
    Assert-True ([string]$manifest.gitPolicy.pullRequestMode -eq 'manual') 'partial uninstall preserves pull-request policy'
    Assert-True ([string]$manifest.gitPolicy.pullRequestActor -eq 'user') 'partial uninstall preserves pull-request actor'
    Assert-True ([string]$manifest.gitPolicy.mergeMode -eq 'manual') 'partial uninstall preserves merge policy'
    Assert-True ([string]$manifest.gitPolicy.mergeActor -eq 'user') 'partial uninstall preserves merge policy'
    Assert-True ($manifest.gitPolicy.pullRequestRequired -eq $true) 'partial uninstall preserves the pull-request requirement'
    Assert-True ($manifest.gitPolicy.ciRequired -eq $true) 'partial uninstall preserves the CI requirement'
    Assert-True ($manifest.gitPolicy.independentReviewRequired -eq $true) 'partial uninstall preserves the independent-review requirement'
    Assert-True ($manifest.gitPolicy.forcePushAllowed -eq $false) 'partial uninstall preserves denied force push'
    Assert-True ($manifest.gitPolicy.directProtectedBranchPushAllowed -eq $false) 'partial uninstall preserves denied direct protected-branch push'
    Assert-True ([string]$manifest.gitPolicy.privilegedOperationsDefault -eq 'deny') 'partial uninstall preserves denied privileged operations'
    Assert-True ($manifest.gitPolicy.deleteAllowed -eq $false) 'partial uninstall preserves denied delete permission'
    Assert-True ([string]$manifest.gitPolicy.policyChangedAt -eq $policyChangedAtBeforeUninstall) 'partial uninstall preserves the policy timestamp'
    Assert-True ([string]$manifest.gitPolicy.policyChangedBy -eq $policyChangedByBeforeUninstall) 'partial uninstall preserves the policy origin'
    $partialExclude = Get-Content -LiteralPath $freshExcludePath -Raw -Encoding UTF8
    Assert-True ($partialExclude -match '/docs/README\.md') 'partial uninstall preserves Core Git excludes'
    Assert-True ($partialExclude -match '/docs/project-memory/') 'partial uninstall preserves local memory exclusion'
    Assert-True ($partialExclude -notmatch '/docs/working-context/' -and $partialExclude -notmatch '/docs/工作日志/') 'partial uninstall removes Delivery-only directory excludes'
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

    $schema3UpgradeTarget = Join-Path $tempRoot 'schema3-upgrade'
    New-Item -ItemType Directory -Path $schema3UpgradeTarget | Out-Null
    & $installScript -TargetPath $schema3UpgradeTarget | Out-Null
    $schema3UpgradeManifestPath = Join-Path $schema3UpgradeTarget '.dev-workflow/manifest.json'
    $schema3UpgradeManifest = Get-Content -LiteralPath $schema3UpgradeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $schema3UpgradeManifest.schemaVersion = 3
    $schema3UpgradeManifest.gitPolicy.pushMode = 'manual'
    $schema3UpgradeManifest.gitPolicy.pushActor = 'ai'
    $schema3UpgradeManifest.gitPolicy.mergeMode = 'auto'
    $schema3UpgradeManifest.gitPolicy.mergeActor = 'ai'
    foreach ($field in @(
        'pullRequestMode',
        'pullRequestActor',
        'pullRequestRequired',
        'ciRequired',
        'independentReviewRequired',
        'forcePushAllowed',
        'directProtectedBranchPushAllowed',
        'privilegedOperationsDefault'
    )) {
        $schema3UpgradeManifest.gitPolicy.PSObject.Properties.Remove($field)
    }
    Write-Utf8NoBom -Path $schema3UpgradeManifestPath -Content (($schema3UpgradeManifest | ConvertTo-Json -Depth 8) + "`n")
    & $installScript -TargetPath $schema3UpgradeTarget | Out-Null
    $schema3UpgradeManifest = Get-Content -LiteralPath $schema3UpgradeManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ([string]$schema3UpgradeManifest.schemaVersion -eq '4') 'schema 3 manifests upgrade to schema 4'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.pushMode -eq 'manual') 'schema 3 upgrade preserves push mode'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.pushActor -eq 'ai') 'schema 3 upgrade preserves push actor'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.mergeMode -eq 'auto') 'schema 3 upgrade preserves merge mode'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.mergeActor -eq 'ai') 'schema 3 upgrade preserves merge actor'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.pullRequestMode -eq 'manual') 'schema 3 upgrade adds safe pull-request mode'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.pullRequestActor -eq 'user') 'schema 3 upgrade adds safe pull-request actor'
    Assert-True ($schema3UpgradeManifest.gitPolicy.pullRequestRequired -eq $true) 'schema 3 upgrade requires pull requests'
    Assert-True ($schema3UpgradeManifest.gitPolicy.ciRequired -eq $true) 'schema 3 upgrade requires CI'
    Assert-True ($schema3UpgradeManifest.gitPolicy.independentReviewRequired -eq $true) 'schema 3 upgrade requires independent review'
    Assert-True ($schema3UpgradeManifest.gitPolicy.forcePushAllowed -eq $false) 'schema 3 upgrade denies force push'
    Assert-True ($schema3UpgradeManifest.gitPolicy.directProtectedBranchPushAllowed -eq $false) 'schema 3 upgrade denies direct protected-branch push'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.privilegedOperationsDefault -eq 'deny') 'schema 3 upgrade denies privileged operations by default'
    Assert-True ([string]$schema3UpgradeManifest.gitPolicy.policyChangedBy -eq 'migration') 'schema 3 upgrade records migration as the policy origin'

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
    Assert-True ([string]$upgradeManifest.schemaVersion -eq '4') 'schema 2 manifests upgrade to schema 4'
    Assert-True ($upgradeManifest.workflowVersion -eq $workflowVersion) 'schema 2 upgrade records the current workflow version'
    Assert-True ([string]$upgradeManifest.gitPolicy.pushMode -eq 'manual') 'upgrade adds safe push policy when missing'
    Assert-True ([string]$upgradeManifest.gitPolicy.pushActor -eq 'user') 'upgrade adds safe push actor when missing'
    Assert-True ([string]$upgradeManifest.gitPolicy.pullRequestMode -eq 'manual') 'upgrade adds safe pull-request policy when missing'
    Assert-True ([string]$upgradeManifest.gitPolicy.pullRequestActor -eq 'user') 'upgrade adds safe pull-request actor when missing'
    Assert-True ([string]$upgradeManifest.gitPolicy.mergeMode -eq 'manual') 'upgrade adds safe merge policy when missing'
    Assert-True ([string]$upgradeManifest.gitPolicy.mergeActor -eq 'user') 'upgrade adds safe merge actor when missing'
    Assert-True ($upgradeManifest.gitPolicy.pullRequestRequired -eq $true) 'schema 2 upgrade requires pull requests'
    Assert-True ($upgradeManifest.gitPolicy.ciRequired -eq $true) 'schema 2 upgrade requires CI'
    Assert-True ($upgradeManifest.gitPolicy.independentReviewRequired -eq $true) 'schema 2 upgrade requires independent review'
    Assert-True ($upgradeManifest.gitPolicy.forcePushAllowed -eq $false) 'schema 2 upgrade denies force push'
    Assert-True ($upgradeManifest.gitPolicy.directProtectedBranchPushAllowed -eq $false) 'schema 2 upgrade denies direct protected-branch push'
    Assert-True ([string]$upgradeManifest.gitPolicy.privilegedOperationsDefault -eq 'deny') 'schema 2 upgrade denies privileged operations by default'
    Assert-True ([string]$upgradeManifest.gitPolicy.policyChangedBy -eq 'migration') 'schema 2 upgrade records migration as the policy origin'

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
    Assert-True ([string]$migratedManifest.schemaVersion -eq '4') 'legacy manifests migrate to schema 4'
    Assert-True (($migratedManifest.files | Where-Object path -eq 'docs/architecture/SYSTEM.md').action -eq 'legacy') 'legacy pack files remain conservatively owned'
    Assert-True ([string]$migratedManifest.gitPolicy.pushMode -eq 'manual') 'schema 1 upgrade adds safe push policy'
    Assert-True ([string]$migratedManifest.gitPolicy.pushActor -eq 'user') 'schema 1 upgrade adds safe push actor'
    Assert-True ([string]$migratedManifest.gitPolicy.pullRequestMode -eq 'manual') 'schema 1 upgrade adds safe pull-request policy'
    Assert-True ([string]$migratedManifest.gitPolicy.pullRequestActor -eq 'user') 'schema 1 upgrade adds safe pull-request actor'
    Assert-True ([string]$migratedManifest.gitPolicy.mergeMode -eq 'manual') 'schema 1 upgrade adds safe merge policy'
    Assert-True ([string]$migratedManifest.gitPolicy.mergeActor -eq 'user') 'schema 1 upgrade adds safe merge actor'
    Assert-True ($migratedManifest.gitPolicy.pullRequestRequired -eq $true) 'schema 1 upgrade requires pull requests'
    Assert-True ($migratedManifest.gitPolicy.ciRequired -eq $true) 'schema 1 upgrade requires CI'
    Assert-True ($migratedManifest.gitPolicy.independentReviewRequired -eq $true) 'schema 1 upgrade requires independent review'
    Assert-True ($migratedManifest.gitPolicy.forcePushAllowed -eq $false) 'schema 1 upgrade denies force push'
    Assert-True ($migratedManifest.gitPolicy.directProtectedBranchPushAllowed -eq $false) 'schema 1 upgrade denies direct protected-branch push'
    Assert-True ([string]$migratedManifest.gitPolicy.privilegedOperationsDefault -eq 'deny') 'schema 1 upgrade denies privileged operations by default'
    Assert-True ([string]$migratedManifest.gitPolicy.policyChangedBy -eq 'migration') 'schema 1 upgrade records migration as the policy origin'

    Write-Output 'PowerShell integration tests passed.'
} finally {
    $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot)
    $resolvedTempBase = [IO.Path]::GetFullPath($tempBase)
    if ($resolvedTempRoot.StartsWith($resolvedTempBase, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedTempRoot)) {
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    }
}
