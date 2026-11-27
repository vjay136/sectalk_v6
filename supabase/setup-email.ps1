# Run in an interactive PowerShell window. Secrets are read without echo and stay in memory.
param([switch]$Gmail)

$ErrorActionPreference = 'Stop'
$project = 'kgcnznxkxukbijgltdsf'
$endpoint = "https://api.supabase.com/v1/projects/$project/config/auth"
$templateDirectory = Join-Path $PSScriptRoot 'templates'
$statusDirectory = Join-Path $PSScriptRoot '.temp'
$statusPath = Join-Path $statusDirectory 'email-setup-status.json'

function Save-Status {
    param([string]$Stage, [bool]$Templates = $false, [bool]$Smtp = $false, [int]$HttpStatus = 0, [string]$FailedDuring = '')
    @{
        stage = $Stage
        templatesVerified = $Templates
        smtpConfigured = $Smtp
        httpStatus = $HttpStatus
        failedDuring = $FailedDuring
    } | ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
    $script:currentOperation = $Stage
}

function Read-Secret {
    param([string]$Prompt)
    $value = Read-Host -Prompt $Prompt -AsSecureString
    try {
        return ([PSCredential]::new('sectalk', $value)).GetNetworkCredential().Password
    }
    finally {
        $value.Dispose()
    }
}

function Test-Smtp {
    param($Configuration)
    return -not [string]::IsNullOrWhiteSpace($Configuration.smtp_host) -and
           -not [string]::IsNullOrWhiteSpace($Configuration.smtp_admin_email)
}

New-Item -ItemType Directory -Force -Path $statusDirectory | Out-Null
Save-Status -Stage 'waiting_for_owner'
$templatesApplied = $false
$customSmtp = $false
$token = $null
$headers = $null
$authState = $null
$smtpChanges = $null
$smtpPassword = $null
$lastHttpStatus = 0

try {
    $Host.UI.RawUI.WindowTitle = 'SecTalk email setup'
    Write-Host 'SecTalk | Supabase email setup'
    Write-Host 'Use a Supabase management access token from the account that owns SecTalk.'
    Write-Host 'Create it here: https://supabase.com/dashboard/account/tokens'
    Write-Host 'The token will be hidden while you paste it. Enter it here only.'
    do {
        $token = (Read-Secret -Prompt 'Supabase management access token (Enter to stop)').Trim()
        if (-not $token) { Save-Status -Stage 'owner_token_required'; return }
        if ($token -notmatch '^sbp_[A-Za-z0-9_-]+$') {
            Write-Host 'Use the management access token that starts with sbp_.'
        }
    } until ($token -match '^sbp_[A-Za-z0-9_-]+$')
    $headers = @{ Authorization = 'Bearer ' + $token }
    Save-Status -Stage 'verifying_access'
    $authState = Invoke-RestMethod -Uri $endpoint -Method Get -Headers $headers
    $customSmtp = Test-Smtp $authState

    $templates = @{
        site_url = 'https://sectalk-ver2.vercel.app'
        mailer_subjects_confirmation = 'Verify your SecTalk email'
        mailer_templates_confirmation_content = Get-Content -Encoding utf8 -Raw (Join-Path $templateDirectory 'confirmation.html')
        mailer_subjects_recovery = 'Reset your SecTalk password'
        mailer_templates_recovery_content = Get-Content -Encoding utf8 -Raw (Join-Path $templateDirectory 'recovery.html')
    }
    Save-Status -Stage 'owner_verified' -Smtp $customSmtp
    Write-Host 'Supabase management access verified for SecTalk.'
    if (-not $customSmtp) {
        Save-Status -Stage 'waiting_for_smtp'
        Write-Host 'This project has no custom SMTP sender configured.'
        Write-Host 'Supabase requires custom SMTP to change Auth templates on this plan.'
        if ($Gmail) {
            Write-Host 'Use a Gmail account with 2-Step Verification and a Google app password.'
            Write-Host 'Create the app password here: https://myaccount.google.com/apppasswords'
            Write-Host 'SecTalk will use this Gmail sender for its Auth emails while it is connected.'
        }
        $configure = if ($Gmail) { Read-Host -Prompt 'Configure Gmail SMTP now? [y/N]' } else { Read-Host -Prompt 'Configure SMTP? [y/N]' }
        if ($configure.Trim() -ieq 'y') {
            if ($Gmail) {
                Save-Status -Stage 'waiting_for_gmail_address'
                do {
                    $sender = (Read-Host -Prompt 'Gmail sender address (Enter to stop)').Trim()
                    if (-not $sender) { Save-Status -Stage 'gmail_address_required'; return }
                    if ($sender -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { Write-Host 'Enter the full email address.' }
                } until ($sender -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
                $smtpHost = 'smtp.gmail.com'
                $portInput = '587'
                $smtpUsername = $sender
            } else {
                $sender = (Read-Host -Prompt 'Verified sender email address').Trim()
                $smtpHost = (Read-Host -Prompt 'SMTP hostname from provider').Trim()
                $portInput = (Read-Host -Prompt 'SMTP port from provider').Trim()
                $smtpUsername = (Read-Host -Prompt 'SMTP username from provider').Trim()
            }
            if ($sender -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$' -or $smtpHost -notmatch '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' -or
                $portInput -notmatch '^\d{1,5}$' -or [int]$portInput -lt 1 -or [int]$portInput -gt 65535 -or -not $smtpUsername) {
                throw [ArgumentException]::new('The sender or SMTP settings are invalid.')
            }
            Save-Status -Stage 'waiting_for_smtp_password'
            if ($Gmail) {
                do {
                    $smtpPassword = (Read-Secret -Prompt '16-character Google app password (Enter to stop)') -replace '\s',''
                    if (-not $smtpPassword) { Save-Status -Stage 'gmail_app_password_required'; return }
                    if ($smtpPassword -notmatch '^[A-Za-z0-9]{16}$') { Write-Host 'Paste the 16-character app password from Google. Spaces are allowed.' }
                } until ($smtpPassword -match '^[A-Za-z0-9]{16}$')
            } else {
                $smtpPassword = Read-Secret -Prompt 'SMTP password from provider'
            }
            if (-not $smtpPassword) { throw [ArgumentException]::new('An SMTP password is required.') }
            $smtpChanges = @{
                smtp_admin_email = $sender
                smtp_host = $smtpHost
                smtp_port = $portInput
                smtp_user = $smtpUsername
                smtp_pass = $smtpPassword
                smtp_sender_name = 'SecTalk by Eagle Security'
            }
            $smtpBody = [System.Text.Encoding]::UTF8.GetBytes(($smtpChanges | ConvertTo-Json -Compress))
            try {
                Save-Status -Stage 'saving_smtp'
                Invoke-RestMethod -Uri $endpoint -Method Patch -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $smtpBody | Out-Null
            }
            finally {
                [Array]::Clear($smtpBody, 0, $smtpBody.Length)
            }
            $authState = Invoke-RestMethod -Uri $endpoint -Method Get -Headers $headers
            $customSmtp = (Test-Smtp $authState) -and $authState.smtp_host -eq $smtpHost -and $authState.smtp_admin_email -eq $sender
            if (-not $customSmtp) { throw [InvalidOperationException]::new('The SMTP configuration could not be verified.') }
        }
    }
    if (-not $customSmtp) {
        Save-Status -Stage 'smtp_required'
        Write-Host 'Owner access is verified. A transactional SMTP sender is still required.'
        return
    }
    Save-Status -Stage 'saving_templates' -Smtp $true
    $templateBody = [System.Text.Encoding]::UTF8.GetBytes(($templates | ConvertTo-Json -Compress))
    Invoke-RestMethod -Uri $endpoint -Method Patch -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $templateBody | Out-Null
    $authState = Invoke-RestMethod -Uri $endpoint -Method Get -Headers $headers
    $templatesApplied = (([string]$authState.mailer_templates_confirmation_content).TrimEnd() -ceq $templates.mailer_templates_confirmation_content.TrimEnd()) -and
                        (([string]$authState.mailer_templates_recovery_content).TrimEnd() -ceq $templates.mailer_templates_recovery_content.TrimEnd())
    if (-not $templatesApplied) {
        throw [InvalidOperationException]::new('The templates could not be verified.')
    }
    Save-Status -Stage 'configured' -Templates $true -Smtp $true
    Write-Host 'Signup confirmation link and recovery code templates are active. SMTP settings are saved.'
    Write-Host 'The delivery test creates an account with a random password for a new address you control.'
    $senderAddress = [string]$authState.smtp_admin_email
    if ($Gmail -and $authState.smtp_host -eq 'smtp.gmail.com' -and $senderAddress -match '^([^@+]+)(?:\+[^@]+)?@(gmail\.com|googlemail\.com)$') {
        $defaultRecipient = $Matches[1] + '+sectalk-test-' + (Get-Date -Format 'yyyyMMddHHmmss') + '@' + $Matches[2]
        $testRecipient = (Read-Host -Prompt 'Press Enter to test in this Gmail inbox, type a different test email, or type skip').Trim()
        if (-not $testRecipient) { $testRecipient = $defaultRecipient }
    } else {
        $testRecipient = (Read-Host -Prompt 'New test email address or Gmail plus alias (Enter to skip)').Trim()
    }
    if ($testRecipient -and $testRecipient -ine 'skip') {
        & (Join-Path $PSScriptRoot 'test-email-delivery.ps1') -Recipient $testRecipient
    }
}
catch {
    if ($_.Exception.Response) { $lastHttpStatus = [int]$_.Exception.Response.StatusCode }
    Save-Status -Stage 'failed' -Templates $templatesApplied -Smtp $customSmtp -HttpStatus $lastHttpStatus -FailedDuring $script:currentOperation
    if ($lastHttpStatus -in 401, 403) {
        Write-Host 'Supabase denied access. Verify that the token belongs to the SecTalk project owner and can read and write Auth configuration.'
    } elseif ($lastHttpStatus) {
        Write-Host ('Supabase returned HTTP ' + $lastHttpStatus + '. No credentials will be printed.')
    } elseif ($_.Exception -is [ArgumentException] -or $_.Exception -is [InvalidOperationException]) {
        Write-Host $_.Exception.Message
    } else {
        Write-Host 'Setup could not finish. No credentials will be printed.'
    }
}
finally {
    $token = $null
    if ($headers) { $headers.Clear() }
    if ($smtpChanges) { $smtpChanges.Clear() }
    $smtpPassword = $null
    $authState = $null
    Remove-Variable token, headers, smtpChanges, smtpPassword, authState -ErrorAction SilentlyContinue
    [void](Read-Host -Prompt 'Press Enter to close this window')
}
