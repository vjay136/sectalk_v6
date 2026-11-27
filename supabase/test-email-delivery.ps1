param([Parameter(Mandatory)][string]$Recipient)
$ErrorActionPreference = 'Stop'
$api = 'https://kgcnznxkxukbijgltdsf.supabase.co/auth/v1'
$localEnvPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'apps/web/.env.local'
$envEntry = Get-Content -LiteralPath $localEnvPath | Where-Object { $_ -like 'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=*' } | Select-Object -First 1
$publishableKey = ($envEntry -split '=',2)[1]
if (-not $publishableKey) { throw 'Supabase public configuration is missing.' }
$statusPath = Join-Path $PSScriptRoot '.temp/email-delivery-test.json'
$headers = @{ apikey = $publishableKey }
$signupVerified = $false
$recoveryVerified = $false
$stage = 'requesting_signup'
$httpStatus = 0

function Record-Result {
    @{ stage = $stage; signupVerified = $signupVerified; recoveryVerified = $recoveryVerified; httpStatus = $httpStatus } |
        ConvertTo-Json | Set-Content -LiteralPath $statusPath -Encoding utf8
}

function Send-AuthRequest {
    param([string]$Path, [hashtable]$Payload)
    $body = [System.Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress))
    try {
        return Invoke-RestMethod -Uri ($api + $Path) -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body $body
    }
    finally {
        [Array]::Clear($body, 0, $body.Length)
    }
}

function Revoke-TestSession {
    param([string]$AccessToken)
    if (-not $AccessToken) { return }
    try {
        Invoke-RestMethod -Uri ($api + '/logout?scope=local') -Method Post -Headers @{
            apikey = $publishableKey
            Authorization = 'Bearer ' + $AccessToken
        } | Out-Null
    } catch {
        Write-Host 'This test session will expire automatically.'
    }
}

function Confirm-RecoveryCode {
    while ($true) {
        $secret = Read-Host -Prompt 'Enter the password reset code from your inbox (Enter to stop)' -AsSecureString
        try { $code = ([PSCredential]::new('otp', $secret)).GetNetworkCredential().Password.Trim() }
        finally { $secret.Dispose() }
        if (-not $code) { throw [OperationCanceledException]::new() }
        if ($code -match '^\d{6,10}$') { break }
        Write-Host 'Enter the digits from the email, or press Enter to stop.'
    }
    try {
        $session = Send-AuthRequest -Path '/verify' -Payload @{ email = $Recipient; token = $code; type = 'recovery' }
        if (-not $session.access_token) { throw [InvalidOperationException]::new() }
        Revoke-TestSession -AccessToken $session.access_token
    } finally {
        $code = $null
        $session = $null
    }
}

try {
    Record-Result
    $password = [guid]::NewGuid().ToString('N') + 'aA1!'
    $response = Send-AuthRequest -Path '/signup' -Payload @{ email = $Recipient; password = $password }
    $signupUser = if ($response.user) { $response.user } else { $response }
    if ($response.access_token) {
        $stage = 'signup_confirmation_disabled'
        throw [InvalidOperationException]::new()
    }
    if ($null -ne $signupUser.identities -and $signupUser.identities.Count -eq 0) {
        $stage = 'recipient_already_registered'
        throw [InvalidOperationException]::new()
    }
    $stage = 'waiting_for_signup_link'
    Record-Result
    Write-Host 'Open the signup email and click Verify email address. The browser should show Your email is verified.'
    $confirmed = Read-Host -Prompt 'Type Y after the verified page appears, or press Enter to stop'
    if ($confirmed.Trim() -ine 'y') { throw [OperationCanceledException]::new() }
    $session = Send-AuthRequest -Path '/token?grant_type=password' -Payload @{ email = $Recipient; password = $password }
    if (-not $session.user.email_confirmed_at) { throw [InvalidOperationException]::new() }
    Revoke-TestSession -AccessToken $session.access_token
    $session = $null
    $password = $null
    $signupVerified = $true
    Write-Host 'The signup link was delivered, accepted, and followed by a successful password login.'
    $stage = 'requesting_recovery'
    Record-Result
    Send-AuthRequest -Path '/recover' -Payload @{ email = $Recipient } | Out-Null
    $stage = 'waiting_for_recovery_code'
    Record-Result
    Confirm-RecoveryCode
    $recoveryVerified = $true
    $stage = 'verified'
    Record-Result
    Write-Host 'Password reset code was delivered and verified.'
} catch {
    if ($_.Exception.Response) { $httpStatus = [int]$_.Exception.Response.StatusCode }
    Record-Result
    Write-Host ('Delivery test stopped at ' + $stage + $(if ($httpStatus) { ' (HTTP ' + $httpStatus + ')' } else { '' }) + '.')
    if ($stage -eq 'recipient_already_registered') { Write-Host 'Use a test address or Gmail plus alias that has never signed up for SecTalk.' }
} finally {
    $password = $null
    $session = $null
}
