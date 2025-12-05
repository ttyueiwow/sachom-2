<?php
require __DIR__ . '/backend_common.php';

handle_cors_preflight_if_needed();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
$turnstile_response = $_POST['cf-turnstile-response'] ?? '';
$honeypot = trim($_POST['company'] ?? '');

if ($honeypot !== '') {
    // Bot filled hidden field
    json_response(['ok' => false, 'error' => 'Unexpected error. Please try again.']);
}

if (!$email) {
    json_response(['ok' => false, 'error' => 'Invalid email address.']);
}

// Verify Turnstile
$ip = get_client_ip();
$ch = curl_init("https://challenges.cloudflare.com/turnstile/v0/siteverify");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'secret'   => TURNSTILE_SECRET,
    'response' => $turnstile_response,
    'remoteip' => $ip
]));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$turnstile_result = json_decode(curl_exec($ch), true);
curl_close($ch);

if (empty($turnstile_result['success'])) {
    json_response(['ok' => false, 'error' => 'Security check failed. Please try again.']);
}

// Email whitelist
if (EMAIL_VALIDATION_ENABLED) {
    $whitelist = load_whitelist();
    if (!in_array($email, $whitelist, true)) {
        json_response(['ok' => false, 'error' => 'Recipient email required']);
    }
}

// Everything ok → issue step token
$token = issue_step_token($email, $ip);

json_response([
    'ok'    => true,
    'token' => $token,
    'email' => $email
]);
