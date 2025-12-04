<?php
session_start();

/**
 * Admin password for the dashboard
 * Prefer: set ENV var ADMIN_DASH_PASSWORD in Railway
 */
$ADMIN_PASSWORD = getenv('ADMIN_DASH_PASSWORD') ?: 'ChangeThisPassword123'; // change this

// Handle logout
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Handle login POST
$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_pass']) && !isset($_SESSION['admin_ok'])) {
    $pass = $_POST['admin_pass'] ?? '';
    if (hash_equals($ADMIN_PASSWORD, $pass)) {
        $_SESSION['admin_ok'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Invalid password.';
    }
}

// If not authenticated → show login form ONLY
if (empty($_SESSION['admin_ok'])):
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Dashboard Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background:#f3f4f7;
            display:flex;
            align-items:center;
            justify-content:center;
            height:100vh;
            margin:0;
        }
        .card {
            background:#fff;
            padding:20px 24px;
            border-radius:8px;
            box-shadow:0 8px 24px rgba(0,0,0,0.12);
            width:100%;
            max-width:320px;
            border:1px solid #e0e0e0;
        }
        h2 {
            margin:0 0 10px;
            font-size:18px;
        }
        .subtitle {
            font-size:12px;
            color:#666;
            margin-bottom:14px;
        }
        .error {
            color:#c62828;
            font-size:13px;
            margin-bottom:10px;
        }
        label {
            font-size:13px;
            display:block;
            margin-bottom:4px;
        }
        input[type=password] {
            width:100%;
            padding:8px;
            font-size:14px;
            border-radius:4px;
            border:1px solid #ccc;
            margin-bottom:10px;
        }
        button {
            width:100%;
            padding:9px;
            background:#1473e6;
            color:#fff;
            border:none;
            border-radius:4px;
            cursor:pointer;
            font-size:14px;
            font-weight:600;
        }
        button:hover { background:#0f5cc0; }
    </style>
</head>
<body>
<div class="card">
    <h2>Login Attempt Dashboard</h2>
    <div class="subtitle">Admin access required</div>

    <?php if ($login_error): ?>
        <div class="error"><?= htmlspecialchars($login_error) ?></div>
    <?php endif; ?>

    <form method="POST">
        <label for="admin_pass">Dashboard password</label>
        <input type="password" id="admin_pass" name="admin_pass" required>
        <button type="submit">Access dashboard</button>
    </form>
</div>
</body>
</html>
<?php
exit;
endif;

/* ===========================
   AUTHENTICATED VIEW BELOW
   =========================== */

$dataFile = '/data/attempts.json';

if (file_exists($dataFile)) {
    $raw = file_get_contents($dataFile);
    $decoded = json_decode($raw, true);
    $data = is_array($decoded) ? $decoded : [];
} else {
    $data = [];
}

/* -------------------------------------------
   Normalise + add timestamps if missing
--------------------------------------------*/
foreach ($data as $email => $row) {
    if (!isset($data[$email]['time'])) {
        $data[$email]['time'] = date('Y-m-d H:i:s');
    }
}

/* -------------------------------------------
   Sort by most recent activity
--------------------------------------------*/
uasort($data, function($a, $b) {
    return strtotime($b['time']) <=> strtotime($a['time']);
});

/* -------------------------------------------
   Stats
--------------------------------------------*/
$totalEmails    = count($data);
$totalAttempts  = 0;
$ips            = [];
$topEmail       = null;
$topEmailCount  = 0;

foreach ($data as $email => $row) {
    $count = isset($row['count']) ? (int)$row['count'] : 0;
    $totalAttempts += $count;

    if (!empty($row['ip'])) {
        $ips[] = $row['ip'];
    }

    if ($count > $topEmailCount) {
        $topEmailCount = $count;
        $topEmail      = $email;
    }
}

$totalUniqueIps = count(array_unique($ips));
?>
<!DOCTYPE html>
<html>
<head>
<title>Login Attempt Dashboard</title>
<style>
body {
    font-family: Arial, sans-serif;
    padding: 20px;
    background: #f3f4f7;
    color: #222;
}
h2 {
    margin-top: 0;
}
.header-bar {
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:12px;
}
.logout-btn {
    border:none;
    background:#e53935;
    color:#fff;
    padding:6px 10px;
    border-radius:4px;
    cursor:pointer;
    font-size:12px;
    font-weight:600;
}
.logout-btn:hover {
    background:#c62828;
}
.metrics {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
}
.metric-card {
    flex: 1 1 160px;
    background: #fff;
    border-radius: 6px;
    padding: 12px 14px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    border: 1px solid #e0e0e0;
}
.metric-label {
    font-size: 12px;
    color: #777;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}
.metric-value {
    font-size: 20px;
    font-weight: bold;
}
.metric-sub {
    font-size: 11px;
    color: #999;
    margin-top: 2px;
}

.actions {
    margin: 10px 0 16px;
}
.clear-btn {
    display: inline-block;
    padding: 8px 14px;
    background: #c62828;
    color: #fff;
    text-decoration: none;
    border-radius: 4px;
    font-weight: bold;
    font-size: 13px;
}
.clear-btn:hover {
    background: #a72222;
}

table {
    border-collapse: collapse;
    width: 100%;
    background: #fff;
    border-radius: 6px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
th {
    background: #333;
    color: #fff;
}
td, th {
    padding: 10px;
    border: 1px solid #ddd;
    font-size: 13px;
}
tr:nth-child(even) {
    background: #f7f7f7;
}
td.small {
    font-size: 12px;
    color: #555;
}
</style>
</head>
<body>

<div class="header-bar">
    <h2>Login Attempt Dashboard</h2>
    <form method="GET" action="">
        <button type="submit" name="logout" value="1" class="logout-btn">Log out</button>
    </form>
</div>

<div class="metrics">
    <div class="metric-card">
        <div class="metric-label">Total Attempts</div>
        <div class="metric-value"><?= htmlspecialchars($totalAttempts) ?></div>
        <div class="metric-sub">Sum of all login attempts</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Unique Emails</div>
        <div class="metric-value"><?= htmlspecialchars($totalEmails) ?></div>
        <div class="metric-sub">Distinct email addresses seen</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Unique IPs</div>
        <div class="metric-value"><?= htmlspecialchars($totalUniqueIps) ?></div>
        <div class="metric-sub">Distinct source IP addresses</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Top Email (by attempts)</div>
        <div class="metric-value" style="font-size:14px; word-break:break-all;">
            <?= $topEmail ? htmlspecialchars($topEmail) : '—' ?>
        </div>
        <div class="metric-sub">
            <?= $topEmail ? htmlspecialchars($topEmailCount) . ' attempt(s)' : 'No data yet' ?>
        </div>
    </div>
</div>

<div class="actions">
    <a href="clear-log.php" class="clear-btn"
       onclick="return confirm('Are you sure you want to CLEAR all log records?');">
        Clear Logs
    </a>
</div>

<table>
<tr>
    <th>#</th>
    <th>Email</th>
    <th>Names Tried</th>
    <th>Total Attempts</th>
    <th>IP Address</th>
    <th>Location</th>
    <th>Last Updated</th>
</tr>

<?php if (empty($data)): ?>
<tr>
    <td colspan="7" style="text-align:center; padding:20px; color:#666;">
        No attempts logged yet.
    </td>
</tr>
<?php endif; ?>

<?php
$idx = 1;
foreach ($data as $email => $row):
    $names    = isset($row['names']) ? $row['names'] : [];
    $count    = isset($row['count']) ? $row['count'] : 0;
    $ip       = isset($row['ip']) ? $row['ip'] : '';
    $location = isset($row['location']) ? $row['location'] : '';
    $time     = isset($row['time']) ? $row['time'] : '';
?>
<tr>
    <td class="small"><?= $idx++ ?></td>
    <td><?= htmlspecialchars($email) ?></td>
    <td class="small"><?= htmlspecialchars(implode(", ", $names)) ?></td>
    <td><?= htmlspecialchars($count) ?></td>
    <td class="small"><?= htmlspecialchars($ip) ?></td>
    <td class="small"><?= htmlspecialchars($location) ?></td>
    <td class="small"><?= htmlspecialchars($time) ?></td>
</tr>
<?php endforeach; ?>

</table>

</body>
</html>
