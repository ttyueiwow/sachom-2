<?php
session_start();

// ---------- CONFIG ----------
$dataFile        = '/data/attempts.json';
$DASHBOARD_PASS  = 'SecureDash@2025';  // 🔐 CHANGE THIS

// ---------- AUTH ----------
if (isset($_GET['logout'])) {
    unset($_SESSION['dash_auth']);
    header("Location: dashboard.php");
    exit;
}

// If not authenticated, show login form
if (empty($_SESSION['dash_auth'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $pass = $_POST['password'] ?? '';
        if (hash_equals($DASHBOARD_PASS, $pass)) {
            $_SESSION['dash_auth'] = true;
            header("Location: dashboard.php");
            exit;
        } else {
            $error = "Incorrect dashboard password.";
        }
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard Login</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f3f4f7;
                display:flex;
                align-items:center;
                justify-content:center;
                height:100vh;
                margin:0;
            }
            .card {
                background:#fff;
                padding:20px 24px;
                border-radius:6px;
                box-shadow:0 2px 6px rgba(0,0,0,0.12);
                width:320px;
            }
            h2 { margin-top:0; font-size:18px; }
            label { font-size:13px; display:block; margin-bottom:6px; }
            input[type="password"] {
                width:100%;
                padding:8px;
                border:1px solid #ccc;
                border-radius:4px;
                font-size:13px;
            }
            button {
                margin-top:12px;
                width:100%;
                padding:8px;
                background:#1976d2;
                color:#fff;
                border:none;
                border-radius:4px;
                font-size:13px;
                font-weight:bold;
                cursor:pointer;
            }
            button:hover { background:#145ea7; }
            .error {
                color:#c62828;
                margin-bottom:8px;
                font-size:13px;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Admin Access</h2>
            <?php if (!empty($error)): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <form method="POST">
                <label>Dashboard Password</label>
                <input type="password" name="password" required>
                <button type="submit">Enter</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// ---------- LOAD DATA ----------
if (file_exists($dataFile)) {
    $raw     = file_get_contents($dataFile);
    $decoded = json_decode($raw, true);
    $data    = is_array($decoded) ? $decoded : [];
} else {
    $data = [];
}

// Normalise timestamp
foreach ($data as $email => $row) {
    if (!isset($data[$email]['time'])) {
        $data[$email]['time'] = date('Y-m-d H:i:s');
    }
}

// Sort: most recent first
uasort($data, function($a, $b) {
    return strtotime($b['time']) <=> strtotime($a['time']);
});

// Stats
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
.clear-btn, .logout-btn {
    display: inline-block;
    padding: 8px 14px;
    color: #fff;
    text-decoration: none;
    border-radius: 4px;
    font-weight: bold;
    font-size: 13px;
    margin-right: 8px;
}
.clear-btn {
    background: #c62828;
}
.clear-btn:hover {
    background: #a72222;
}
.logout-btn {
    background: #555;
}
.logout-btn:hover {
    background: #333;
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

<h2>Login Attempt Dashboard</h2>

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
    <a href="dashboard.php?logout=1" class="logout-btn">Logout</a>
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
