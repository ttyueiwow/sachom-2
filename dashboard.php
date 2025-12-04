<?php
session_start();

// Admin password (better: set in env ADMIN_DASH_PASSWORD)
$ADMIN_PASSWORD = getenv('ADMIN_DASH_PASSWORD') ?: 'ChangeThisPassword123';

// Log file
$dataFile = '/data/attempts.json';

// Handle login POST
$login_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_pass'])) {
    $pass = $_POST['admin_pass'] ?? '';
    if (hash_equals($ADMIN_PASSWORD, $pass)) {
        $_SESSION['admin_ok'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $login_error = 'Invalid password.';
    }
}

// If not logged in as admin → show login form only
if (empty($_SESSION['admin_ok'])):
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Admin Login – Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background:#f5f5f5;
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
            box-shadow:0 6px 18px rgba(0,0,0,0.12);
            width:100%;
            max-width:320px;
        }
        h2 {
            margin:0 0 10px;
            font-size:18px;
        }
        .error {
            color:#c9252d;
            font-size:13px;
            margin-bottom:8px;
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
        }
        button {
            margin-top:10px;
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
    <h2>Dashboard Login</h2>
    <?php if ($login_error): ?>
        <div class="error"><?= htmlspecialchars($login_error) ?></div>
    <?php endif; ?>
    <form method="POST">
        <label for="admin_pass">Admin password</label>
        <input type="password" id="admin_pass" name="admin_pass" required>
        <button type="submit">Access dashboard</button>
    </form>
</div>
</body>
</html>
<?php
exit;
endif;

// If we’re here → authenticated
if (file_exists($dataFile)) {
    $raw = file_get_contents($dataFile);
    $decoded = json_decode($raw, true);
    $data = is_array($decoded) ? $decoded : [];
} else {
    $data = [];
}

// Simple totals
$totalEmails   = count($data);
$totalAttempts = 0;
foreach ($data as $row) {
    $totalAttempts += (int)($row['count'] ?? 0);
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Login Attempt Dashboard</title>
<style>
body { font-family: Arial, sans-serif; padding: 20px; background: #f7f7f7; }
h1 { margin-top:0; }
.summary {
    display:flex;
    gap:16px;
    margin-bottom:16px;
    flex-wrap:wrap;
}
.card {
    background:#fff;
    padding:10px 14px;
    border-radius:4px;
    box-shadow:0 2px 6px rgba(0,0,0,0.08);
    font-size:14px;
}
table { border-collapse: collapse; width: 100%; background: #fff; margin-top:10px; }
th { background: #333; color: #fff; }
td, th { padding: 8px; border: 1px solid #ccc; font-size: 13px; }
tr:nth-child(even) { background: #f2f2f2; }
.small { font-size:12px; color:#666; }
.logout {
    text-align:right;
    margin-bottom:12px;
}
.logout form { display:inline; }
.logout button {
    border:none;
    background:#e53e3e;
    color:#fff;
    padding:4px 10px;
    border-radius:3px;
    cursor:pointer;
    font-size:12px;
}
.logout button:hover { background:#c53030; }
</style>
</head>
<body>

<div class="logout">
    <form method="post" action="?logout=1">
        <input type="hidden" name="admin_pass" value="" />
        <button type="submit" name="logout_btn" onclick="event.preventDefault(); document.cookie=''; window.location='?logout=1';">Log out</button>
    </form>
</div>

<?php
// Handle logout via GET ?logout=1
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}
?>

<h1>Login Attempt Dashboard</h1>

<div class="summary">
    <div class="card">
        <strong>Total tracked emails:</strong> <?= htmlspecialchars((string)$totalEmails) ?>
    </div>
    <div class="card">
        <strong>Total attempts:</strong> <?= htmlspecialchars((string)$totalAttempts) ?>
    </div>
</div>

<table>
    <tr>
        <th>Email</th>
        <th>Names Tried</th>
        <th>Total Attempts</th>
        <th>IP Address</th>
        <th>Location</th>
        <th>Last Time</th>
    </tr>

    <?php if (empty($data)): ?>
        <tr>
            <td colspan="6" style="text-align:center; padding:20px; color:#666;">
                No attempts logged yet.
            </td>
        </tr>
    <?php endif; ?>

    <?php foreach ($data as $email => $row): ?>
        <tr>
            <td><?= htmlspecialchars($email) ?></td>
            <td><?= htmlspecialchars(implode(", ", $row["names"] ?? [])) ?></td>
            <td><?= htmlspecialchars((string)($row["count"] ?? 0)) ?></td>
            <td><?= htmlspecialchars($row["ip"] ?? '') ?></td>
            <td><?= htmlspecialchars($row["location"] ?? '') ?></td>
            <td><?= htmlspecialchars($row["time"] ?? '') ?></td>
        </tr>
    <?php endforeach; ?>
</table>

<p class="small">
    Data source: <?= htmlspecialchars($dataFile) ?>  
</p>

</body>
</html>
