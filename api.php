<?php
/*
 * HUBA Fragrances: website server file.
 * Upload it next to index.html. Needs PHP 7.4 or newer. It lets the Admin page save changes on your website instantly
 * (prices, stock, pictures, notes, password) and emails customer orders to $ORDER_TO.
 */

$ORDER_TO  = 'huba@huba.com.pk';   // customer orders are emailed here
$CURRENCY  = 'PKR';
$MAX_BODY  = 40 * 1024 * 1024;     // largest request accepted (your host's PHP limit may be lower)

$DIR      = __DIR__;
$CATALOG  = $DIR . '/catalog.json';
$AUTHFILE = $DIR . '/auth.php';
$UPLOADS  = $DIR . '/uploads';
$BACKUPS  = $DIR . '/backups';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function jerr($code, $msg, $extra = array()) { http_response_code($code); echo json_encode(array('ok' => false, 'error' => $msg) + $extra); exit; }
function jok($data = array()) { echo json_encode(array('ok' => true) + $data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE); exit; }
function is_https() { return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'); }

function start_session() {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $path = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'])), '/') . '/';
    session_name('huba_admin');
    session_set_cookie_params(array('lifetime' => 0, 'path' => $path, 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax'));
    @session_start();
}
function need_admin() {
    start_session();
    if (empty($_SESSION['admin'])) jerr(401, 'Please log in again.');
    $tok = isset($_SERVER['HTTP_X_CSRF']) ? $_SERVER['HTTP_X_CSRF'] : '';
    if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $tok)) jerr(403, 'Please log in again.');
}
function read_body() {
    global $MAX_BODY;
    $raw = file_get_contents('php://input');
    if ($raw === false || strlen($raw) > $MAX_BODY) jerr(413, 'The request is too large.');
    $in = json_decode($raw, true);
    if (!is_array($in)) jerr(400, 'The request could not be read.');
    return $in;
}
function client_ip() { return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'x'; }
// Simple per-visitor limit kept in temporary files: returns false when the limit is used up.
function rate_limit($name, $max, $window) {
    $f = sys_get_temp_dir() . '/huba_' . $name . '_' . md5(client_ip());
    $now = time(); $hits = array();
    if (is_file($f)) { $d = json_decode((string)@file_get_contents($f), true); if (is_array($d)) foreach ($d as $t) if ($now - $t < $window) $hits[] = $t; }
    if (count($hits) >= $max) return false;
    $hits[] = $now; @file_put_contents($f, json_encode($hits), LOCK_EX);
    return true;
}
function rate_reset($name) { @unlink(sys_get_temp_dir() . '/huba_' . $name . '_' . md5(client_ip())); }
function atomic_write($path, $data) {
    $tmp = $path . '.tmp' . bin2hex(random_bytes(4));
    if (file_put_contents($tmp, $data, LOCK_EX) === false) return false;
    if (!@rename($tmp, $path)) { @unlink($tmp); return false; }
    return true;
}
function load_auth() { global $AUTHFILE; $a = is_file($AUTHFILE) ? include $AUTHFILE : null; return (is_array($a) && isset($a['user'], $a['hash'])) ? $a : null; }
function load_catalog() { global $CATALOG; if (!is_file($CATALOG)) return null; $c = json_decode((string)file_get_contents($CATALOG), true); return is_array($c) ? $c : null; }

$action = isset($_GET['action']) ? (string)$_GET['action'] : '';
$method = $_SERVER['REQUEST_METHOD'];

/* ---------- ping: is the server file working, and is this browser logged in? ---------- */
if ($action === 'ping') {
    start_session();
    $authed = !empty($_SESSION['admin']);
    $out = array('app' => 'huba', 'authed' => $authed);
    if ($authed) { $a = load_auth(); $out['csrf'] = $_SESSION['csrf']; $out['user'] = $a ? $a['user'] : 'admin'; }
    jok($out);
}
if ($method !== 'POST') jerr(405, 'Use POST.');

/* ---------- login / logout ---------- */
if ($action === 'login') {
    $in = read_body();
    if (!rate_limit('login', 8, 900)) jerr(429, 'Too many attempts. Wait 15 minutes and try again.');
    $a = load_auth();
    $user = isset($in['user']) ? strtolower(trim((string)$in['user'])) : '';
    $pass = isset($in['pass']) ? (string)$in['pass'] : '';
    $okUser = $a && hash_equals(strtolower(trim($a['user'])), $user);
    $okPass = $a && password_verify($pass, $a['hash']); // always checked, so timing does not reveal the username
    if ($okUser && $okPass) {
        start_session(); session_regenerate_id(true);
        $_SESSION['admin'] = true; $_SESSION['csrf'] = bin2hex(random_bytes(16));
        rate_reset('login');
        jok(array('csrf' => $_SESSION['csrf'], 'user' => $a['user']));
    }
    usleep(800000);
    jerr(401, 'Incorrect username or password.');
}
if ($action === 'logout') {
    start_session(); $_SESSION = array(); @session_destroy();
    jok();
}

/* ---------- change username / password ---------- */
if ($action === 'password') {
    need_admin(); $in = read_body(); $a = load_auth();
    $cur = isset($in['current']) ? (string)$in['current'] : '';
    $user = isset($in['user']) ? trim((string)$in['user']) : '';
    $new = isset($in['password']) ? (string)$in['password'] : '';
    if (!rate_limit('pw', 8, 900)) jerr(429, 'Too many attempts. Try again later.');
    if (!$a || !password_verify($cur, $a['hash'])) jerr(400, 'Your current password is not correct.');
    if (!preg_match('/^[A-Za-z0-9._@ -]{3,40}$/', $user)) jerr(400, 'The username must be 3 to 40 letters, numbers or . _ @ - characters.');
    if (strlen($new) < 8 || strlen($new) > 200) jerr(400, 'The new password must be at least 8 characters.');
    $code = "<?php\n// HUBA admin login. Do not share this file.\nreturn " . var_export(array('user' => $user, 'hash' => password_hash($new, PASSWORD_DEFAULT)), true) . ";\n";
    if (!atomic_write($AUTHFILE, $code)) jerr(500, 'The password could not be saved. Check that auth.php is writable.');
    session_regenerate_id(true);
    jok(array('user' => $user));
}

/* ---------- save the catalogue (prices, stock, pictures, notes) ---------- */
function valid_id($s) { return is_string($s) && preg_match('/^[a-z0-9-]{1,140}$/', $s); }
function save_image($dataUri) {
    global $UPLOADS;
    if (!preg_match('#^data:image/jpeg;base64,([A-Za-z0-9+/=]+)$#', $dataUri, $m)) return null;
    $bin = base64_decode($m[1], true);
    if ($bin === false || strlen($bin) > 900 * 1024 || substr($bin, 0, 3) !== "\xFF\xD8\xFF") return null;
    $info = @getimagesizefromstring($bin);
    if (!$info || $info[2] !== IMAGETYPE_JPEG || $info[0] > 4000 || $info[1] > 4000) return null;
    if (function_exists('imagecreatefromstring')) { // re-encode: removes anything hidden inside the file
        $im = @imagecreatefromstring($bin);
        if ($im) { ob_start(); imagejpeg($im, null, 85); $re = ob_get_clean(); imagedestroy($im); if ($re) $bin = $re; }
    }
    $name = sha1($bin) . '.jpg';
    if (!is_dir($UPLOADS)) @mkdir($UPLOADS, 0755, true);
    $path = $UPLOADS . '/' . $name;
    if (!is_file($path) && file_put_contents($path, $bin, LOCK_EX) === false) return null;
    return 'uploads/' . $name;
}
function clean_picture($v) {
    global $UPLOADS;
    if (!is_string($v)) return null;
    if (strpos($v, 'data:') === 0) return save_image($v);
    if (preg_match('#^uploads/([a-f0-9]{40})\.jpg$#', $v, $m) && is_file($UPLOADS . '/' . $m[1] . '.jpg')) return $v;
    return null;
}
function clean_catalog($in) {
    $out = array('version' => 3, 'prices' => array(), 'images' => array(), 'soldOut' => array(), 'notes' => array(), 'notePics' => array());
    if (isset($in['prices']) && is_array($in['prices'])) foreach ($in['prices'] as $id => $pr) {
        if (!valid_id((string)$id) || !is_array($pr)) continue;
        $row = array(); $ok = true;
        foreach (array(30, 50, 100) as $s) {
            $v = isset($pr[$s]) ? $pr[$s] : (isset($pr[(string)$s]) ? $pr[(string)$s] : null);
            if (!is_numeric($v) || (int)$v != $v || $v < 1 || $v > 10000000) { $ok = false; break; }
            $row[(string)$s] = (int)$v;
        }
        if ($ok) $out['prices'][(string)$id] = $row;
    }
    if (isset($in['images']) && is_array($in['images'])) foreach ($in['images'] as $id => $v) {
        if (!valid_id((string)$id)) continue;
        $p = clean_picture($v); if ($p) $out['images'][(string)$id] = $p;
    }
    if (isset($in['soldOut']) && is_array($in['soldOut'])) foreach ($in['soldOut'] as $id) if (valid_id($id)) $out['soldOut'][$id] = $id;
    $out['soldOut'] = array_values($out['soldOut']);
    if (isset($in['notes']) && is_array($in['notes'])) foreach ($in['notes'] as $id => $n) {
        if (!valid_id((string)$id) || !is_array($n)) continue;
        $row = array(); $any = false;
        foreach (array('top', 'mid', 'base') as $t) {
            $row[$t] = array();
            if (isset($n[$t]) && is_array($n[$t])) foreach ($n[$t] as $name) {
                if (!is_string($name)) continue;
                $name = trim(preg_replace('/\s+/', ' ', $name));
                if ($name !== '' && strlen($name) <= 60 && count($row[$t]) < 12) { $row[$t][] = $name; $any = true; }
            }
        }
        if ($any) $out['notes'][(string)$id] = $row;
    }
    if (isset($in['notePics']) && is_array($in['notePics'])) foreach ($in['notePics'] as $k => $v) {
        if (!is_string($k) || !preg_match('/^[a-z0-9]{1,60}$/', $k)) continue;
        $p = clean_picture($v); if ($p) $out['notePics'][$k] = $p;
    }
    return $out;
}
if ($action === 'save') {
    need_admin(); $in = read_body();
    if (!isset($in['catalog']) || !is_array($in['catalog'])) jerr(400, 'Nothing to save.');
    if (!is_dir($BACKUPS)) @mkdir($BACKUPS, 0755, true);
    $lock = @fopen($BACKUPS . '/.lock', 'c');
    if ($lock) flock($lock, LOCK_EX);
    $current = load_catalog();
    $base = isset($in['base']) ? (string)$in['base'] : '';
    if ($current && isset($current['savedAt']) && $current['savedAt'] !== $base) jerr(409, 'Someone saved newer changes.', array('savedAt' => $current['savedAt']));
    $clean = clean_catalog($in['catalog']);
    $clean['savedAt'] = gmdate('Y-m-d\TH:i:s') . sprintf('.%03dZ', (int)(fmod(microtime(true), 1) * 1000));
    if ($current) { // keep the previous version, newest 30
        @copy($CATALOG, $BACKUPS . '/catalog-' . gmdate('Ymd-His') . '.json');
        $old = glob($BACKUPS . '/catalog-*.json'); if ($old && count($old) > 30) { sort($old); foreach (array_slice($old, 0, count($old) - 30) as $f) @unlink($f); }
    }
    if (!atomic_write($CATALOG, json_encode($clean, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))) jerr(500, 'The changes could not be saved. Check that this folder is writable.');
    // remove pictures nothing uses any more (keeps the newest 10 minutes in case of a slow save)
    $used = array(); foreach (array_merge(array_values($clean['images']), array_values($clean['notePics'])) as $u) $used[basename($u)] = true;
    foreach ((array)glob($UPLOADS . '/*.jpg') as $f) if (!isset($used[basename($f)]) && time() - filemtime($f) > 600) @unlink($f);
    if ($lock) { flock($lock, LOCK_UN); fclose($lock); }
    jok(array('catalog' => $clean));
}

/* ---------- customer order: email it to the shop ---------- */
function str_cut($s, $max) { return function_exists('mb_substr') ? mb_substr((string)$s, 0, $max) : substr((string)$s, 0, $max); }
function one_line($s, $max) { return trim(str_cut(preg_replace('/[\r\n\t]+/', ' ', (string)$s), $max)); }
if ($action === 'order') {
    $in = read_body();
    if (!empty($in['website'])) jok(); // hidden field only robots fill in
    if (!rate_limit('order', 6, 600)) jerr(429, 'Too many orders from this connection. Try again in a few minutes.');
    $o = isset($in['order']) && is_array($in['order']) ? $in['order'] : jerr(400, 'The order could not be read.');
    $c = isset($o['customer']) && is_array($o['customer']) ? $o['customer'] : jerr(400, 'The order could not be read.');
    $number = isset($o['number']) ? (string)$o['number'] : '';
    if (!preg_match('/^HUBA-[A-Z0-9]{6}$/', $number)) jerr(400, 'The order could not be read.');
    $name = one_line(isset($c['name']) ? $c['name'] : '', 100); $email = trim((string)(isset($c['email']) ? $c['email'] : ''));
    $phone = one_line(isset($c['phone']) ? $c['phone'] : '', 40); $addr = one_line(isset($c['address']) ? $c['address'] : '', 200);
    $city = one_line(isset($c['city']) ? $c['city'] : '', 80); $postal = one_line(isset($c['postal']) ? $c['postal'] : '', 20);
    $notes = trim(str_cut(str_replace("\r", '', (string)(isset($c['notes']) ? $c['notes'] : '')), 500));
    $pay = one_line(isset($o['payment']) ? $o['payment'] : '', 60);
    if ($name === '' || $phone === '' || $addr === '' || $city === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 120) jerr(400, 'Some order details are missing.');
    $items = isset($o['items']) && is_array($o['items']) ? $o['items'] : array();
    if (!$items || count($items) > 40) jerr(400, 'The order has no items.');
    $cat = load_catalog(); $lines = array(); $sub = 0; $warn = array();
    foreach ($items as $it) {
        if (!is_array($it)) jerr(400, 'The order could not be read.');
        $size = (int)(isset($it['sizeMl']) ? $it['sizeMl'] : 0); $qty = (int)(isset($it['qty']) ? $it['qty'] : 0); $unit = (int)(isset($it['unitPrice']) ? $it['unitPrice'] : 0);
        if (!in_array($size, array(30, 50, 100), true) || $qty < 1 || $qty > 50 || $unit < 1 || $unit > 10000000) jerr(400, 'The order could not be read.');
        $id = isset($it['id']) ? (string)$it['id'] : '';
        if ($cat && valid_id($id) && isset($cat['prices'][$id][(string)$size]) && (int)$cat['prices'][$id][(string)$size] !== $unit)
            $warn[] = one_line(isset($it['name']) ? $it['name'] : $id, 80) . ' ' . $size . ' ml: customer price ' . $unit . ', your saved price ' . (int)$cat['prices'][$id][(string)$size];
        $sub += $unit * $qty;
        $insp = one_line(isset($it['inspiredBy']) ? $it['inspiredBy'] : '', 80);
        $lines[] = '- ' . one_line(isset($it['name']) ? $it['name'] : '', 120) . ($insp !== '' ? ' (inspired by ' . $insp . ')' : '') . ', ' . $size . ' ml x ' . $qty . ' = ' . $CURRENCY . ' ' . number_format($unit * $qty);
    }
    $ship = (int)(isset($o['delivery']) ? $o['delivery'] : 0); if ($ship < 0 || $ship > 100000) $ship = 0;
    $body = "Order $number\nDate: " . gmdate('Y-m-d H:i') . " UTC\n\nName: $name\nEmail: $email\nPhone: $phone\nAddress: $addr, $city" . ($postal !== '' ? " $postal" : '') . "\nPayment: $pay\n" . ($notes !== '' ? "Notes: $notes\n" : '')
        . "\nItems:\n" . implode("\n", $lines) . "\n\nSubtotal: $CURRENCY " . number_format($sub) . "\nDelivery: " . ($ship ? "$CURRENCY " . number_format($ship) : 'Free') . "\nTotal: $CURRENCY " . number_format($sub + $ship) . "\n";
    if ($warn) $body .= "\nCHECK PRICES: the customer's prices differ from your saved prices:\n- " . implode("\n- ", $warn) . "\n";
    $host = preg_replace('/[^a-z0-9.-]/', '', strtolower(preg_replace('/:\d+$/', '', isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost')));
    $headers = "From: HUBA Store <noreply@$host>\r\nReply-To: $email\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n";
    $subject = "New HUBA order $number (" . $CURRENCY . ' ' . number_format($sub + $ship) . ')';
    $log = getenv('HUBA_MAIL_LOG'); // used only for testing without a mail server
    if ($log) { $sent = file_put_contents($log, "TO: $ORDER_TO\nSUBJECT: $subject\n$body\n----\n", FILE_APPEND) !== false; }
    else { $sent = @mail($ORDER_TO, $subject, $body, $headers); }
    if (!$sent) jerr(502, 'The email could not be sent.');
    jok(array('number' => $number));
}

jerr(404, 'Unknown request.');
