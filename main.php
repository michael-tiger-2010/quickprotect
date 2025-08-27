<?php
// Time until forced interstitial
$time_limit = 3600;

// CHANGE THIS TO AN UNIQUE VALUE FOR YOUR SITE
$salt = "mathdragonsalt";

// The number of seconds after which IP data is cleared.
$seconds_before_clear = 20;

// The number of hits before a PoW is triggered.
$hits_threshold = 5;

// The file path for storing IP data. For security, place this outside the web root if possible.
$ip_data_file = "/home/vol12_6/infinityfree.com/if0_37757553/htdocs/protection/ips.txt";




$clear_threshold = 15; //if a user sees the "it's too fast" message, make this larger.
$interstitial_url = "https://rawcdn.githack.com/michael-tiger-2010/quickprotect/d72727feb17473f7e3d310ee9962431fb6f5dd5c/interstitial-min.html"; //Aug 27 2025

// ************************** //
function read_and_write_ip_data($file_path, callable $callback) {
    $fp = fopen($file_path, 'c+');
    if ($fp === false) {
        error_log("Failed to open file for IP data: $file_path");
        return;
    }
    if (flock($fp, LOCK_EX)) {
        $content = stream_get_contents($fp, -1, 0);
        $data = json_decode($content, true) ?: [];
        $data = $callback($data);
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
        flock($fp, LOCK_UN);
    } else {
        error_log("Failed to acquire exclusive lock on IP data file: $file_path");
    }
    fclose($fp);
}
$v = $_COOKIE["mathdragon-proof-verif-time"] ?? null;
$a = $_COOKIE["mathdragon-proof-verif-answer"] ?? null;
$s = $_COOKIE["mathdragon-proof-verif-secret"] ?? null;
$current_time = time();
$is_pow_valid = ($v && $a && $s) && ($current_time - intval($v) / 1000 <= $time_limit) && str_starts_with($a, "0000") && $a === hash('sha256', $v . $s . $salt);
$trigger_pow = false;
$ip = $_SERVER['REMOTE_ADDR'];
read_and_write_ip_data($ip_data_file, function($ip_data) use ($current_time, $seconds_before_clear, $ip, $is_pow_valid, $clear_threshold, $hits_threshold, $time_limit, $v, &$trigger_pow) {
    $ip_data = array_filter($ip_data, fn($entry) => ($current_time - $entry['timestamp']) < $seconds_before_clear);    
    $time_to_use = $current_time;
    if(isset($ip_data[$ip])){
        $time_to_use = $ip_data[$ip]["timestamp"];
        if($current_time - intval($v)/1000 < $clear_threshold){
            $ip_data[$ip]['count'] = 0;
        }
    }
    $ip_data[$ip] = ['count' => ($ip_data[$ip]['count'] ?? 0) + 1, 'timestamp' => $time_to_use];
    if ($ip_data[$ip]['count'] > $hits_threshold) {
        $trigger_pow = true;
    }
    return $ip_data;
});
if (!$is_pow_valid || $trigger_pow) {
    echo str_replace("[--salt--]", $salt, file_get_contents($interstitial_url));
    die();
}
