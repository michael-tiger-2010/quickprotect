<?php
// Configurable time limit (in seconds). Must be over 10.
$time_limit = 10;

// CHANGE THIS TO AN UNIQUE VALUE FOR YOUR SITE
$salt = "examplesalt";

$v = $_COOKIE["mathdragon-proof-verif-time"];
$a = $_COOKIE["mathdragon-proof-verif-answer"];
$s = $_COOKIE["mathdragon-proof-verif-secret"];
$current_time = time();
function e(){global $salt; echo str_replace("[--salt--]", $salt, file_get_contents("https://rawcdn.githack.com/michael-tiger-2010/quickprotect/refs/heads/main/show.html"));}
if ($current_time - intval($v)/1000 > $time_limit) {e();die();}
$expected_hash = hash('sha256', strval(intval($v) + intval($s)) . $salt);
if ($a !== $expected_hash) {e();die();}
?>

Rest of html here.
