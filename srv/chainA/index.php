<?php
// Chain A target: any POST endpoint that triggers a session
session_start();
echo "PHP " . PHP_VERSION . " SAPI " . php_sapi_name() .
     " upload_progress=" . ini_get('session.upload_progress.enabled') .
     " save_path=" . ini_get('session.save_path') . "\n";
