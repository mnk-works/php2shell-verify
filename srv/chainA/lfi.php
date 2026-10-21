<?php
// Chain A: deliberately vulnerable LFI (this IS the vulnerability under test,
// mirroring the documented "app has LFI" precondition). My own code, not the lab's.
$page = $_GET['page'] ?? '';
include($page);
