<?php
// Chain C write endpoint. Handler comes from .user.ini in this directory.
session_start();
echo "OK handler=" . ini_get('session.serialize_handler') . "\n";
