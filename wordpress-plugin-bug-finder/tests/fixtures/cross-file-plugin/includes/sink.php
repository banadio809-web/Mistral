<?php
/**
 * The vulnerable callback body lives here while its entry-point hook is
 * registered in the plugin main file — the classic cross-file case.
 */

function grab_records() {
    global $wpdb;
    $order = wpbf_decode($_GET['order']);
    $wpdb->query("SELECT * FROM wp_options ORDER BY " . $order);
}

function wpbf_decode($v) {
    return str_replace('"', '', $v);
}
