<?php
/*
 * Plugin Name: Cross File Plugin
 * Version: 1.0.0
 */

add_action('wp_ajax_nopriv_grab', 'grab_records');

include 'includes/sink.php';
