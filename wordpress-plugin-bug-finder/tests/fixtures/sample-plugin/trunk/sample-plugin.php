<?php
/**
 * Plugin Name: Sample Plugin
 * Version: 1.2.3
 */
// no ABSPATH guard on purpose

class Sample_Plugin {

    public function __construct() {
        add_action( 'wp_ajax_nopriv_sp_load', array( $this, 'ajax_load' ) );
        add_action( 'wp_ajax_sp_save', array( $this, 'ajax_save' ) );
        add_shortcode( 'sp_render', array( $this, 'shortcode_render' ) );
    }

    public function ajax_load() {
        $id = $_GET['id'];
        global $wpdb;
        $rows = $wpdb->get_results( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" );
        echo $rows[0]->post_title;
    }

    public function ajax_save() {
        $title = sanitize_text_field( $_POST['title'] );
        update_option( 'sp_title', $title );
        $raw = $_POST['url'];
        update_option( 'sp_url', $raw );
        wp_redirect( $_POST['redirect'] );
    }

    public function shortcode_render( $atts ) {
        $atts = shortcode_atts( array( 'x' => '' ), $atts );
        echo '<div>' . $_GET['q'] . '</div>';
    }
}

new Sample_Plugin();
