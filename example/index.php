<?php
/**
 * Opauth webroot catchall
 * - Only required if you are sending traffic directly to Opauth's webroot
 * - If you instantiate Opauth directly from your app or PHP framework, this will not be run.
 * 
 */

/**
 * Define paths
 */
define('OPAUTH_EXAMPLE', dirname(__FILE__).'/');
define('OPAUTH_LIB', dirname(OPAUTH_EXAMPLE).'/lib/Opauth/');

/**
* Load config
*/
if (!file_exists(OPAUTH_EXAMPLE.'opauth.conf.php')){
	trigger_error('Config file missing at '.OPAUTH_EXAMPLE.'opauth.conf.php', E_USER_ERROR);
	exit();
}
require OPAUTH_EXAMPLE.'opauth.conf.php';

/**
 * Instantiate Opauth with the loaded config
 */
require OPAUTH_LIB.'opauth.php';
$Opauth = new Opauth( $config );