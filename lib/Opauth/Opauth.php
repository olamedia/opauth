<?php
/**
 * Opauth
 * Multi-provider authentication framework for PHP
 * 
 * This is a fork
 *
 * @copyright    Copyright © 2012 U-Zyn Chua (http://uzyn.com)
 * @copyright    Copyright © 2013 olamedia (olamedia@gmail.com)
 * @link         http://opauth.org
 * @package      Opauth
 * @license      MIT License
 */

/**
 * Opauth
 * Multi-provider authentication framework for PHP
 * 
 * @package			Opauth
 */
class Opauth {
	/**
	 * User configurable settings
	 * Refer to example/opauth.conf.php.default or example/opauth.conf.php.advanced for sample
	 * More info: https://github.com/uzyn/opauth/wiki/Opauth-configuration
	 */
	public $config;
	
	/** 
	 * Strategy map: for mapping URL-friendly name to Class name
	 */
	public $strategyMap;
	
	/**
	 * Constructor
	 * Loads user configuration and strategies.
	 * 
	 * @param array $config User configuration
	 * @param boolean $run Whether Opauth should auto run after initialization.
	 */
	public function __construct($config = []) {
		$defaults = [
			'host' => 'http'.((array_key_exists('HTTPS', $_SERVER) && $_SERVER['HTTPS'])?'s':'').'://'.$_SERVER['HTTP_HOST'],
			'path' => '/',
			'callback_url' => '/callback',
			'callback_transport' => 'session',
			'debug' => false,
			'security_salt' => null,
			'security_iteration' => 300,
			'security_timeout' => '2 minutes',
			'request_uri' => $_SERVER['REQUEST_URI'],
			'complete_path' => $config['host'].$config['path'],
		];
		$config = array_merge($defaults, $config);
		$this->config = $config;
		
		if (null === $this->config['security_salt']){
			trigger_error('Please change the value of \'security_salt\' to a salt value specific to your application', E_USER_NOTICE);
		}
	}
	
	public function runStrategy($strategyClass, $strategyConfig = [], $action = null){
		$this->Strategy = new $strategyClass($strategyConfig, $this->config);
		$this->Strategy->callAction(null===$action?'request':$action); // 'request' is for compatibility only
	}
	
	/**
	 * Validate $auth response
	 * Accepts either function call or HTTP-based call
	 * 
	 * @param string $input = sha1(print_r($auth, true))
	 * @param string $timestamp = $_REQUEST['timestamp'])
	 * @param string $signature = $_REQUEST['signature']
	 * @param string $reason Sets reason for failure if validation fails
	 * @return boolean true: valid; false: not valid.
	 */
	public function validate($input = null, $timestamp = null, $signature = null, &$reason = null) {
		$functionCall = true;
		if (!empty($_REQUEST['input']) && !empty($_REQUEST['timestamp']) && !empty($_REQUEST['signature'])) {
			$functionCall = false;
			$provider = $_REQUEST['input'];
			$timestamp = $_REQUEST['timestamp'];
			$signature = $_REQUEST['signature'];
		}
		
		$timestamp_int = strtotime($timestamp);
		if ($timestamp_int < strtotime('-'.$this->env['security_timeout']) || $timestamp_int > time()) {
			$reason = "Auth response expired";
			return false;
		}
		
		$hash = OpauthStrategy::hash($input, $timestamp, $this->config['security_iteration'], $this->config['security_salt']);
		
		if (strcasecmp($hash, $signature) !== 0) {
			$reason = "Signature does not validate";
			return false;
		}
		
		return true;
	}
	
	/**
	 * Callback: prints out $auth values, and acts as a guide on Opauth security
	 * Application should redirect callback URL to application-side.
	 * Refer to example/callback.php on how to handle auth callback.
	 */
	public function callback() {
		echo "<strong>Note: </strong>Application should set callback URL to application-side for further specific authentication process.\n<br>";
		
		$response = null;
		switch($this->env['callback_transport']) {
			case 'session':
				if (!session_id()) {
					session_start();
					$response = $_SESSION['opauth'];
					unset($_SESSION['opauth']);
				}
				break;
			case 'post':
				$response = unserialize(base64_decode( $_POST['opauth'] ));
				break;
			case 'get':
				$response = unserialize(base64_decode( $_GET['opauth'] ));
				break;
			default:
				echo '<strong style="color: red;">Error: </strong>Unsupported callback_transport.'."<br>\n";
				break;
		}
		
		
		if (array_key_exists('error', $response)) {  // Check if it's an error callback
			echo '<strong style="color: red;">Authentication error: </strong> Opauth returns error auth response.'."<br>\n";
		} else { // No it isn't. Proceed with auth validation
			if (empty($response['auth']) || empty($response['timestamp']) || empty($response['signature']) || empty($response['auth']['provider']) || empty($response['auth']['uid'])) {
				echo '<strong style="color: red;">Invalid auth response: </strong>Missing key auth response components.'."<br>\n";
			} elseif (!$this->validate(sha1(print_r($response['auth'], true)), $response['timestamp'], $response['signature'], $reason)) {
				echo '<strong style="color: red;">Invalid auth response: </strong>'.$reason.".<br>\n";
			} else {
				echo '<strong style="color: green;">OK: </strong>Auth response is validated.'."<br>\n";
			}
		}		
		
		/**
		 * Auth response dump
		 */
		echo "<pre>";
		print_r($response);
		echo "</pre>";
	}

	
	/**
	 * Prints out variable with <pre> tags
	 * Silence if Opauth is not in debug mode
	 * 
	 * @param mixed $var Object or variable to be printed
	 */	
	public function debug($var) {
		if ($this->env['debug'] !== false) {
			echo "<pre>";
			print_r($var);
			echo "</pre>";
		}
	}
}
