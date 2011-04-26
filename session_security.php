<?php
/**
 * Session Security Class
 * 
 * Include as part of your project for increased session security by
 * creating an instance of this object on each page load.
 * 
 * On each load, a fingerprint unique to the user's browser at that point
 * in time is created and then verified against the fingerprint generated
 * on the previous page load. If a mismatch occurs, we drop the contents
 * of the session as it has been compromised.
 * 
 * @author Chris Martin
 * @copyright Copyright (C) 2011 Chris Martin. All rights reserved.
 * @licence GNU/GPL Version 3 (http://www.gnu.org/licenses/gpl.html)
 */

class Session_Security
{
	protected $data;
	protected $hijacked=false;

	/**
	 * Initialise the object and perform fingerprint checks.
	 * 
	 * The key to use for storing data in the session array can be
	 * specified via parameter.
	 * 
	 * @param string $key
	 */
	public function __construct($key='fingerprint') {
		// Initialise the session if necessary and map our object's data into the session.
		if (!isset($_SESSION)) session_start();
		$this->data = &$_SESSION[$key];
		
		if (empty($this->data->fingerprint)) {
			$this->generateFingerprint(); // No fingerprint exists - create one.
		} else {
			$this->verifyFingerprint(); // Verify the current fingerprint. 
		}
	}

	/**
	 * Generate a fingerprint based on timestamp and user agent.
	 * 
	 * @param int $time
	 */
	protected function generateFingerprint($time=0) {
		// If no timestamp is provided, assume current time.
		if ($time === 0) $time = time();
		
		// Create data arrays to pick values from to form the basis for the fingerprint.
		$fingers = explode(' ',$_SERVER['HTTP_USER_AGENT']);
		$fingers2 = explode(',',$_SERVER['HTTP_ACCEPT']);
		
		// Based on the time, select the array indexes to use.		
		$i = $time%count($fingers);
		$j = $time%count($fingers2);
		
		// Generate the fingerprint and save the timestamp (so the process is repeatable).
		$this->data->fingerprint = sha1($fingers[$i].$fingers2[$j].$time);
		$this->data->time = $time;
	}

	/**
	 * Verify the current fingerprint to ensure that we have the same user agent
	 * by regenerating the previous fingerprint using the stored timestamp.
	 */
	protected function verifyFingerprint() {
		// Save the last fingerprint for comparison and regenerate the fingerprint based on the stored timestamp.
		$lastFingerprint = $this->data->fingerprint;
		$this->generateFingerprint($this->data->time);
		
		// If the request originated from the same user, they should match.
		if ($lastFingerprint === $this->data->fingerprint) {
			// Generate a new fingerprint for next load (to tighten the window of opportunity).
			$this->generateFingerprint();
		} else {
			// Fingerprint mismatch. Move to a new session ID and clear the data.
			session_regenerate_id();
			session_destroy();
			session_start();
			
			// Set object status to denote session hijack was attempted.
			$this->hijacked = true;
		}
	}

	/**
	 * Was a session hijack attempt detected?
	 * 
	 * @return bool $hijacked
	 */
	public function isHijacked() {
		return $this->hijacked;
	}

}