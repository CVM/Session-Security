Session Security Class
======================

Usage
-----

Include the file before all other code (or make available to your custom autoload). You can then protect your sessions with:

    new Session_Security;

The object stores the fingerprint information in the session under key "fingerprint". You can specify a custom key to use like this:

    new Session_Security('foo');

If a hijack attempt is detected, the would-be attacker is pushed to a new session. If you wish to take any action in the case of a hijack attempt, you can detect them like this:

    $session = new Session_Security;
    if ($session->isHijacked()) {
      // Do something
    }