<?php

namespace Drupal\webserver_auth;

use Symfony\Component\HttpFoundation\Request;
use Drupal\Core\Database\Connection;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\user\Entity\User;

class WebserverAuthHelper {

  /**
   * The database connection.
   *
   * @var \Drupal\Core\Database\Connection
   */
  protected $connection;

  /**
   * Constructs a new cookie authentication provider.
   *
   * @param \Drupal\Core\Database\Connection $connection
   *   The database connection.
   *
   */
  public function __construct(Connection $connection) {
    $this->connection = $connection;
  }

  /**
   * Retrieving remove username from server variables.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *
   * @return string
   */
  public function getRemoteUser(Request $request) {
    $authinfo = [
      'email' => NULL,
      'name' => NULL,
    ];

    // Load values from server vars.
    if ($request->server->get('HTTP_X_EMAIL')) {
      $authinfo['email'] = $request->server->get('HTTP_X_EMAIL');
    }
    if ($request->server->get('HTTP_X_FULL_NAME')) {
      $authinfo['name'] = $request->server->get('HTTP_X_FULL_NAME');
    }

    //$config = \Drupal::config('webserver_auth.settings');

    return $authinfo;
  }

  /**
   * Checking that user exists in the system.
   * Creating new user if site is configured this way.
   *
   * @param string $authname
   *
   * @return integer
   */
  public function validateRemoteUser($authinfo) {
    // Checking if user exists and not blocked.
    $email_query = $this->connection->select('users_field_data', 'u');
    $email_query->fields('u', array('uid', 'status'));
    $email_query->condition('u.mail', $authinfo['email'], '=');
    $email_result = $email_query->execute();
    $email_data = $email_result->fetchAssoc();

    // Creating new user.
    $config = \Drupal::config('webserver_auth.settings');
    if ($authinfo['email'] && $config->get('create_user') && !$email_data) {
      $new_user = $this->createNewUser($authinfo);
      return $new_user->id();
    }

    // Letting user know that his account was blocked.
    if ($email_data && !$email_data['status']) {
      drupal_set_message(t('Sorry, there was a problem verifying your account.'), 'error');
    }

    if ($email_data['status']) {
      return $email_data['uid'];
    }

    return NULL;
  }

  /**
   * Login in user. This is basically copy of user_login_finalize with few small changes.
   *
   * @param $account
   */
  public function logInUser($account) {
    \Drupal::currentUser()->setAccount($account);
    \Drupal::logger('user')
      ->notice('Webserver Auth Session opened for %name.', array('%name' => $account->getUsername()));

    // Update the user table timestamp noting user has logged in.
    // This is also used to invalidate one-time login links.
    $account->setLastLoginTime(REQUEST_TIME);
    \Drupal::entityManager()
      ->getStorage('user')
      ->updateLastLoginTimestamp($account);

    // Regenerate the session ID to prevent against session fixation attacks.
    // This is called before hook_user_login() in case one of those functions
    // fails or incorrectly does a redirect which would leave the old session
    // in place.
    \Drupal::service('session')->migrate();
    \Drupal::service('session')->set('uid', $account->id());
    \Drupal::moduleHandler()->invokeAll('user_login', array($account));
  }

  /**
   * @param $authinfo
   *
   * @return \Drupal\user\Entity\User $used
   */
  public function createNewUser($authinfo) {
    // Generating password. It won't be used, but we still don't want
    // to use empty password or same password for all users.
    $pass = user_password(12);

    $data = [
      'name' => $authinfo['name'],
      'mail' => $authinfo['email'],
      'pass' => $pass,
    ];

    try {
        $user = User::create($data);
        $user->activate();
        $user->save();
    } catch (Exception $ex) {
        if ($ex instanceof EntityStorageException) {
            // no collision between names allowed, add some noise
            $data['name'] .= ' ' . user_password(6);
            $user = User::create($data);
            $user->activate();
            $user->save();
        } else {
            throw $ex;
        }
    }

    return $user;
  }

  /**
   * Login in user. This is basically copy of user_logout with few small changes.
   */
  public function logOutUser() {
    $user = \Drupal::currentUser();

    \Drupal::logger('user')->notice('Webserver Auth Session closed for %name.', array('%name' => $user->getAccountName()));

    \Drupal::moduleHandler()->invokeAll('user_logout', array($user));

    // Destroy the current session, and reset $user to the anonymous user.
    // Note: In Symfony the session is intended to be destroyed with
    // Session::invalidate(). Regrettably this method is currently broken and may
    // lead to the creation of spurious session records in the database.
    // @see https://github.com/symfony/symfony/issues/12375
    \Drupal::service('session_manager')->destroy();
    $user->setAccount(new AnonymousUserSession());
  }
}
