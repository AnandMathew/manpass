<?php
function random_str($length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
{
    $pieces = [];
    $max = strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
        $pieces []= $keyspace[random_int(0, $max)];
    }
    return implode('', $pieces);
}

/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db) {



  if ($request->header("Origin") == "http://localhost:8000" ) {
    $response->set_http_code(200);
    $response->success("Request OK");
    log_to_console("OK");
  }
  else {
    $response->set_http_code(400);
    $response->failure("Request OK");
    log_to_console("not ok");
  }
  

  return true;
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db) {
  $username = $request->param("username"); // The requested username from the client
  $password = $request->param("password"); // The requested password from the client
  $email    = $request->param("email");    // The requested email address from the client

  $salt  = bin2hex(random_bytes(8)); 
  
  $stmt = $db->prepare("insert into user_login values(:username, :salt, null, null )");
  $stmt->bindValue(':username', $username, SQLITE3_TEXT);
  $stmt->bindValue(':salt', $salt, SQLITE3_TEXT);
  $stmt->execute();


  $password = hash("sha256", $password . $salt);  // stored in database

   

  $stmt = $db->prepare("insert into user values(:username, :password, :email, null, null )");
  $stmt->bindValue(':username', $username, SQLITE3_TEXT);
  $stmt->bindValue(':password', $password, SQLITE3_TEXT);
  $stmt->bindValue(':email', $email, SQLITE3_TEXT);

  $stmt->execute();


 

  // Respond with a message of success.
  $response->set_http_code(201); // Created
  $response->success("Account created.");
  log_to_console("Account created.");

  return true;
}


/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce 
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username

 // check if user name exists in the database

 // if exists then retrieve salt, generate challenge and send that to the server, also store challenge in the user_login table

  $challenge = bin2hex(random_bytes(8)); 

  $sql = "update user_login set challenge = :challenge WHERE username = :username";
  $stmt = $db->prepare($sql);
  $stmt->bindValue(':username', $username, SQLITE3_TEXT);
  $stmt->bindValue(':challenge', $challenge, SQLITE3_TEXT);
  $stmt->execute();

  

  

  $sql = "SELECT salt FROM user_login WHERE username = :username";
  $stmt = $db->prepare($sql);
  $stmt->bindValue(':username', $username, SQLITE3_TEXT);

  $stmt->execute();

  $salt = $stmt->fetch(PDO:: FETCH_ASSOC);
  $salt = $salt['salt'];

  $response->set_data("challenge", $challenge);
  $response->set_data("salt", $salt);



  $response->set_http_code(200);
  $response->success("Successfully identified user.");
  log_to_console("Success.");

  return true;
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username with which to log in
  $password = $request->param("password"); // The password with which to log in

  log_to_console("username: " . $username);
  log_to_console("computed value from client: " . $password);

  $sql = "SELECT challenge FROM user_login WHERE username = :username";
  $stmt = $db->prepare($sql);
  $stmt->bindValue(':username', $username, SQLITE3_TEXT);

  $stmt->execute();

  $challenge = $stmt->fetch(PDO:: FETCH_ASSOC);
  $challenge = $challenge['challenge'];

  log_to_console("challenge from db: " . $challenge);

  // $password = hash("sha256", $password . $salt);

  // log_to_console("password: " . $password);


  $sql = "SELECT passwd FROM user WHERE username = :username";
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->execute();

  $passindb = $stmt->fetch(PDO:: FETCH_ASSOC);
  $passindb = $passindb['passwd'];

  log_to_console("passwd from db: " . $passindb);

  $servercomputedpass =  hash("sha256", $passindb . $challenge); 

  log_to_console("computed value by server: " . $servercomputedpass);

    if ($servercomputedpass == $password) {
  
      // create session 

      $sessionid = hash("sha256", $username . "saltybae");

      // $expires = new DateTime();
      // $interval = new DateInterval("PT15M");
      // $expires->add($interval)->format(DateTimeInterface::ISO8601);

      //$expires = time() + 180;

      $expires = new DateTime();
      $interval = new DateInterval("PT15M");
      $expires=$expires->add($interval)->format(DateTimeInterface::ISO8601);

      
      $stmt = $db->prepare("INSERT OR REPLACE INTO user_session (sessionid, username, expires) VALUES (:sessionid, :username, :expires)");
      $stmt->bindValue(':sessionid', $sessionid, SQLITE3_TEXT);
      $stmt->bindValue(':username', $username, SQLITE3_TEXT);
      $stmt->bindValue(':expires', $expires, SQLITE3_TEXT);
     
    
      $stmt->execute();

      $token = bin2hex(random_bytes(8));


      $stmt = $db->prepare("DELETE from web_session");
      $stmt->execute();

      $stmt = $db->prepare("INSERT INTO web_session (sessionid, expires, metadata) VALUES (:sessionid, :expires, null)");
      $stmt->bindValue(':sessionid', $token, SQLITE3_TEXT);
      $stmt->bindValue(':expires', $expires, SQLITE3_TEXT);
      $stmt->execute();

      $response->set_http_code(200); // OK
      $response->success("Successfully logged in.");

      $response->add_cookie("session-cookie", $sessionid);

      $response->set_token("passdb-token", $token);
      log_to_console("Session created, dawg.");
    
    } else {

      log_to_console("servercomputedpass: " . $servercomputedpass);
      log_to_console("pass from client: " . $password);
      $response->set_http_code(401); // OK
      $response->failure("User name or password is incorrect");
      log_to_console("Session not created.");

        // send 400 error 
    }


  // $response->set_http_code(200); // OK
  // $response->success("Successfully logged in.");
  // log_to_console("Session created.");
  return true;
}


/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db) {
  $sites = array();

  $sessionid = $request->cookie("session-cookie");
  $reqtoken =  $request->token("passdb-token");

  log_to_console("check the session id: ". $sessionid);


  $sql = "SELECT username FROM user_session WHERE sessionid = :sessionid";
  $stmt = $db->prepare($sql);
  $stmt->bindValue(':sessionid', $sessionid, SQLITE3_TEXT);

  $stmt->execute();

  $username = $stmt->fetch(PDO:: FETCH_ASSOC);
  $username = $username['username'];

  $sql = "SELECT sessionid FROM web_session";
  $stmt = $db->prepare($sql);
  $stmt->execute();

  $tokenstored = $stmt->fetch(PDO:: FETCH_ASSOC);
  $tokenstored = $tokenstored['sessionid'];


  // $username = $stmt->fetch(PDO:: FETCH_ASSOC);
  // $username = $username['username'];
 

  log_to_console("get my username: ". $username);

  if (($username != "") and ($tokenstored == $reqtoken) ) {
    $stmt = $db->prepare('SELECT site from user_safe where username = :username');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->execute();

    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {

      //echo a row
      //is working
  
        $sites[] = $row['site'];
    } 


    $response->set_data("sites", $sites); // return the sites array to the client
    $response->set_http_code(200);
    $response->success("Sites with recorded passwords.");
    log_to_console("Found and returned sites");



  } else {
    $response->set_http_code(401); // OK
    $response->failure("Session not valid");
    log_to_console("Session not valid");
  }

  return true;
      
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db) {
  $site       = $request->param("site");
  $siteuser   = $request->param("siteuser");
  $sitepasswd = $request->param("sitepasswd");
  $siteiv = $request->param("siteiv");
  // $username = $request->param("username");

  $sessionid = $request->cookie("session-cookie");
  $reqtoken =  $request->token("passdb-token");

  log_to_console("check the session id: ". $sessionid);


  $sql = "SELECT username FROM user_session WHERE sessionid = :sessionid";
  $stmt = $db->prepare($sql);
  $stmt->bindValue(':sessionid', $sessionid, SQLITE3_TEXT);

  $stmt->execute();

  $username = $stmt->fetch(PDO:: FETCH_ASSOC);
  $username = $username['username'];
 

  log_to_console("get my username: ". $username);


  $sql = "SELECT sessionid FROM web_session";
  $stmt = $db->prepare($sql);
  $stmt->execute();

  $tokenstored = $stmt->fetch(PDO:: FETCH_ASSOC);
  $tokenstored = $tokenstored['sessionid'];

  if (($username != "") and ($tokenstored == $reqtoken) ) {

    // log_to_console($username);
    // log_to_console($site);
    // log_to_console($siteuser);
    // log_to_console($sitepasswd);
  
    //TODO: implement update
  
  
    $stmt = $db->prepare("insert or replace into user_safe values(:username, :site,:siteuser, :sitepasswd, :siteiv, null )");
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':site', $site, SQLITE3_TEXT);
    $stmt->bindValue(':siteuser', $siteuser, SQLITE3_TEXT);
    $stmt->bindValue(':sitepasswd', $sitepasswd, SQLITE3_TEXT);
    $stmt->bindValue(':siteiv', $siteiv, SQLITE3_TEXT);
  
    $stmt->execute();
  
    
  
    // add site passwords (encrypted) and  to data base using sql
  
    $response->set_http_code(200); // OK
    $response->success("Save to safe succeeded.");
    log_to_console("Successfully saved site data");

  } else {
    $response->set_http_code(401); // OK
    $response->failure("Session not valid");
    log_to_console("Session not valid");
  }

 

  return true;
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db) {
  $site = $request->param("site");


  $sessionid = $request->cookie("session-cookie");
  $reqtoken =  $request->token("passdb-token");

  
  $sql = "SELECT username FROM user_session WHERE sessionid = :sessionid";
  $stmt = $db->prepare($sql);
  $stmt->bindValue(':sessionid', $sessionid, SQLITE3_TEXT);

  $stmt->execute();

  $username = $stmt->fetch(PDO:: FETCH_ASSOC);
  $username = $username['username'];


  $sql = "SELECT sessionid FROM web_session";
  $stmt = $db->prepare($sql);
  $stmt->execute();

  $tokenstored = $stmt->fetch(PDO:: FETCH_ASSOC);
  $tokenstored = $tokenstored['sessionid'];
 
  if (($username != "") and ($tokenstored == $reqtoken) ) {
    $sql = "SELECT siteuser, sitepasswd, siteiv FROM user_safe WHERE site = :site AND username = :username";
    $stmt = $db->prepare($sql);
    $stmt->bindValue(':site', $site, SQLITE3_TEXT);
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->execute();

    $result = $stmt->fetch(PDO:: FETCH_ASSOC);
    $siteuser = $result['siteuser'];
    $sitepasswd = $result['sitepasswd'];

    $siteiv = $result['siteiv'];
    

    $response->set_data("site", $site);
    $response->set_data("siteuser", $siteuser);
    $response->set_data("sitepasswd", $sitepasswd);
    $response->set_data("siteiv", $siteiv);


    $response->set_http_code(200); // OK 
    $response->success("Site data retrieved.");
    log_to_console("Successfully retrieved site data");

  } else {
    $response->set_data("site", $site);

    $response->set_http_code(404); // OK 
    $response->failure("Site data could not be retrieved: invalid session");
    log_to_console("Site data could not be retrieved: invalid session");
  }
  return true;
}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db) {


  $response->delete_cookie("session-cookie");

  $response->set_http_code(200);
  $response->success("Successfully logged out.");
  log_to_console("Logged out");

  return true;
}
?>