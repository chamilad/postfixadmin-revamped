<?php
/** 
 * Postfix Admin 
 * 
 * LICENSE 
 * This source file is subject to the GPL license that is bundled with  
 * this package in the file LICENSE.TXT. 
 * 
 * Further details on the project are available at : 
 *     http://www.postfixadmin.com or http://postfixadmin.sf.net 
 * 
 * @version $Id: login.php 857 2010-08-22 12:18:43Z christian_boltz $ 
 * @license GNU GPL v2 or later. 
 * 
 * File: login.php
 * Authenticates a user, and populates their $_SESSION as appropriate.
 * Template File: login.php
 *
 * Template Variables:
 *
 *  tMessage
 *
 * Form POST \ GET Variables:
 *
 *  fUsername
 *  fPassword
 *  lang
 */

require_once('common.php');
require_once('captcha/recaptchalib.php');


if($CONF['configured'] !== true) {
  print "Installation not yet configured; please edit config.inc.php";
  exit;
}

if ($_SERVER['REQUEST_METHOD'] == "GET")
{
    if(!isset($_SESSION['show_captcha'])) $_SESSION['show_captcha'] = false;
    // $_SESSION['capt_retries'] = 0;
    include ("./templates/header.php");
    include ("./templates/login.php");
    include ("./templates/footer.php");
}

if ($_SERVER['REQUEST_METHOD'] == "POST")
{
    $fUsername = '';
    $fPassword = '';
    if (isset ($_POST['fUsername'])) $fUsername = escape_string ($_POST['fUsername']);
    if (isset ($_POST['fPassword'])) $fPassword = escape_string ($_POST['fPassword']);
    $lang = safepost('lang');

    if ( $lang != check_language(0) ) { # only set cookie if language selection was changed
        setcookie('lang', $lang, time() + 60*60*24*30); # language cookie, lifetime 30 days
        # (language preference cookie is processed even if username and/or password are invalid)
    }

    $result = db_query ("SELECT password FROM $table_admin WHERE username='$fUsername' AND active='1'");
    if ($result['rows'] == 1)
    {
        $row = db_array ($result['result']);
        $password = pacrypt ($fPassword, $row['password']);
        $result = db_query ("SELECT * FROM $table_admin WHERE username='$fUsername' AND password='$password' AND active='1'");
        if ($result['rows'] != 1)
        {
            $error = 1;
            setCaptchaStatus($CONF['max_retries_before_captcha']);
            $tMessage = '<span class="error_msg">' . $PALANG['pLogin_failed'] . '</span>';
        }
    }
    else
    {
        $error = 1;
        setCaptchaStatus($CONF['max_retries_before_captcha']);
        $tMessage = '<span class="error_msg">' . $PALANG['pLogin_failed'] . '</span>';        
    }

    // check captcha verification
    if($error != 1 && $_SESSION['show_captcha'])
    {
        $privatekey = "6LdPfOsSAAAAABKFG4ZV5ZnRXhfgbMdvdkKfzbWM";
        $resp = recaptcha_check_answer (
                                            $privatekey,
                                            $_SERVER["REMOTE_ADDR"],
                                            $_POST["recaptcha_challenge_field"],
                                            $_POST["recaptcha_response_field"]
                                        );

        if (!$resp->is_valid) {
            // invalid captcha
            $error = 1;
            $tMessage = '<span class="error_msg">Incorrect CAPTCHA! Please read the message carefully and enter to verify you are not a bot.</span>';
        } 
    }

    if ($error != 1)
    {        
        session_regenerate_id();
        $_SESSION['sessid'] = array();
        $_SESSION['sessid']['username'] = $fUsername;
        $_SESSION['sessid']['roles'] = array();
        $_SESSION['sessid']['roles'][] = 'admin';

        // they've logged in, so see if they are a domain admin, as well.
        $result = db_query ("SELECT * FROM $table_domain_admins WHERE username='$fUsername' AND domain='ALL' AND active='1'");
        if ($result['rows'] == 1)
        {
            $_SESSION['sessid']['roles'][] = 'global-admin';
#            header("Location: admin/list-admin.php");
#            exit(0);
        }
        header("Location: main.php");
        exit(0);                
    }

    include ("./templates/header.php");
    include ("./templates/login.php");
    include ("./templates/footer.php");
}

function setCaptchaStatus($max_retry_count)
{
    if(!isset($_SESSION['capt_retries']))
    {
        // first time login in
        $_SESSION['capt_retries'] = 1;
        $_SESSION['show_captcha'] = false;
    }
    else if($_SESSION['capt_retries'] < $max_retry_count)
    {
        $retry_number = $_SESSION['capt_retries'];
        $_SESSION['capt_retries'] = $retry_number + 1;
        $_SESSION['show_captcha'] = false;
    }
    
    if($_SESSION['capt_retries'] >= $max_retry_count)
    {
        //show recaptcha
        $_SESSION['show_captcha'] = true;
    }
}

/* vim: set expandtab softtabstop=4 tabstop=4 shiftwidth=4: */
?>
