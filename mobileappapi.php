<?php
//require_once('vendor/autoload.php');
use \Firebase\JWT\JWT;

/**
 *
 * @wordpress-plugin
 * Plugin Name:       Mobile app API
 * Description:       All functions which is used in mobile app with JWT Auth.
 * Version:           1.0
 * Author:            Knoxweb
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}


add_action( 'rest_api_init', function() {
    
	remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
	add_filter( 'rest_pre_serve_request', function( $value ) {
		header( 'Access-Control-Allow-Origin: *' );
		header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
		header( 'Access-Control-Allow-Credentials: true' );

		return $value;
		
	});
}, 15 );



function test_jwt_auth_expire($issuedAt)
{
    return $issuedAt + (DAY_IN_SECONDS * 10000);
}
add_filter('jwt_auth_expire', 'test_jwt_auth_expire');

add_action('rest_api_init', function () {
    register_rest_route('mobileapi/v1', '/register', array(
        'methods' => 'POST',
        'callback' => 'MobileApiMakeNewAuthor',
    ));

    register_rest_route('mobileapi/v1', '/retrieve_password', array(
        'methods' => 'POST',
        'callback' => 'RetrivePassword',
    ));

    //GetUserImage

    register_rest_route('mobileapi/v1', '/GetUserImage', array(
        'methods' => 'POST',
        'callback' => 'GetUserImage',
    ));


    register_rest_route('mobileapi/v1', '/validate_token', array(
        'methods' => 'POST',
        'callback' => 'validate_token',
    ));

    register_rest_route('mobileapi/v1', '/facebook_login', array(
        'methods' => 'POST',
        'callback' => 'facebook_login',
    ));

});


function facebook_login($request)
{

    $username = $request->get_param('username');
    $email = $request->get_param('email');
    $fbname = $request->get_param('fbname');
    $facebook_id = $request->get_param('facebook_id');

    if (!is_email($email)) {
        $email = $facebook_id . "_facebook_random@gmail.com";
    }

    $userloginFlag = true;
    $user_id = username_exists($username);
    if (!$user_id and email_exists($email) == false) {
        $userloginFlag = false;
    }
    // check if facebookID exists
    $users_check_facebookID = get_users(
        array(
            'meta_key' => 'facebook_id',
            'meta_value' => $facebook_id,
        )
    );

    if (count($users_check_facebookID) == 0) {
        $userloginFlag = false;
    } else {
        $user_id = $users_check_facebookID[0]->data->ID;
    }

    if ($userloginFlag == true) {
        $data = fb_check_login($user_id, $facebook_id);
    } else {
        $user_id = FBSignup($email, $username, $fbname, $facebook_id);
        $data = fb_check_login($user_id);
    }

    if (count($data) > 0) {
        return new WP_REST_Response($data, 200);
    } else {
        $res = array("status" => 'error');
        return new WP_REST_Response($res, 403);
    }

}

// Facebook Signup function
function FBSignup($user_email, $user_name, $first_name, $facebook_id)
{

    $user_id = username_exists($user_name);
    if (!$user_id and email_exists($user_email) == false) {
        $random_password = wp_generate_password($length = 12, $include_standard_special_chars = false);
        $user_id = wp_create_user($user_name, $password, $user_email);
        $user = new WP_User($user_id);
        $user->set_role('author');
        update_user_meta($user_id, 'first_name', $first_name);
        update_user_meta($user_id, 'nickname', $first_name);
        update_user_meta($user_id, 'facebook_id', $facebook_id);
        return $user_id;
    } else {
        return $user_id;
    }

}

// Facebook Login function
function fb_check_login($user_id, $facebook_id = null)
{
    $secret_key = defined('JWT_AUTH_SECRET_KEY') ? JWT_AUTH_SECRET_KEY : false;

    /** Try to authenticate the user with the passed credentials*/
    $user = get_userdata($user_id);
    if (count($user) > 0) {
        if ($facebook_id) {
            update_user_meta($user_id, 'facebook_id', $facebook_id);
        }

        /** Valid credentials, the user exists create the according Token */
        $issuedAt = time();
        $notBefore = apply_filters('jwt_auth_not_before', $issuedAt, $issuedAt);
        $expire = apply_filters('jwt_auth_expire', $issuedAt + (DAY_IN_SECONDS * 7), $issuedAt);

        $token = array(
            'iss' => get_bloginfo('url'),
            'iat' => $issuedAt,
            'nbf' => $notBefore,
            'exp' => $expire,
            'data' => array(
                'user' => array(
                    'id' => $user->data->ID,
                ),
            ),
        );

        /** Let the user modify the token data before the sign. */
        $token = JWT::encode(apply_filters('jwt_auth_token_before_sign', $token, $user), $secret_key);

        /** The token is signed, now create the object with no sensible user data to the client*/
        $data = array(
            'token' => $token,
            'user_email' => $user->data->user_email,
            'user_nicename' => $user->data->user_nicename,
            'user_display_name' => $user->data->display_name,
        );

        /** Let the user modify the data before send it back */
        $data = apply_filters('jwt_auth_token_before_dispatch', $data, $user);
        return $data;
    }

}

function validate_token($request)
{
    $param = $request->get_params();
    $token = $param['token'];
    $user_id = GetMobileAPIUserByIdToken($token);
    if ($user_id) {
        $res['status'] = "ok";
        return new WP_REST_Response($res, 200);
    } else {
        $res['status'] = "error";
        $res['msg'] = "Your session expired, please login again";
        return new WP_REST_Response($res, 200);
    }

}

// Create new user
function MobileApiMakeNewAuthor($request)
{

    $data = array("status" => "ok", "errormsg" => "", 'error_code' => "");
    $param = $request->get_params();
    $user_name = $param['email'];
    $user_email = $param['email'];
    $type = $param['type'];
    $password = $param['password'];

    // JWT_AUTH_SECRET_KEY define in wp-config
    if ($param['jw_auth_sec'] != JWT_AUTH_SECRET_KEY) {
        $data['status'] = "error";
        $data['errormsg'] = __('cheating----.');
        $data['error_code'] = "token_error";
        return new WP_REST_Response($data, 403);
    }

    if (!is_email($user_email)) {
        $data['status'] = "error";
        $data['errormsg'] = __('This is not a Valid Email.');
        $data['error_code'] = "invalid_email";
        return new WP_REST_Response($data, 403);
    }

    $user_id = username_exists($user_name);

    if ($passowrd == " ") {
        $data['status'] = "error";
        $data['errormsg'] = __('Please provide password.');
        $data['error_code'] = "password_blank";
        return new WP_REST_Response($data, 403);
    }
    if (!$user_id and email_exists($user_email) == false) {
        //$random_password = wp_generate_password( $length=12, $include_standard_special_chars=false );
        $user_id = wp_create_user($user_name, $password, $user_email);
        $user = new WP_User($user_id);
        if ($type == "vipeel") {
            $user->set_role('author');
        }

        if ($type == "justlooking") {
            $user->set_role('subscriber');
        }

        add_user_meta($user_id, 'first_name', $first_name);
        add_user_meta($user_id, 'nickname', $first_name);
        return new WP_REST_Response($data, 200);
    } else {
        $data['status'] = "error";
        $data['errormsg'] = __('Account exists with this email.');
        $data['error_code'] = "user_already";
        return new WP_REST_Response($data, 403);
    }
}

function user_id_exists($user)
{
    global $wpdb;
    $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $wpdb->users WHERE ID = %d", $user));

    if ($count == 1) {return true;} else {return false;}
}

// Get User ID by token
function GetMobileAPIUserByIdToken($token)
{
    $decoded_array = array();
    $user_id = 0;
    if ($token) {
        $decoded = JWT::decode($token, JWT_AUTH_SECRET_KEY, array('HS256'));

        $decoded_array = (array) $decoded;

    }
    if (count($decoded) > 0) {
        $user_id = $decoded_array['data']->user->id;
    }

    if (user_id_exists($user_id)) {
        return $user_id;
    } else {
        return false;

    }
}

// forgot password
function RetrivePassword($request)
{
    global $wpdb, $current_site;

    $data = array("status" => "ok", "msg" => "you will be recive login instructions.");
    $param = $request->get_params();
    $user_login = sanitize_text_field($param['user_login']);

    if (!is_email($user_login)) {
        $data = array("status" => "error", "msg" => "Please provide valid email.");
        return new WP_REST_Response($data, 403);
    }

    if (empty($user_login)) {
        $data = array("status" => "error", "msg" => "User email is empty.");
        return new WP_REST_Response($data, 403);

    } elseif (strpos($user_login, '@')) {

        $user_data = get_user_by('email', trim($user_login));

    } else {
        $login = trim($user_login);
        $user_data = get_user_by('login', $login);
    }

    if (!$user_data) {
        $data = array("status" => "error", "msg" => "User not found using email.");
        return new WP_REST_Response($data, 403);
    }

    // redefining user_login ensures we return the right case in the email
    $user_login = $user_data->user_login;
    $user_email = $user_data->user_email;

    $allow = apply_filters('allow_password_reset', true, $user_data->ID);

    if (!$allow) {
        $data = array("status" => "error", "msg" => "Password reset not allowed.");
        return new WP_REST_Response($data, 403);
    } elseif (is_wp_error($allow)) {
        $data = array("status" => "error", "msg" => "Something went wrong");
        return new WP_REST_Response($data, 403);
    }

    //$key = $wpdb->get_var($wpdb->prepare("SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s", $user_login));
    // if ( empty($key) ) {
    // Generate something random for a key...
    $key = get_password_reset_key($user_data);
    $password = wp_generate_password(6, false);
    wp_set_password($password, $user_data->ID);

    // do_action('retrieve_password_key', $user_login, $key);
    // Now insert the new md5 key into the db
    //$wpdb->update($wpdb->users, array('user_activation_key' => $key), array('user_login' => $user_login));
    // }

    $message = __('Hello ,') . "\r\n\r\n";

    $message = __('Someone requested that the password be reset for the following account:') . "\r\n\r\n";
    //$message .= network_home_url( '/' ) . "\r\n\r\n";
    $message .= sprintf(__('Username: %s'), $user_login) . "\r\n\r\n";
    $message .= sprintf(__('New Password : %s'), $password) . "\r\n\r\n";

    //$message .= __('If this was a mistake, just ignore this email and nothing will happen.') . "\r\n\r\n";
    $message .= __('Thank you') . "\r\n\r\n";
    // $message .= network_site_url("resetpass/?key=$key&login=" . rawurlencode($user_login), 'login') . "\r\n";
    /* <http://vipeel.testplanets.com/resetpass/?key=wDDY0rDxwfaWPOFZrrmf&login=ajaytest%40gmail.com> */
    if (is_multisite()) {
        $blogname = $GLOBALS['current_site']->site_name;
    } else
    // The blogname option is escaped with esc_html on the way into the database in sanitize_option
    // we want to reverse this for the plain text arena of emails.
    {
        $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
    }

    $title = sprintf(__('[%s] Password Reset'), $blogname);

    $title = apply_filters('retrieve_password_title', $title);
    $message = apply_filters('retrieve_password_message', $message, $key);

    if ($message && !wp_mail($user_email, $title, $message)) {
        $data = array("status" => "error", "msg" => "The e-mail could not be sent..");
        return new WP_REST_Response($data, 403);
    }
    // wp_die( __('The e-mail could not be sent.') . "<br />\n" . __('Possible reason: your host may have disabled the mail() function...') );

    return new WP_REST_Response($data, 200);
}

//apply_filters('jwt_auth_token_before_dispatch', $data, $user);
add_filter('jwt_auth_token_before_dispatch', 'mobileapi_jwt_auth_token_before_dispatch', 10, 2);
function mobileapi_jwt_auth_token_before_dispatch($data, $user)
{

    $role = 'subscriber';
    if (in_array('author', (array) $user->roles)) {
        $role = 'author';
    }



    $data['role'] = $role;
    $first_name = get_user_meta($user->ID, "first_name", true);
    if (!empty($first_name)) {
        $data['user_display_name'] = ucfirst($first_name);
    } else {
        $data['user_display_name'] = ucfirst($data['user_display_name']);
    }
    $useravatar = get_user_meta($user->ID, 'wp_user_avatar', true);
    if ($useravatar) {
        $img = wp_get_attachment_image_src($useravatar, array('150', '150'), true);
        $data['user_avatar'] = $img[0];
    } else {
        $data['user_avatar'] = 'http://1.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=96&d=mm&r=g';
    }
    $data['user_id'] = $user->ID;
   

    return $data;
}

function GetUserImage($request)
{
    $param = $request->get_params();
    $token = $param['token'];
    $user_id = GetMobileAPIUserByIdToken($token);
    $useravatar = get_user_meta($user_id, 'wp_user_avatar', true);
    if ($useravatar) {
        $img = wp_get_attachment_image_src($useravatar, array('150', '150'), true);
        $data['user_avatar'] = $img[0];
    } else {
        $data['user_avatar'] = 'http://1.gravatar.com/avatar/1aedb8d9dc4751e229a335e371db8058?s=96&d=mm&r=g';
    }
    return new WP_REST_Response($data, 200);
}
