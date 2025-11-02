<?php

/**
 * Plugin Name: WP Auth via Custom API (ProxiCE)
 * Description: Replaces WordPress password auth with a call to your external API. On success, it finds/creates a matching WP user and logs them in.
 * Version: 0.1.0
 * Author: Antony GIBBS <antony@cantoute.com>
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 */

if (!defined('ABSPATH')) {
    exit;
}

// error_reporting(E_ALL);
// ini_set('display_errors', 1);

final class WP_Auth_Custom_API_ProxiCE
{
    const OPTION = 'wp_auth_custom_api_proxice_options';
    const NONCE  = 'wp_auth_custom_api_proxice_nonce';

    const API_ENDPOINT_LOGIN = 'login_v3';
    const API_ENDPOINT_PROFILE = 'me';
    const API_ENDPOINT_COMPANY = 'company/:id';

    private static ?WP_User $auth_local_user = null; // user returned by wp auth, if admin we'll use else we'll create/update local user
    private static ?string $remote_jwt_token = null;
    private static ?array $remote_jwt_token_decoded = null; // header|payload|signature_valid
    private static ?array $authenticate_via_api_response = null; // if authenticated stores json response

    public static function init(): void
    {
        add_filter('authenticate', [__CLASS__, 'authenticate_via_api'], 30, 3);
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('profile_update', [__CLASS__, 'maybe_sync_profile_back'], 10, 2); // optional no-op
    }

    /**
     * Settings schema w/ sane defaults. Adjust to your API.
     */
    public static function defaults(): array
    {
        return [
            'enabled'        => 1,
            'api_base'       => 'https://proxicetech.fr/nodejs',                 // e.g. https://api.example.com/auth/login
            // 'method'         => 'POST',            // POST or GET
            // 'api_key'        => '',                // optional shared secret / header token
            // 'header_key'     => 'X-Auth-Key',      // header name for api_key
            'timeout'        => 8,                 // seconds
            'sslverify'      => 1,                 // verify TLS
            'auto_provision' => 1,                 // create local user if missing
            'role_default'   => 'subscriber',      // role for newly provisioned users
            // 'map_username'   => 'username',        // field in API response user object
            // 'map_email'      => 'email',
            // 'map_first'      => 'first_name',
            // 'map_last'       => 'last_name',
            // 'map_roles'      => 'roles',           // array of role slugs (must exist in WP)
            // 'map_ext_id'     => 'id',              // external user id field
        ];
    }

    /**
     * Main auth hook: validates credentials against your API. If OK, returns a WP_User to short-circuit core password check.
     */
    public static function authenticate_via_api($user, string $username, string $password)
    {

        // Only run on standard username/password logins
        if (is_a($user, 'WP_User')) {
            self::$auth_local_user = $user;

            // print_r($user);

            (array) $roles = $user->roles;
            if (
                in_array('administrator', $roles) ||
                in_array('particuliers', $roles)
            ) {
                return $user; // another auth provider already succeeded
            } else {
                $user = null; // we won't trust local password auth and validate against API
            }
        }

        if (empty($username) || empty($password)) {
            return null; // let other auth handlers run (e.g., magic links)
        }

        $opts = self::get_plugin_opts();

        if (empty($opts['enabled']) || empty($opts['api_base'])) {
            return null; // plugin disabled or misconfigured; fall back to core
        }

        $result = self::remote_auth_request($opts, $username, $password);
        if (is_wp_error($result)) {
            return $result; // surface transport/format errors to user
        }

        self::$authenticate_via_api_response = $result;

        /**
         * status 400
         * {
         *    "err": "Invalid credentials."
         * }
         */

        /**
         * {
         *    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiVVNFUlMiLCJlbWFpbCI6ImNhbnRvdXRlK3Byb3hpY2UuY29ycEBnbWFpbC5jb20iLCJfaWQiOiI2OGRkMTlhYTRjYzY1YjUwZWE2Y2M1ZTciLCJjb21wYW55SUQiOiI2NzkwYjYwYzQ4NDU4NTAxZWJmMDIwYWIiLCJmaXJzdE5hbWUiOiJBbnRvbnkiLCJ3bGNJRCI6IjY3OTBiNWI4NDg0NTg1MDFlYmYwMWNiZiIsImlhdCI6MTc2MTEzNjk2NiwiZXhwIjoxNzYyMDAwOTY2LCJpc3MiOiJjdmMtcHVuZSIsInN1YiI6IjEyMDI2NDU4OTU5In0.KVOODt32jaK6Wr1Mf9H8LGQ4SwHRvPKF-yedrqC625c",
         *    "region": "5e85951e7d7d2dabfb7b16c0",
         *    "company_status": true,
         *    "local_status": true,
         *    ?"wlcID": "string",
         *    ?"companyID": "string"
         *}
         */

        /**
         * JWT Header
         * {
         *  "alg": "HS256",
         *  "typ": "JWT"
         * }

         * JWT Payload
         * {
         *  "role": "USERS",
         *  "email": "cantoute+proxice.corp@gmail.com",
         *  "_id": "68dd19aa4cc65b50ea6cc5e7",
         *  "companyID": "6790b60c48458501ebf020ab",
         *  "firstName": "Antony",
         *  "wlcID": "6790b5b848458501ebf01cbf",
         *  "iat": 1759411168,
         *  "exp": 1760275168,
         *  "iss": "cvc-pune",
         *  "sub": "12026458959"
         *  }
         */

        self::$remote_jwt_token = !empty($result['token']) ? $result['token'] : null;

        if (self::$remote_jwt_token) {
            self::$remote_jwt_token_decoded = self::jwt_decode(self::$remote_jwt_token);
        }

        $ok = !empty(self::$remote_jwt_token) &&
            !empty(self::$remote_jwt_token_decoded) &&
            is_array(self::$remote_jwt_token_decoded['payload']);

        if (!$ok) {
            $msg = isset($result['err']) ? sanitize_text_field((string) $result['err']) : __('Invalid username or password.', 'wp-auth-custom-api-proxice');
            return new WP_Error('invalid_credentials', $msg);
        }


        // Users linked to a white label company have no access here
        $wlcID = self::$remote_jwt_token_decoded['payload']['wlcID'] ?: null;
        if (!empty($wlcID)) {
            // return new WP_Error('not_authorized_proxice', "You are not authorized to use this service. (WLC user)");
        }

        $wp_user = self::create_or_update_wp_user($opts, self::$remote_jwt_token, $result);

        // $wp_user = null;
        if (is_wp_error($wp_user)) {
            return $wp_user;
        }

        // Optionally sync profile fields on every login
        // self::update_user_profile_from_map($wp_user->ID, $opts, $data);

        return $wp_user; // <- signals success to WP core
    }

    /**
     * returns plugin options and optionally takes an argument to override
     *
     * @param ?array $override_opts
     * @return array
     */
    private static function get_plugin_opts(array $override_opts = []): array
    {
        $saved = get_option(self::OPTION, self::defaults());
        if (!is_array($saved)) $saved = [];
        return array_merge(self::defaults(), $saved, $override_opts);
    }


    /**
     * Perform the HTTP request to your API - verify
     */
    private static function remote_auth_request(array $opts, string $username, string $password)
    {
        $api_base = esc_url_raw($opts['api_base']);
        $url = $api_base . '/' . self::API_ENDPOINT_LOGIN;

        $headers  = [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];
        // if (!empty($opts['api_key'])) {
        //     $headers[$opts['header_key'] ?: 'X-Auth-Key'] = $opts['api_key'];
        // }

        $body = [
            'username' => $username,
            'password' => $password,
            'role'     => 'USERS', // required by current ProxiCE API
        ];

        $args = [
            'headers'   => $headers,
            'timeout'   => max(1, (int) $opts['timeout']),
            'sslverify' => (bool) $opts['sslverify'],
        ];

        $args['body'] = wp_json_encode($body);
        $resp = wp_remote_post($url, $args);

        if (is_wp_error($resp)) {
            return new WP_Error('api_transport_error_login', __('Authentication server unreachable.', 'wp-auth-custom-api-proxice'));
        }

        $code = wp_remote_retrieve_response_code($resp);
        $json = json_decode(wp_remote_retrieve_body($resp), true);

        if ($code < 200 || $code >= 300) {
            $msg = is_array($json) && !empty($json['err']) ? (string) $json['err'] : sprintf(__('Authentication failed (HTTP %d).', 'wp-auth-custom-api-proxice'), $code);
            return new WP_Error('api_http_error', $msg);
        }

        if (!is_array($json)) {
            return new WP_Error('api_format_error', __('Invalid response from authentication server.', 'wp-auth-custom-api-proxice'));
        }

        return $json;
    }

    /**
     * Perform the HTTP request to your API - get profile
     */
    private static function get_remote_profile(array $opts, string $token)
    {
        $api_base = esc_url_raw($opts['api_base']);
        $url = $api_base . '/' . self::API_ENDPOINT_PROFILE;

        $headers  = [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];

        $headers['Authorization'] = 'Bearer ' . $token;

        $args = [
            'headers'   => $headers,
            'timeout'   => max(1, (int) $opts['timeout']),
            'sslverify' => (bool) $opts['sslverify'],
        ];

        $resp = wp_remote_get($url, $args);

        /**
         *{
         * "_id": "68dd19aa4cc65b50ea6cc5e7",
         * "username": "12026458959",
         * "firstName": "Antony",
         * "lastName": "GIBBS",
         * "email": "cantoute+proxice.corp@gmail.com",
         * "mobile": "619117419",
         * "role": "USERS",
         * "isVerified": true,
         * "status": true,
         * "validDate": "2026-12-31T00:00:00.000Z",
         * "isDeleted": false,
         * "region": "5e85951e7d7d2dabfb7b16c0",
         * "membershipCard": "12026458959",
         * "createdDate": "2025-10-01T12:08:10.655Z",
         * "authToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiVVNFUlMiLCJlbWFpbCI6ImNhbnRvdXRlK3Byb3hpY2UuY29ycEBnbWFpbC5jb20iLCJfaWQiOiI2OGRkMTlhYTRjYzY1YjUwZWE2Y2M1ZTciLCJjb21wYW55SUQiOiI2NzkwYjYwYzQ4NDU4NTAxZWJmMDIwYWIiLCJmaXJzdE5hbWUiOiJBbnRvbnkiLCJ3bGNJRCI6IjY3OTBiNWI4NDg0NTg1MDFlYmYwMWNiZiIsImlhdCI6MTc1OTQxMTE2OCwiZXhwIjoxNzYwMjc1MTY4LCJpc3MiOiJjdmMtcHVuZSIsInN1YiI6IjEyMDI2NDU4OTU5In0.mEzp941zyxiWxEfxdz32Ns9Nwcb_0KwUo9CI-Nf4_Wk",
         * "companyID": "6790b60c48458501ebf020ab",
         * "local_offers_status": true,
         * "WLC": true,
         * "wlcID": "6790b5b848458501ebf01cbf",
         * "company_offers_status": true
         *}

         */

        if (is_wp_error($resp)) {
            return new WP_Error('api_transport_error_profile', __('Failed to fetch user profile from API.', 'wp-auth-custom-api-proxice'));
        }

        $code = wp_remote_retrieve_response_code($resp);
        $json = json_decode(wp_remote_retrieve_body($resp), true);

        if ($code < 200 || $code >= 300) {
            $msg = is_array($json) && !empty($json['err']) ? (string) $json['err'] : sprintf(__('Authentication failed (HTTP %d).', 'wp-auth-custom-api-proxice'), $code);
            return new WP_Error('api_http_error', $msg);
        }

        if (!is_array($json)) {
            return new WP_Error('api_format_error', __('Invalid response from authentication server.', 'wp-auth-custom-api-proxice'));
        }

        return $json;
    }


    /**
     * Undocumented function
     *
     * @param array $opts
     * @param string $token
     * @param string $id
     * @return array
     */
    private static function get_remote_company(array $opts, string $token, string $id)
    {
        $api_base = esc_url_raw($opts['api_base']);
        $url = $api_base . '/' . self::API_ENDPOINT_COMPANY;

        $url = str_replace(':id', $id, $url);

        $headers  = [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];

        $headers['Authorization'] = 'Bearer ' . $token;

        $args = [
            'headers'   => $headers,
            'timeout'   => max(1, (int) $opts['timeout']),
            'sslverify' => (bool) $opts['sslverify'],
        ];

        $resp = wp_remote_get($url, $args);

        /**
         * {
         *  "_id": "6790b60c48458501ebf020ab",
         *  "companynameEnglish": "DEMO CSE",
         *  "companynameFrench": "DEMO CSE",
         *  "description": "DEMO CSE",
         *  "company_status": true,
         *  "companyEmail": "emq@proxice.fr",
         *  "logo": "./uploads/BandeauModuleCSE.jpg",
         *  "WLC": true,
         *  "wlcID": "6790b5b848458501ebf01cbf",
         *  "isActive": true,
         *  "default_link": "https://www.horizon-ce.fr"
         * }
         */

        if (is_wp_error($resp)) {
            return new WP_Error('api_transport_error_company', __('Failed to fetch user profile from API.', 'wp-auth-custom-api-proxice'));
        }

        $code = wp_remote_retrieve_response_code($resp);
        $json = json_decode(wp_remote_retrieve_body($resp), true);

        if ($code < 200 || $code >= 300) {
            $msg = is_array($json) && !empty($json['err']) ? (string) $json['err'] : sprintf(__('Authentication failed (HTTP %d).', 'wp-auth-custom-api-proxice'), $code);
            return new WP_Error('api_http_error', $msg);
        }

        if (!is_array($json)) {
            return new WP_Error('api_format_error', __('Invalid response from authentication server.', 'wp-auth-custom-api-proxice'));
        }


        return $json;
    }

    /**
     * Find existing WP user (by login or email). Create if allowed.
     */
    private static function create_or_update_wp_user(array $opts, string $token, ?array $auth_result = null)
    {
        $profile = self::get_remote_profile($opts, $token);
        if (is_wp_error($profile)) {
            // Surface the exact reason from the transport / http helper
            return $profile;
        }

        $external_user_id = self::pluck($profile, '_id');
        $username = (string) self::pluck($profile, 'username'); // is membership card number at this time
        $email = self::pluck($profile, 'email');

        $membershipCard = self::pluck($profile, 'membershipCard');
        $d = self::pluck($profile, 'validDate');
        $membershipCardExpireDate = $d ? (new DateTime($d))->format('Y-m-d') : null;

        $firstName = self::pluck($profile, 'firstName');
        $lastName = self::pluck($profile, 'lastName');
        $local_offers_status = self::pluck($profile, 'local_offers_status');
        $company_offers_status = self::pluck($profile, 'company_offers_status');
        $mobile = self::pluck($profile, 'mobile');
        $status = self::pluck($profile, 'status');
        $companyID = self::pluck($profile, 'companyID');
        $WLC = (bool) self::pluck($profile, 'WLC'); // boolean
        $wlcID = self::pluck($profile, 'wlcID');


        $displayName = $firstName . ' ' . $lastName;

        // $login = self::pluck($data, (string) $opts['map_username']) ?: $fallback_username;
        // $email = self::pluck($data, (string) $opts['map_email']);

        // $user = get_user_by('login', $login);
        // if (!$user && $email) {
        //     $user = get_user_by('email', $email);
        // }



        $company = null;

        if (!empty($companyID)) {
            $company = self::get_remote_company($opts, $token, $companyID);
            if (is_wp_error($company)) {
                // Surface the exact reason from the transport / http helper
                return $company;
            }
        }

        // $user = get_user_by('login', $username) ?: get_user_by('email', $email);

        $user = get_user_by('email', $email);

        if ($user) {
            return self::update_wp_user($user, $profile, $company);
        }

        if (empty($opts['auto_provision'])) {
            return new WP_Error('no_local_account', __('Your account is not provisioned.', 'wp-auth-custom-api-proxice'));
        }

        if (!$email || !is_email($email)) {
            // WP requires a unique, valid email for new users
            return new WP_Error('provision_email_missing', __('Cannot create local user without a valid email.', 'wp-auth-custom-api-proxice'));
        }

        // $first = self::pluck($data, (string) $opts['map_first']) ?: '';
        // $last  = self::pluck($data, (string) $opts['map_last']) ?: '';

        $user_id = wp_insert_user([
            'user_login'   => $username,
            'user_pass'    => wp_generate_password(32), // random; local password is unused
            'user_email'   => $email,
            'first_name'   => $firstName,
            'last_name'    => $lastName,
            'display_name' => $displayName ?: $username,
            'role'         => sanitize_key((string) $opts['role_default']),
        ]);

        if (is_wp_error($user_id)) {
            return $user_id;
        }

        $user = get_user_by('id', $user_id);


        // Apply roles from API, if provided and valid
        // self::apply_api_roles($user, $profile, $company);

        self::update_wp_user($user, $profile, $company);

        return $user;
    }

    private static function update_wp_user(WP_User $user, array $profile, ?array $company = null)
    {
        // TODO: update user email etc...

        // Store external ID for future linkage
        // $ext_id = self::pluck($profile, (string) $opts['map_ext_id']);

        $user_id = $user->ID;

        $external_user_id = self::pluck($profile, '_id');
        $username = (string) self::pluck($profile, 'username'); // is membership card number at this time
        $email = self::pluck($profile, 'email');

        $membershipCard = self::pluck($profile, 'membershipCard');
        $d = self::pluck($profile, 'validDate');
        $membershipCardExpireDate = $d ? (new DateTime($d))->format('Y-m-d') : null;

        $firstName = self::pluck($profile, 'firstName');
        $lastName = self::pluck($profile, 'lastName');
        $local_offers_status = self::pluck($profile, 'local_offers_status') ?: false;
        $company_offers_status = self::pluck($profile, 'company_offers_status') ?: false;
        $mobile = self::pluck($profile, 'mobile');
        $status = self::pluck($profile, 'status');
        $companyID = self::pluck($profile, 'companyID');
        $WLC = (bool) self::pluck($profile, 'WLC') ?: false; // boolean
        $wlcID = self::pluck($profile, 'wlcID');


        // Update the WP User
        $userdata = [
            'ID'         => $user_id,
            'first_name' => $firstName,
            'last_name'  => $lastName,
            'user_email' => $email,
        ];
        $update_user = wp_update_user($userdata);
        if (is_wp_error($update_user)) {
            return new WP_Error('failed_update_local_user', $update_user->get_error_message());
        }

        if ($external_user_id) {
            update_user_meta($user_id, 'external_user_id', sanitize_text_field((string) $external_user_id));
        }

        if ($membershipCard) {
            update_user_meta($user_id, 'membership_card', sanitize_text_field((string) $membershipCard));
            update_user_meta($user_id, 'membership_card_expire_date', sanitize_text_field((string) $membershipCardExpireDate));
        } else {
            // delete entries
            delete_user_meta($user_id, 'membership_card');
            delete_user_meta($user_id, 'membership_card_expire_date');
        }

        update_user_meta($user_id, 'mobile', $mobile ?: '');
        update_user_meta($user_id, 'status', $status ? '1' : '0');
        update_user_meta($user_id, 'company_id', $companyID ?: '');

        update_user_meta($user_id, 'local_offers_status', $local_offers_status ? '1' : '0');
        update_user_meta($user_id, 'company_offers_status', $company_offers_status ? '1' : '0');

        self::apply_api_roles($user, $profile, $company);

        return $user;
    }

    /**
     * If the user is linked to a company try find role matching companynameFrench to role.displayName
     * If WP_Role not exists create it and set role slug to user
     * If no company apply role.no_company
     * 
     * @param WP_User|null $user
     * @param array $profile
     * @param array|null $company
     * @return void
     */
    private static function apply_api_roles(?WP_User $user, array $profile, ?array $company): void
    {
        if (!$user) {
            return;
        }

        // $user_info = get_userdata($user->ID);

        $defaultRoleDisplayName = 'No Company';

        $roles = [$defaultRoleDisplayName];

        if ($company) {
            $companyName = trim($company['companynameFrench']);
            $roles = [$companyName];
        }


        if (is_array($roles)) {
            // Reset to default then add allowed roles
            $user->set_role('');

            foreach ($roles as $display_name) {
                $role_name = self::get_role_slug_by_display_name($display_name);

                if (empty($role_name)) {
                    $role_name = sanitize_key(strtolower(self::safe_str('corp_' . $display_name)));

                    $role = add_role(
                        $role_name,
                        $display_name,
                        [],
                        // [
                        //     'read'         => true,
                        //     'edit_posts'   => true,
                        //     'upload_files' => true,
                        // ]
                    );

                    if (
                        null === $role ||
                        !($role instanceof WP_Role)
                    ) {
                        // TODO: handle error

                        return;
                    }

                    $role_name = $role->name;
                }

                $user->add_role($role_name);
            }



            // $existing = array_keys(wp_roles()->roles);
            // foreach ($roles as $r) {
            //     $r = sanitize_key((string) $r);
            //     if (in_array($r, $existing, true)) {
            //         $user->add_role($r);
            //     }
            // }
            // if (empty($user->roles)) {
            //     $user->add_role(sanitize_key((string) $opts['role_default']));
            // }
        }
    }

    /** Simple deep pluck supporting dot.notation */
    private static function pluck($array, string $path)
    {
        if (!is_array($array) || $path === '') return null;
        $parts = explode('.', $path);
        $val = $array;
        foreach ($parts as $p) {
            if (is_array($val) && array_key_exists($p, $val)) {
                $val = $val[$p];
            } else {
                return null;
            }
        }
        return $val;
    }

    /* ————— Settings UI ————— */

    public static function admin_menu(): void
    {
        add_options_page(
            __('External Auth', 'wp-auth-custom-api-proxice'),
            __('External Auth', 'wp-auth-custom-api-proxice'),
            'manage_options',
            'wp-auth-custom-api-proxice',
            [__CLASS__, 'render_settings']
        );
    }

    public static function register_settings(): void
    {
        register_setting('wp_auth_custom_api_proxice', self::OPTION, [
            'type' => 'array',
            'sanitize_callback' => [__CLASS__, 'sanitize_options'],
            'default' => self::defaults(),
        ]);

        add_settings_section('main', __('Connection', 'wp-auth-custom-api-proxice'), '__return_false', 'wp-auth-custom-api-proxice');

        $fields = [
            'enabled' => __('Enable API authentication', 'wp-auth-custom-api-proxice'),
            'api_base' => __('API base URL', 'wp-auth-custom-api-proxice'),
            // 'method' => __('HTTP method (GET/POST)', 'wp-auth-custom-api-proxice'),
            // 'api_key' => __('API key / token (optional)', 'wp-auth-custom-api-proxice'),
            // 'header_key' => __('Auth header key', 'wp-auth-custom-api-proxice'),
            'timeout' => __('Timeout (seconds)', 'wp-auth-custom-api-proxice'),
            'sslverify' => __('Verify SSL certificate', 'wp-auth-custom-api-proxice'),
            'auto_provision' => __('Auto-provision local users', 'wp-auth-custom-api-proxice'),
            'role_default' => __('Default role', 'wp-auth-custom-api-proxice'),
            // 'map_username' => __('Map: username path', 'wp-auth-custom-api-proxice'),
            // 'map_email' => __('Map: email path', 'wp-auth-custom-api-proxice'),
            // 'map_first' => __('Map: first name path', 'wp-auth-custom-api-proxice'),
            // 'map_last' => __('Map: last name path', 'wp-auth-custom-api-proxice'),
            // 'map_roles' => __('Map: roles path', 'wp-auth-custom-api-proxice'),
            // 'map_ext_id' => __('Map: external id path', 'wp-auth-custom-api-proxice'),
        ];

        foreach ($fields as $key => $label) {
            add_settings_field($key, $label, [__CLASS__, 'render_field'], 'wp-auth-custom-api-proxice', 'main', ['key' => $key]);
        }
    }

    public static function sanitize_options($input): array
    {
        $d = self::defaults();
        $out = [];
        $out['enabled']        = empty($input['enabled']) ? 0 : 1;
        $out['api_base']       = esc_url_raw($input['api_base'] ?? $d['api_base']);
        // $out['method']         = in_array(strtoupper($input['method'] ?? 'POST'), ['GET','POST'], true) ? strtoupper($input['method']) : 'POST';
        // $out['api_key']        = sanitize_text_field($input['api_key'] ?? '');
        // $out['header_key']     = sanitize_text_field($input['header_key'] ?? $d['header_key']);
        $out['timeout']        = max(1, (int) ($input['timeout'] ?? $d['timeout']));
        $out['sslverify']      = empty($input['sslverify']) ? 0 : 1;
        $out['auto_provision'] = empty($input['auto_provision']) ? 0 : 1;
        $out['role_default']   = sanitize_key($input['role_default'] ?? $d['role_default']);
        // $out['map_username']   = sanitize_text_field($input['map_username'] ?? $d['map_username']);
        // $out['map_email']      = sanitize_text_field($input['map_email'] ?? $d['map_email']);
        // $out['map_first']      = sanitize_text_field($input['map_first'] ?? $d['map_first']);
        // $out['map_last']       = sanitize_text_field($input['map_last'] ?? $d['map_last']);
        // $out['map_roles']      = sanitize_text_field($input['map_roles'] ?? $d['map_roles']);
        // $out['map_ext_id']     = sanitize_text_field($input['map_ext_id'] ?? $d['map_ext_id']);
        return $out;
    }

    public static function render_settings(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $opts = self::get_plugin_opts();
?>
        <div class="wrap">
            <h1><?php esc_html_e('External API Authentication', 'wp-auth-custom-api-proxice'); ?></h1>
            <form action="options.php" method="post">
                <?php settings_fields('wp_auth_custom_api_proxice'); ?>
                <?php do_settings_sections('wp-auth-custom-api-proxice'); ?>
                <?php submit_button(); ?>
            </form>
            <hr />
            <details>
                <summary><strong><?php esc_html_e('Expected API response (example)', 'wp-auth-custom-api-proxice'); ?></strong></summary>
                <pre>{
  "ok": true,
  "message": "",
  "user": {
    "id": 123,
    "username": "jdoe",
    "email": "jdoe@example.com",
    "first_name": "Jane",
    "last_name": "Doe",
    "roles": ["subscriber"]
  }
}</pre>
            </details>
        </div>
<?php
    }

    public static function render_field(array $args): void
    {
        $key  = $args['key'];
        $opts = self::get_plugin_opts();
        $val  = $opts[$key] ?? '';

        $bools = ['enabled', 'sslverify', 'auto_provision'];
        if (in_array($key, $bools, true)) {
            printf('<label><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s/> %4$s</label>', esc_attr(self::OPTION), esc_attr($key), checked($val, 1, false), esc_html__('Yes', 'wp-auth-custom-api-proxice'));
            return;
        }

        if ($key === 'method') {
            printf('<select name="%1$s[%2$s]"><option value="POST" %3$s>POST</option><option value="GET" %4$s>GET</option></select>', esc_attr(self::OPTION), esc_attr($key), selected($val, 'POST', false), selected($val, 'GET', false));
            return;
        }

        if ($key === 'role_default') {
            echo '<select name="' . esc_attr(self::OPTION) . '[' . esc_attr($key) . ']">';
            foreach (wp_roles()->roles as $slug => $role) {
                printf('<option value="%1$s" %2$s>%3$s</option>', esc_attr($slug), selected($val, $slug, false), esc_html($role['name']));
            }
            echo '</select>';
            return;
        }

        $type = ($key === 'api_base') ? 'url' : (($key === 'timeout') ? 'number' : 'text');
        $extra = $type === 'number' ? ' min="1" step="1"' : '';
        printf('<input type="%1$s" name="%2$s[%3$s]" value="%4$s" class="regular-text" %5$s/>', esc_attr($type), esc_attr(self::OPTION), esc_attr($key), esc_attr($val), $extra);
    }

    /**
     * Optional: push back profile updates to external API when the user edits their WP profile.
     * Replace with your own logic or remove if not needed.
     */
    public static function maybe_sync_profile_back($user_id, $old_user_data): void
    {
        // Intentionally left as a stub; implement if your API needs it.
    }

    private static function b64url_decode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $data = strtr($data, '-_', '+/');
        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw new Exception('Invalid base64url segment.');
        }
        return $decoded;
    }


    /**
     * @param string $jwt The raw JWT (header.payload.signature)
     * @param null|string|resource $key  HS256: shared secret; RS256: OpenSSL public key (PEM string or resource)
     * @param array $options [
     *   'verify' => bool (default false),
     *   'allowed_algs' => ['HS256','RS256'],
     *   'leeway' => int seconds (default 0),
     *   'time' => int override current time (unix)
     * ]
     * @return array [ 'header' => array, 'payload' => array, 'signature_valid' => bool ]
     * @throws Exception
     */
    private static function jwt_decode(string $jwt, $key = null, array $options = []): array
    {
        $opts = array_merge([
            'verify' => false,
            'allowed_algs' => ['HS256', 'RS256'],
            'leeway' => 0,
            'time' => time(),
        ], $options);

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new Exception('JWT must have three segments.');
        }
        [$h64, $p64, $s64] = $parts;

        $headerJson  = self::b64url_decode($h64);
        $payloadJson = self::b64url_decode($p64);
        $signature   = self::b64url_decode($s64);

        $header = json_decode($headerJson, true, 512, JSON_THROW_ON_ERROR);
        $payload = json_decode($payloadJson, true, 512, JSON_THROW_ON_ERROR);

        $alg = $header['alg'] ?? null;
        if (!$alg) {
            throw new Exception('Missing alg in header.');
        }
        if (!in_array($alg, $opts['allowed_algs'], true)) {
            throw new Exception("Algorithm {$alg} not allowed.");
        }

        $signatureValid = false;
        if ($opts['verify']) {
            $signingInput = $h64 . '.' . $p64;

            switch ($alg) {
                case 'HS256':
                    if (!is_string($key) || $key === '') {
                        throw new Exception('HS256 requires a non-empty string secret.');
                    }
                    $expected = hash_hmac('sha256', $signingInput, $key, true);
                    $signatureValid = hash_equals($expected, $signature);
                    break;

                case 'RS256':
                    if (!$key) {
                        throw new Exception('RS256 requires a public key.');
                    }
                    $pubKey = is_resource($key) ? $key : openssl_pkey_get_public($key);
                    if ($pubKey === false) {
                        throw new Exception('Invalid RS256 public key.');
                    }
                    $ok = openssl_verify($signingInput, $signature, $pubKey, OPENSSL_ALGO_SHA256);
                    if (is_resource($pubKey)) { /* no-op: provided by user */
                    }
                    $signatureValid = ($ok === 1);
                    if ($ok === -1) {
                        throw new Exception('OpenSSL verify error: ' . openssl_error_string());
                    }
                    break;

                default:
                    throw new Exception("Unsupported alg {$alg} in this helper.");
            }

            if (!$signatureValid) {
                throw new Exception('Invalid signature.');
            }

            // Validate registered time-based claims if present
            $now = (int)$opts['time'];
            $leeway = max(0, (int)$opts['leeway']);

            if (isset($payload['nbf']) && $now + $leeway < (int)$payload['nbf']) {
                throw new Exception('Token not yet valid (nbf).');
            }
            if (isset($payload['iat']) && $now + $leeway < (int)$payload['iat']) {
                throw new Exception('Token issued in the future (iat).');
            }
            if (isset($payload['exp']) && $now - $leeway >= (int)$payload['exp']) {
                throw new Exception('Token expired (exp).');
            }
        }

        return [
            'header' => $header,
            'payload' => $payload,
            'signature_valid' => $signatureValid,
        ];
    }


    private static function get_role_by_display_name(string $name): ?WP_Role
    {
        $name = trim($name);
        $roles = wp_roles()->roles;

        foreach ($roles as $slug => $r) {
            $n = trim($r['name']);
            if (empty($n)) continue;

            if (strtolower($n) === strtolower($name)) {
                return $r;
            }
        }

        return null;
    }

    private static function get_role_slug_by_display_name(string $name): ?string
    {
        $name = trim($name);
        $roles = wp_roles()->roles;

        foreach ($roles as $slug => $r) {
            $n = trim($r['name']);
            if (empty($n)) continue;

            if (strtolower($n) === strtolower($name)) {
                return $slug;
            }
        }

        return null;
    }


    private static function safe_str(string $str, string $separator = '_'): string
    {
        $str = trim(self::remove_accents($str));
        // Trim spaces, replace non-alphanumeric sequences with underscores
        $formatted = preg_replace('/[^A-Za-z0-9_]+/', $separator, $str);

        $formatted = trim($formatted, $separator);

        // Convert to uppercase
        return $formatted;
    }

    private static function remove_accents(string $str): string
    {
        // Si possible, utiliser la fonction interne transliterator_transliterate (plus propre)
        if (function_exists('transliterator_transliterate')) {
            return transliterator_transliterate('Any-Latin; Latin-ASCII; [:Nonspacing Mark:] Remove; NFC;', $str);
        }

        // Sinon, fallback manuel (utile sur hébergements limités)
        $accents = [
            'à' => 'a',
            'á' => 'a',
            'â' => 'a',
            'ä' => 'a',
            'ã' => 'a',
            'å' => 'a',
            'æ' => 'ae',
            'ç' => 'c',
            'è' => 'e',
            'é' => 'e',
            'ê' => 'e',
            'ë' => 'e',
            'ì' => 'i',
            'í' => 'i',
            'î' => 'i',
            'ï' => 'i',
            'ñ' => 'n',
            'ò' => 'o',
            'ó' => 'o',
            'ô' => 'o',
            'ö' => 'o',
            'õ' => 'o',
            'ø' => 'o',
            'œ' => 'oe',
            'ù' => 'u',
            'ú' => 'u',
            'û' => 'u',
            'ü' => 'u',
            'ý' => 'y',
            'ÿ' => 'y',
            'À' => 'A',
            'Á' => 'A',
            'Â' => 'A',
            'Ä' => 'A',
            'Ã' => 'A',
            'Å' => 'A',
            'Æ' => 'AE',
            'Ç' => 'C',
            'È' => 'E',
            'É' => 'E',
            'Ê' => 'E',
            'Ë' => 'E',
            'Ì' => 'I',
            'Í' => 'I',
            'Î' => 'I',
            'Ï' => 'I',
            'Ñ' => 'N',
            'Ò' => 'O',
            'Ó' => 'O',
            'Ô' => 'O',
            'Ö' => 'O',
            'Õ' => 'O',
            'Ø' => 'O',
            'Œ' => 'OE',
            'Ù' => 'U',
            'Ú' => 'U',
            'Û' => 'U',
            'Ü' => 'U',
            'Ý' => 'Y'
        ];

        return strtr($str, $accents);
    }
}

WP_Auth_Custom_API_ProxiCE::init();
