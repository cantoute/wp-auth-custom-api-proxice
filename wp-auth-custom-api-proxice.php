<?php

/**
 * Plugin Name: WP Auth via Custom API (ProxiCE)
 * Description: Replaces WordPress password auth with a call to an external API. On success, finds/creates a matching WP user and logs them in.
 * Version: 0.1.0
 * Author: Antony GIBBS <antony@cantoute.com>
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Text Domain: wp-auth-custom-api-proxice
 * Domain Path: /languages
 * License: GPL-2.0-or-later
 *
 * @package WP_Auth_Custom_API_ProxiCE
 *
 * How it works (high level):
 * - Hooks into the 'authenticate' filter at a later priority (30) to run after core username/password auth kicked off.
 * - If an admin or specific whitelisted role already authenticated locally, trusts that result.
 * - Otherwise, calls the external API (login_v3) with username/password.
 * - If the API returns a valid JWT, fetches the remote profile (/me) and optional company info (/company/:id).
 * - Finds existing WP user (by email). If missing and auto-provision is enabled, creates a local user.
 * - Updates user profile/meta, and maps company name to a WP role (auto-creating the role if needed).
 *
 * Security notes:
 * - Local passwords are not used (provisioned users get random local passwords).
 * - JWT is decoded for claims; signature verification is OFF by default. If you need verification,
 *   pipe the shared secret/public key via jwt_decode() options and enable 'verify' => true.
 */

if (!defined('ABSPATH')) {
    exit; // No direct access
}

// error_reporting(E_ALL);
// ini_set('display_errors', 1);

// cspell:ignore ProxiCE wlcID pune XVCJ Efxdz Nwcb algs zyxi jdoe

final class WP_Auth_Custom_API_ProxiCE
{
    /** @var string Option name storing plugin settings */
    const OPTION = 'wp_auth_custom_api_proxice_options';

    /** @var string Nonce handle (reserved for future admin actions) */
    const NONCE  = 'wp_auth_custom_api_proxice_nonce';

    /** @var string Relative path for the login endpoint on the external API */
    const API_ENDPOINT_LOGIN = 'login_v3';

    /** @var string Relative path for the "current user" endpoint on the external API */
    const API_ENDPOINT_PROFILE = 'me';

    /** @var string Relative path template for the company endpoint on the external API (":id" will be replaced) */
    const API_ENDPOINT_COMPANY = 'company/:id';

    /** @var WP_User|null Locally authenticated user (if any). If admin/whitelisted, we defer to WP. */
    private static ?WP_User $local_auth_user = null;

    /** @var string|null Raw JWT returned by the remote authentication endpoint */
    private static ?string $remote_jwt_token = null;

    /**
     * @var array|null Decoded JWT pieces: ['header' => array, 'payload' => array, 'signature_valid' => bool]
     *                 Note: Signature verification is off by default unless enabled via options.
     */
    private static ?array $remote_jwt_token_decoded = null;

    /** @var array|null Cached raw response of a successful authenticate_via_api call */
    private static ?array $remote_login_response = null;

    /**
     * Bootstraps plugin hooks.
     *
     * Hooks:
     * - authenticate (filter): main integration point for login flow
     * - admin_menu (action): settings page
     * - admin_init (action): register settings/fields
     * - profile_update (action): stub to push profile changes back to API (optional)
     *
     * @return void
     */
    public static function init(): void
    {
        add_filter('authenticate', [__CLASS__, 'authenticate_via_api'], 30, 3); // priority (30) to run after core username/password auth
        add_action('admin_menu', [__CLASS__, 'admin_menu']);
        add_action('admin_init', [__CLASS__, 'register_settings']);
        add_action('profile_update', [__CLASS__, 'maybe_sync_profile_back'], 10, 2); // optional no-op
    }

    /**
     * Settings schema with sensible defaults (tweak to match your API).
     * Stored under the OPTION constant via get_option()/update_option().
     *
     * @return array<string,mixed>
     */
    public static function defaults(): array
    {
        return [
            'enabled'        => 1,
            'api_base'       => 'https://proxicetech.fr/nodejs', // e.g. https://api.example.com
            'timeout'        => 8,     // HTTP timeout (seconds)
            'sslverify'      => 1,     // Verify TLS certificate
            'auto_provision' => 1,     // Create local user if missing
            'role_default'   => 'subscriber', // Fallback role when mapping is not available
            'local_auth_roles' => 'administrator,particuliers',
        ];
    }

    /**
     * Main auth filter: validates credentials against the external API.
     *
     * Expected behavior for WordPress:
     * - Return WP_User on success to bypass further password checks.
     * - Return WP_Error on hard failure (transport, HTTP error, invalid credentials).
     * - Return null to allow other auth filters to run.
     *
     * @param null|WP_User|WP_Error $user     Existing auth result (if any) from earlier handlers.
     * @param string                $username Username submitted via login form.
     * @param string                $password Password submitted via login form.
     * @return null|WP_User|WP_Error
     */
    public static function authenticate_via_api($user, string $username, string $password)
    {
        $opts = self::get_plugin_opts();


        // If a previous handler already produced a WP_User (e.g., local password auth),
        // allow admins or specific whitelisted roles to pass through untouched.
        if (is_a($user, 'WP_User')) {
            self::$local_auth_user = $user;

            $user_roles = (array) $user->roles;
            if (
                self::has_matching_value($user_roles, explode(',', $opts['local_auth_roles']))
            ) {
                return $user; // trusted: don't override
            } else {
                // Not trusted: require validation against the external API
                $user = null;
            }
        }

        // No credentials? Let other auth providers handle (e.g., magic links, SSO).
        if (empty($username) || empty($password)) {
            return null;
        }

        // Disabled or misconfigured => fall back to core auth.
        if (empty($opts['enabled']) || empty($opts['api_base'])) {
            return null;
        }

        // 1) Exchange credentials for JWT
        $result = self::remote_auth_request($opts, $username, $password);
        if (is_wp_error($result)) {
            // Transport/HTTP/format failure surfaces to the user

            // return better error messages / translatable
            $msg = $result->get_error_message();
            if ($msg == 'subscription') {
                $subscription_suspended = __('Your subscription has expired. Please renew your subscription to access this service.', 'wp-auth-custom-api-proxice');
                return new WP_Error('subscription_suspended', $subscription_suspended);
            }

            if ($msg == 'Invalid credentials.') {
                $subscription_suspended = __('Invalid username or password.', 'wp-auth-custom-api-proxice');
                return new WP_Error('subscription_suspended', $subscription_suspended);
            }

            return $result;
        }

        self::$remote_login_response = $result;

        /*
         * Example error (HTTP 400):
         * { "err": "Invalid credentials." }
         *
         * Example success:
         * {
         *   "token": "<JWT>",
         *   "region": "5e85951e7d7d2dabfb7b16c0",
         *   "company_status": true,
         *   "local_status": true,
         *   "wlcID": "string?",
         *   "companyID": "string?"
         * }
         */

        // 2) Decode (but not verify) the JWT to access claims.
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

        $ok = !empty(self::$remote_jwt_token)
            && !empty(self::$remote_jwt_token_decoded)
            && is_array(self::$remote_jwt_token_decoded['payload']);

        if (!$ok) {
            $msg = isset($result['err'])
                ? sanitize_text_field((string) $result['err'])
                : __('An error occurred, invalid token.', 'wp-auth-custom-api-proxice');

            return new WP_Error('token_error', $msg);
        }

        // 3) Enforce business rule: WLC-linked accounts are not allowed.
        $wlcID = self::$remote_jwt_token_decoded['payload']['wlcID'] ?? null;
        if (!empty($wlcID)) {
            return new WP_Error(
                'not_authorized_proxice',
                __("You are not authorized to use this service. (WLC user)", 'wp-auth-custom-api-proxice')
            );
        }

        // 4) Create or update the local WP user based on /me (and optional company).
        $wp_user = self::create_or_update_wp_user($opts, self::$remote_jwt_token, $result);
        if (is_wp_error($wp_user)) {
            return $wp_user;
        }


        return $wp_user; // Success => short-circuit core auth.
    }

    /**
     * Get plugin options, merging saved values over defaults, then local overrides.
     *
     * @param array $override_opts Overrides to apply on top of saved options.
     * @return array<string,mixed>
     */
    private static function get_plugin_opts(array $override_opts = []): array
    {
        $saved = get_option(self::OPTION, self::defaults());
        if (!is_array($saved)) {
            $saved = [];
        }
        return array_merge(self::defaults(), $saved, $override_opts);
    }

    /**
     * Exchange username/password against remote API to obtain JWT.
     *
     * @param array  $opts     Plugin options (api_base, timeout, sslverify, ...).
     * @param string $username Submitted login username.
     * @param string $password Submitted login password.
     * @return array|WP_Error  Decoded JSON array on success; WP_Error on failure.
     */
    private static function remote_auth_request(array $opts, string $username, string $password)
    {
        $api_base = esc_url_raw($opts['api_base']);
        $url = $api_base . '/' . self::API_ENDPOINT_LOGIN;

        $headers  = [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
        ];
        // If needed:
        // if (!empty($opts['api_key'])) {
        //     $headers[$opts['header_key'] ?: 'X-Auth-Key'] = $opts['api_key'];
        // }

        $body = [
            'username' => $username,
            'password' => $password,
            'role'     => 'USERS', // Required by current ProxiCE API contract
        ];

        $args = [
            'headers'   => $headers,
            'timeout'   => max(1, (int) $opts['timeout']),
            'sslverify' => (bool) $opts['sslverify'],
            'body'      => wp_json_encode($body),
        ];

        $resp = wp_remote_post($url, $args);

        if (is_wp_error($resp)) {
            return new WP_Error('api_transport_error_login', __('Authentication server unreachable.', 'wp-auth-custom-api-proxice'));
        }

        $code = wp_remote_retrieve_response_code($resp);
        $json = json_decode(wp_remote_retrieve_body($resp), true);

        if ($code < 200 || $code >= 300) {
            $msg = is_array($json) && !empty($json['err'])
                ? (string) $json['err']
                /* translators: HTTP Status Code (ex: 200 403) */
                : sprintf(__('Authentication failed (HTTP %d).', 'wp-auth-custom-api-proxice'), $code);
            return new WP_Error('api_http_error', $msg);
        }
        if (!is_array($json)) {
            return new WP_Error('api_format_error', __('Invalid response from authentication server.', 'wp-auth-custom-api-proxice'));
        }

        return $json;
    }

    /**
     * Fetch the remote "current user" profile via /me using a Bearer token.
     *
     * @param array  $opts  Plugin options.
     * @param string $token JWT returned by login endpoint.
     * @return array|WP_Error Remote profile array; WP_Error on failure.
     */
    private static function get_remote_profile(array $opts, string $token)
    {
        $api_base = esc_url_raw($opts['api_base']);
        $url = $api_base . '/' . self::API_ENDPOINT_PROFILE;

        $headers  = [
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ];

        $args = [
            'headers'   => $headers,
            'timeout'   => max(1, (int) $opts['timeout']),
            'sslverify' => (bool) $opts['sslverify'],
        ];

        $resp = wp_remote_get($url, $args);

        /*
         * Example /me response:
         *{
         * "_id": "68dd19aa4cc65b50ea6cc5e7",
         * "username": "12026458959",
         * "firstName": "Antony",
         * "lastName": "GIBBS",
         * "email": "xxxx+proxice.corp@xxxxx.com",
         * "mobile": "123456789",
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
            $msg = is_array($json) && !empty($json['err'])
                ? (string) $json['err']
                : sprintf(__('Authentication failed (HTTP %d).', 'wp-auth-custom-api-proxice'), $code);
            return new WP_Error('api_http_error', $msg);
        }

        if (!is_array($json)) {
            return new WP_Error('api_format_error', __('Invalid response from authentication server.', 'wp-auth-custom-api-proxice'));
        }

        return $json;
    }

    /**
     * Fetch company details via /company/:id using a Bearer token (optional enrichment).
     *
     * @param array  $opts Plugin options.
     * @param string $token JWT.
     * @param string $id    Company ID from profile.
     * @return array|WP_Error Company array on success; WP_Error on failure.
     */
    private static function get_remote_company(array $opts, string $token, string $id)
    {
        $api_base = esc_url_raw($opts['api_base']);
        $url = $api_base . '/' . self::API_ENDPOINT_COMPANY;
        $url = str_replace(':id', $id, $url);

        $headers  = [
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $token,
        ];

        $args = [
            'headers'   => $headers,
            'timeout'   => max(1, (int) $opts['timeout']),
            'sslverify' => (bool) $opts['sslverify'],
        ];

        $resp = wp_remote_get($url, $args);

        /*
         * Example /company/:id response:
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
            $msg = is_array($json) && !empty($json['err'])
                ? (string) $json['err']
                : sprintf(__('Authentication failed (HTTP %d).', 'wp-auth-custom-api-proxice'), $code);
            return new WP_Error('api_http_error', $msg);
        }

        if (!is_array($json)) {
            return new WP_Error('api_format_error', __('Invalid response from authentication server.', 'wp-auth-custom-api-proxice'));
        }

        return $json;
    }

    /**
     * Ensure a local WP user exists and is up-to-date:
     * - Fetches remote profile (/me).
     * - Optionally fetches company info (/company/:id).
     * - Finds existing user by email; otherwise creates a user if auto-provision is enabled.
     *
     * @param array       $opts        Plugin options.
     * @param string      $token       JWT.
     * @param array|null  $auth_result Raw auth response (unused today, kept for future logic).
     * @return WP_User|WP_Error
     */
    private static function create_or_update_wp_user(array $opts, string $token, ?array $auth_result = null)
    {
        $profile = self::get_remote_profile($opts, $token);
        if (is_wp_error($profile)) {
            return $profile; // bubble up
        }

        // Extract core identity fields
        $external_user_id = self::pluck($profile, '_id');
        $username = (string) self::pluck($profile, 'username'); // membership card # at this time
        $email = self::pluck($profile, 'email');

        // Additional attributes used in meta
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
        $WLC = (bool) self::pluck($profile, 'WLC'); // bool flag
        $wlcID = self::pluck($profile, 'wlcID');

        $displayName = $firstName . ' ' . $lastName;

        // Enrich with company record if available
        $company = null;
        if (!empty($companyID)) {
            $company = self::get_remote_company($opts, $token, $companyID);
            if (is_wp_error($company)) {
                return $company;
            }
        }

        // Prefer matching by login
        $user = get_user_by('login', $username);

        if (false === $user) {
            // At registration on WP the login does not match the membership card yet
            // grab the user by it's email
            $user = get_user_by('email', $email);
        }

        if ($user) {
            return self::update_wp_user($user, $profile, $company);
        }

        // No local user exists
        if (empty($opts['auto_provision'])) {
            return new WP_Error('no_local_account', __('Your account is not provisioned.', 'wp-auth-custom-api-proxice'));
        }

        if (!$email || !is_email($email)) {
            // WP requires a unique, valid email for new users
            return new WP_Error('provision_email_missing', __('Cannot create local user without a valid email.', 'wp-auth-custom-api-proxice'));
        }

        // Create with a random local password; local credential is unused
        $user_id = wp_insert_user([
            'user_login'   => $username,
            'user_pass'    => wp_generate_password(32),
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

        // Sync meta/roles
        self::update_wp_user($user, $profile, $company);

        return $user;
    }

    /**
     * Update a WP_User from the remote profile/company data.
     *
     * @param WP_User     $user
     * @param array       $profile
     * @param array|null  $company
     * @return WP_User|WP_Error
     */
    private static function update_wp_user(WP_User $user, array $profile, ?array $company = null)
    {
        // Extract profile attributes (dup of create step to keep function self-contained)
        $user_id = $user->ID;

        $external_user_id = self::pluck($profile, '_id');
        $username = (string) self::pluck($profile, 'username'); // membership card #
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
        $WLC = (bool) self::pluck($profile, 'WLC') ?: false;
        $wlcID = self::pluck($profile, 'wlcID');

        // Core user fields
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

        // Keep user_login aligned to remote "username" if it changed (requires direct db update)
        if (!empty($username) && $username !== $user->user_login) {
            $updated_login = self::update_wp_user_login($user->ID, $username);
            if (!empty($updated_login)) {
                $user->user_login = $username; // update runtime object to reflect change
            }
        }

        // Sync meta from remote identity
        if ($external_user_id) {
            update_user_meta($user_id, 'external_user_id', sanitize_text_field((string) $external_user_id));
        }

        if ($membershipCard) {
            update_user_meta($user_id, 'membership_card', sanitize_text_field((string) $membershipCard));
            update_user_meta($user_id, 'membership_card_expire_date', sanitize_text_field((string) $membershipCardExpireDate));
        } else {
            delete_user_meta($user_id, 'membership_card');
            delete_user_meta($user_id, 'membership_card_expire_date');
        }

        update_user_meta($user_id, 'mobile', $mobile ?: '');
        update_user_meta($user_id, 'status', $status ? '1' : '0');
        update_user_meta($user_id, 'company_id', $companyID ?: '');

        update_user_meta($user_id, 'local_offers_status', $local_offers_status ? '1' : '0');
        update_user_meta($user_id, 'company_offers_status', $company_offers_status ? '1' : '0');

        // Map company -> roles (auto-create role if needed)
        self::apply_api_roles($user, $profile, $company);

        return $user;
    }

    /**
     * Role mapping strategy:
     * - If company data is present: assign a role named after companynameFrench.
     *   If the role doesn't exist, create it (no capabilities).
     * - If no company: assign a "No Company" role (also auto-created if missing).
     *
     * Notes:
     * - We reset the user's roles to none first, then add exactly these mapped roles.
     * - If you want capabilities, add them in the add_role() third argument.
     *
     * @param WP_User|null $user
     * @param array        $profile
     * @param array|null   $company
     * @return void
     */
    private static function apply_api_roles(?WP_User $user, array $profile, ?array $company): void
    {
        if (!$user) {
            return;
        }

        $defaultRoleDisplayName = 'No Company';
        $roles = [$defaultRoleDisplayName];

        if ($company) {
            $companyName = trim($company['companynameFrench']);
            $roles = [$companyName];
        }

        if (is_array($roles)) {
            // Reset to no role; then add mapped roles
            $user->set_role('');

            foreach ($roles as $display_name) {
                $role_name = self::get_role_slug_by_display_name($display_name);

                if (empty($role_name)) {
                    // Role not found: create a slug from display name
                    $role_name = sanitize_key(strtolower(self::safe_str('corp_' . $display_name)));

                    $role = add_role(
                        $role_name,
                        $display_name,
                        [] // Capabilities: keep empty or customize per your needs
                    );

                    if (null === $role || !($role instanceof WP_Role)) {
                        // Failed to create role; bail without assigning to avoid partial state
                        return;
                    }

                    $role_name = $role->name;
                }

                $user->add_role($role_name);
            }
        }
    }

    /**
     * Deep getter supporting "dot.notation".
     *
     * @param mixed  $array Source array.
     * @param string $path  Dot path (e.g., 'user.profile.email').
     * @return mixed|null
     */
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

    /**
     * Adds a simple settings page under Settings → External Auth.
     *
     * @return void
     */
    public static function admin_menu(): void
    {
        add_options_page(
            __('External Auth (ProxiCE)', 'wp-auth-custom-api-proxice'),
            __('External Auth (ProxiCE)', 'wp-auth-custom-api-proxice'),
            'manage_options',
            'wp-auth-custom-api-proxice',
            [__CLASS__, 'render_settings']
        );
    }

    /**
     * Registers option storage, the main section, and the individual fields.
     *
     * @return void
     */
    public static function register_settings(): void
    {
        register_setting('wp_auth_custom_api_proxice', self::OPTION, [
            'type' => 'array',
            'sanitize_callback' => [__CLASS__, 'sanitize_options'],
            'default' => self::defaults(),
        ]);

        add_settings_section('main', __('Connection', 'wp-auth-custom-api-proxice'), '__return_false', 'wp-auth-custom-api-proxice');

        $fields = [
            'enabled'        => __('Enable API authentication', 'wp-auth-custom-api-proxice'),
            'api_base'       => __('API base URL', 'wp-auth-custom-api-proxice'),
            'timeout'        => __('Timeout (seconds)', 'wp-auth-custom-api-proxice'),
            'sslverify'      => __('Verify SSL certificate', 'wp-auth-custom-api-proxice'),
            'auto_provision' => __('Auto-provision local users', 'wp-auth_custom_api_proxice'),
            'role_default'   => __('Default role', 'wp-auth-custom-api-proxice'),
            'local_auth_roles' => __('Local auth roles (comma separated)', 'wp-auth-custom-api-proxice'),
        ];

        foreach ($fields as $key => $label) {
            add_settings_field($key, $label, [__CLASS__, 'render_field'], 'wp-auth-custom-api-proxice', 'main', ['key' => $key]);
        }
    }

    /**
     * Sanitizes and normalizes option input.
     *
     * @param mixed $input Raw settings input.
     * @return array<string,mixed>
     */
    public static function sanitize_options($input): array
    {
        $d = self::defaults();
        $out = [];

        $local_auth_roles = self::sanitize_key_csv_values(
            strtolower($input['local_auth_roles'])
        ) ?? $d['local_auth_roles'];

        $out['enabled']        = empty($input['enabled']) ? 0 : 1;
        $out['api_base']       = esc_url_raw($input['api_base'] ?? $d['api_base']);
        // $out['header_key']  = sanitize_text_field($input['header_key'] ?? $d['header_key']);
        $out['timeout']        = max(1, (int) ($input['timeout'] ?? $d['timeout']));
        $out['sslverify']      = empty($input['sslverify']) ? 0 : 1;
        $out['auto_provision'] = empty($input['auto_provision']) ? 0 : 1;
        $out['role_default']   = sanitize_key($input['role_default'] ?? $d['role_default']);
        $out['local_auth_roles'] = $local_auth_roles;

        return $out;
    }

    /**
     * Renders the plugin's settings page.
     *
     * @return void
     */
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
            <!-- <hr /> -->
            <!-- <details>
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
            </details> -->
        </div>
<?php
    }

    /**
     * Render a single field based on its key (checkbox/select/text/number).
     *
     * @param array $args ['key' => string]
     * @return void
     */
    public static function render_field(array $args): void
    {
        $key  = $args['key'];
        $opts = self::get_plugin_opts();
        $val  = $opts[$key] ?? '';

        $bools = ['enabled', 'sslverify', 'auto_provision'];
        if (in_array($key, $bools, true)) {
            printf(
                '<label><input type="checkbox" name="%1$s[%2$s]" value="1" %3$s/> %4$s</label>',
                esc_attr(self::OPTION),
                esc_attr($key),
                checked($val, 1, false),
                esc_html__('Yes', 'wp-auth-custom-api-proxice')
            );
            return;
        }

        if ($key === 'method') {
            printf(
                '<select name="%1$s[%2$s]"><option value="POST" %3$s>POST</option><option value="GET" %4$s>GET</option></select>',
                esc_attr(self::OPTION),
                esc_attr($key),
                selected($val, 'POST', false),
                selected($val, 'GET', false)
            );
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
        printf(
            '<input type="%1$s" name="%2$s[%3$s]" value="%4$s" class="regular-text" %5$s/>',
            esc_attr($type),
            esc_attr(self::OPTION),
            esc_attr($key),
            esc_attr($val),
            $extra
        );
    }

    /**
     * Optional: push profile updates to your external API when users edit their WP profile.
     * Currently a no-op; keep the hook for forward compatibility.
     *
     * @param int      $user_id       User ID being updated.
     * @param WP_User  $old_user_data Previous user object snapshot.
     * @return void
     */
    public static function maybe_sync_profile_back($user_id, $old_user_data): void
    {
        // Intentionally left as a stub; implement if your API needs it.
    }

    /**
     * Base64url decode helper (RFC 7515).
     *
     * @param string $data Base64url-encoded data.
     * @return string
     * @throws Exception On invalid segment.
     */
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
     * Lightweight JWT decoder with optional signature/time claim verification.
     *
     * @param string                    $jwt     Raw JWT string (header.payload.signature).
     * @param null|string|resource      $key     HS256: shared secret; RS256: OpenSSL public key (PEM string/resource).
     * @param array{verify?:bool,allowed_algs?:array,leeway?:int,time?:int} $options
     * @return array{header:array,payload:array,signature_valid:bool}
     * @throws Exception On malformed JWT or failed verification when enabled.
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
                    // If a resource is provided by user, do not free it.
                    $signatureValid = ($ok === 1);
                    if ($ok === -1) {
                        throw new Exception('OpenSSL verify error: ' . openssl_error_string());
                    }
                    break;

                default:
                    throw new Exception("Unsupported alg {$alg} in this helper.");
            }

            // Time claim checks (all optional in payload)
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

    /**
     * Find role by localized/display name.
     *
     * @param string $name Display name to search.
     * @return WP_Role|null
     */
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

    /**
     * Find role slug by its display name (case-insensitive).
     *
     * @param string $name Display name.
     * @return string|null Role slug or null if not found.
     */
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

    /**
     * Normalize a string to an uppercase, ASCII-ish, underscore-separated token.
     * Useful for generating stable role slugs from free-text company names.
     *
     * @param string $str
     * @param string $separator
     * @return string
     */
    private static function safe_str(string $str, string $separator = '_'): string
    {
        $str = trim(self::remove_accents($str));
        // Collapse non-alnum sequences to the separator
        $formatted = preg_replace('/[^A-Za-z0-9_]+/', $separator, $str);
        $formatted = trim($formatted, $separator);
        return $formatted;
    }

    /**
     * Lightweight diacritics removal with Intl transliterator fallback.
     *
     * @param string $str
     * @return string
     */
    private static function remove_accents(string $str): string
    {
        if (function_exists('transliterator_transliterate')) {
            return transliterator_transliterate('Any-Latin; Latin-ASCII; [:Nonspacing Mark:] Remove; NFC;', $str);
        }

        // Fallback table for common Latin diacritics
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

    /**
     * Update the user_login field directly in the DB (WordPress does not provide a setter).
     * Cleans the user cache after update.
     *
     * @param int    $ID         User ID
     * @param string $user_login New login
     * @return false|int         Rows updated count on success; false on failure
     */
    private static function update_wp_user_login(int $ID, string $user_login)
    {
        global $wpdb;

        $updated = false;

        if (!empty($ID)) {
            $updated = $wpdb->update(
                $wpdb->users,
                ['user_login' => $user_login],
                ['ID' => $ID]
            );

            if (!empty($updated)) {
                clean_user_cache($ID);
            }
        }


        return $updated;
    }

    private static function sanitize_key_csv_values(string $csv, bool $removeEmpty = true): string
    {
        // Split the string by commas
        $values = explode(',', $csv);

        $result = [];

        foreach ($values as $v) {
            $result[] = sanitize_key($v);
        }

        // Optionally remove empty entries
        if ($removeEmpty) {
            $result = array_filter($result, fn($v) => $v !== '');
        }

        // Rejoin the cleaned values into a string
        return implode(',', $result);
    }

    private static function has_matching_value(array $array1, array $array2): bool
    {
        // Check if there is any intersection between the two arrays
        return count(array_intersect($array1, $array2)) > 0;
    }
}

// Register hooks
WP_Auth_Custom_API_ProxiCE::init();
