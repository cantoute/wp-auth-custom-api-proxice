<?php

/**
 * dummy.php – Minimal WordPress shims for local linting
 * Drop this file in your project to avoid "undefined function/class" errors in IDEs.
 * Do NOT include this in production builds.
 */

declare(strict_types=1);

/* -------------------------------------------------------------------------- */
/*  Core constants                                                             */
/* -------------------------------------------------------------------------- */
if (!defined('ABSPATH')) {
	define('ABSPATH', __DIR__ . '/');
}

/* -------------------------------------------------------------------------- */
/*  Basic utility functions                                                    */
/* -------------------------------------------------------------------------- */
if (!function_exists('__')) {
	function __($text, $domain = null)
	{
		return $text;
	}
}
if (!function_exists('_e')) {
	function _e($text, $domain = null)
	{
		echo $text;
	}
}
if (!function_exists('esc_html__')) {
	function esc_html__($text, $domain = null)
	{
		return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
	}
}
if (!function_exists('esc_html_e')) {
	function esc_html_e($text, $domain = null)
	{
		echo esc_html__($text, $domain);
	}
}
if (!function_exists('esc_attr')) {
	function esc_attr($text)
	{
		return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
	}
}
if (!function_exists('esc_html')) {
	function esc_html($text)
	{
		return htmlspecialchars((string)$text, ENT_QUOTES, 'UTF-8');
	}
}
if (!function_exists('esc_url_raw')) {
	function esc_url_raw($url)
	{
		return (string)$url;
	}
}
if (!function_exists('sanitize_text_field')) {
	function sanitize_text_field($str)
	{
		return is_scalar($str) ? trim((string)$str) : '';
	}
}
if (!function_exists('sanitize_key')) {
	function sanitize_key($key)
	{
		return preg_replace('/[^a-z0-9_\-]/', '', strtolower((string)$key));
	}
}
if (!function_exists('is_email')) {
	function is_email($email)
	{
		return (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
	}
}
if (!function_exists('checked')) {
	function checked($checked, $current = true, $echo = true)
	{
		$result = $checked == $current ? 'checked="checked"' : '';
		if ($echo) echo $result;
		return $result;
	}
}
if (!function_exists('selected')) {
	function selected($selected, $current = true, $echo = true)
	{
		$result = $selected == $current ? 'selected="selected"' : '';
		if ($echo) echo $result;
		return $result;
	}
}
if (!function_exists('wp_json_encode')) {
	function wp_json_encode($data, $options = 0, $depth = 512)
	{
		return json_encode($data, $options, $depth);
	}
}
if (!function_exists('__return_false')) {
	function __return_false()
	{
		return false;
	}
}
if (!function_exists('wp_generate_password')) {
	function wp_generate_password($length = 24)
	{
		$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
		$pass = '';
		for ($i = 0; $i < $length; $i++) {
			$pass .= $chars[random_int(0, strlen($chars) - 1)];
		}
		return $pass;
	}
}

/* -------------------------------------------------------------------------- */
/*  WP_Error                                                                   */
/* -------------------------------------------------------------------------- */
if (!class_exists('WP_Error')) {
	class WP_Error
	{
		public $errors = [];
		public $error_data = [];
		public function __construct($code = '', $message = '', $data = '')
		{
			if (!empty($code)) {
				$this->errors[$code][] = $message;
				if ($data) $this->error_data[$code] = $data;
			}
		}
		public function get_error_code()
		{
			return key($this->errors);
		}
		public function get_error_message($code = '')
		{
			if ($code && !empty($this->errors[$code][0])) return $this->errors[$code][0];
			$code = key($this->errors);
			return $code && !empty($this->errors[$code][0]) ? $this->errors[$code][0] : '';
		}
		public function add($code, $message, $data = '')
		{
			$this->errors[$code][] = $message;
			if ($data) $this->error_data[$code] = $data;
		}
	}
}
if (!function_exists('is_wp_error')) {
	function is_wp_error($thing)
	{
		return $thing instanceof WP_Error;
	}
}

/* -------------------------------------------------------------------------- */
/*  Hooks (actions/filters)                                                    */
/* -------------------------------------------------------------------------- */
if (!function_exists('add_action')) {
	function add_action($hook, $callback, $priority = 10, $accepted_args = 1)
	{ /* no-op for linting */
	}
}
if (!function_exists('add_filter')) {
	function add_filter($hook, $callback, $priority = 10, $accepted_args = 1)
	{ /* no-op for linting */
	}
}

/* -------------------------------------------------------------------------- */
/*  Options API                                                                */
/* -------------------------------------------------------------------------- */
$GLOBALS['__DUMMY_WP_OPTIONS__'] = $GLOBALS['__DUMMY_WP_OPTIONS__'] ?? [];

if (!function_exists('get_option')) {
	function get_option($name, $default = false)
	{
		return array_key_exists($name, $GLOBALS['__DUMMY_WP_OPTIONS__']) ? $GLOBALS['__DUMMY_WP_OPTIONS__'][$name] : $default;
	}
}
if (!function_exists('update_option')) {
	function update_option($name, $value)
	{
		$GLOBALS['__DUMMY_WP_OPTIONS__'][$name] = $value;
		return true;
	}
}

/* -------------------------------------------------------------------------- */
/*  Users                                                                      */
/* -------------------------------------------------------------------------- */
if (!class_exists('WP_User')) {
	class WP_User
	{
		public $ID;
		public $user_login = '';
		public $user_email = '';
		public $roles = [];
		public function __construct($id = 0, $login = '', $email = '', $roles = [])
		{
			$this->ID = $id ?: random_int(1000, 9999);
			$this->user_login = $login;
			$this->user_email = $email;
			$this->roles = $roles ?: [];
		}
		public function set_role($role)
		{
			$this->roles = $role ? [$role] : [];
		}
		public function add_role($role)
		{
			if (!in_array($role, $this->roles, true)) $this->roles[] = $role;
		}
		public function remove_role($role)
		{
			$this->roles = array_values(array_diff($this->roles, [$role]));
		}
	}
}

$GLOBALS['__DUMMY_WP_USERS__'] = $GLOBALS['__DUMMY_WP_USERS__'] ?? [];

if (!function_exists('get_user_by')) {
	function get_user_by($field, $value)
	{
		foreach ($GLOBALS['__DUMMY_WP_USERS__'] as $u) {
			if ($field === 'id' && $u->ID == $value) return $u;
			if ($field === 'email' && $u->user_email === $value) return $u;
			if ($field === 'login' && $u->user_login === $value) return $u;
		}
		return false;
	}
}
if (!function_exists('wp_insert_user')) {
	function wp_insert_user($userdata)
	{
		$u = new WP_User(
			0,
			$userdata['user_login'] ?? '',
			$userdata['user_email'] ?? '',
			isset($userdata['role']) ? [$userdata['role']] : []
		);
		$GLOBALS['__DUMMY_WP_USERS__'][] = $u;
		return $u->ID;
	}
}
if (!function_exists('wp_update_user')) {
	function wp_update_user($userdata)
	{
		$u = get_user_by('id', (int)($userdata['ID'] ?? 0));
		if (!$u) return new WP_Error('user_not_found', 'User not found');
		if (isset($userdata['first_name'])) { /* ignore */
		}
		if (isset($userdata['last_name'])) { /* ignore */
		}
		if (isset($userdata['user_email'])) $u->user_email = $userdata['user_email'];
		return $u->ID;
	}
}
if (!function_exists('update_user_meta')) {
	function update_user_meta($user_id, $key, $value)
	{ /* no-op */
		return true;
	}
}
if (!function_exists('delete_user_meta')) {
	function delete_user_meta($user_id, $key)
	{ /* no-op */
		return true;
	}
}

/* -------------------------------------------------------------------------- */
/*  Roles                                                                      */
/* -------------------------------------------------------------------------- */
if (!class_exists('WP_Role')) {
	class WP_Role
	{
		public $name;
		public $capabilities;
		public function __construct($name, $caps = [])
		{
			$this->name = $name;
			$this->capabilities = $caps;
		}
	}
}
if (!class_exists('WP_Roles')) {
	class WP_Roles
	{
		public $roles = [
			'subscriber' => null,
			'administrator' => null,
		];

		public function __construct()
		{
			$this->roles['subscriber'] = new WP_Role('subscriber', []);
			$this->roles['administrator'] = new WP_Role('administrator', []);
		}

		public function get_role($role)
		{
			return $this->roles[$role] ?? null;
		}
	}
}
if (!function_exists('wp_roles')) {
	function wp_roles()
	{
		static $roles;
		if (!$roles) $roles = new WP_Roles();
		return $roles;
	}
}
if (!function_exists('add_role')) {
	function add_role($role, $display_name, $capabilities = [])
	{
		wp_roles()->roles[$role] = new WP_Role($role, $capabilities);
		return wp_roles()->roles[$role];
	}
}

/* -------------------------------------------------------------------------- */
/*  Admin UI (settings)                                                        */
/* -------------------------------------------------------------------------- */
if (!function_exists('add_options_page')) {
	function add_options_page($page_title, $menu_title, $capability, $menu_slug, $callback = '')
	{ /* no-op */
	}
}
if (!function_exists('register_setting')) {
	function register_setting($option_group, $option_name, $args = [])
	{ /* no-op */
	}
}
if (!function_exists('add_settings_section')) {
	function add_settings_section($id, $title, $callback, $page)
	{ /* no-op */
	}
}
if (!function_exists('add_settings_field')) {
	function add_settings_field($id, $title, $callback, $page, $section = 'default', $args = [])
	{ /* no-op */
	}
}
if (!function_exists('settings_fields')) {
	function settings_fields($option_group)
	{ /* no-op */
	}
}
if (!function_exists('do_settings_sections')) {
	function do_settings_sections($page)
	{ /* no-op */
	}
}
if (!function_exists('submit_button')) {
	function submit_button($text = 'Save Changes')
	{
		echo '<button type="submit">' . esc_attr($text) . '</button>';
	}
}
if (!function_exists('current_user_can')) {
	function current_user_can($cap)
	{
		return true;
	}
}

/* -------------------------------------------------------------------------- */
/*  HTTP API                                                                   */
/* -------------------------------------------------------------------------- */
if (!function_exists('wp_remote_post')) {
	function wp_remote_post($url, $args = [])
	{
		return [
			'response' => ['code' => 200, 'message' => 'OK'],
			'body' => wp_json_encode(['ok' => true]),
			'headers' => [],
		];
	}
}
if (!function_exists('wp_remote_get')) {
	function wp_remote_get($url, $args = [])
	{
		return [
			'response' => ['code' => 200, 'message' => 'OK'],
			'body' => wp_json_encode(['ok' => true]),
			'headers' => [],
		];
	}
}
if (!function_exists('wp_remote_retrieve_response_code')) {
	function wp_remote_retrieve_response_code($response)
	{
		return (int)($response['response']['code'] ?? 0);
	}
}
if (!function_exists('wp_remote_retrieve_body')) {
	function wp_remote_retrieve_body($response)
	{
		return (string)($response['body'] ?? '');
	}
}

/* -------------------------------------------------------------------------- */
/*  DB / $wpdb                                                                 */
/* -------------------------------------------------------------------------- */
if (!isset($GLOBALS['wpdb'])) {
	$GLOBALS['wpdb'] = new class {
		public $users = 'wp_users';
		public function update($table, $data, $where)
		{
			// Pretend update succeeded (1 row)
			return 1;
		}
	};
}
if (!function_exists('clean_user_cache')) {
	function clean_user_cache($user_id)
	{ /* no-op */
	}
}

/* -------------------------------------------------------------------------- */
/*  Misc                                                                       */
/* -------------------------------------------------------------------------- */
if (!function_exists('admin_url')) {
	function admin_url($path = '')
	{
		return 'http://example.com/wp-admin/' . ltrim($path, '/');
	}
}
if (!function_exists('is_a')) {
	// PHP has is_a() natively; this is just to be safe in some analyzers.
	function is_a($object, $class_name)
	{
		return $object instanceof $class_name;
	}
}
