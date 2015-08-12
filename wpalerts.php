<?php
/*
Plugin Name: WPAlerts
Plugin URI: http://wp-alerts.com/
Description: WPAlerts is a free plugin that helps you to make updates on your WordPress sites (with the WPAlerts software http://wp-alerts.com/).
Version: 1.0
Author: OC Web Logic
Author URI: http://www.ocweblogic.com/
License: GPL2
*/
/*
Copyright 2015 OC Web Logic (email: rich@ocweblogic.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

if(!class_exists('WPAlerts_Plugin'))
{
  class WPAlerts_Plugin {

	public function __construct() {
		// Check PHP Version and deactivate & die if it doesn't meet minimum requirements.
		if ( version_compare( phpversion(), '5.2', '<' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
			deactivate_plugins( plugin_basename( __FILE__ ) );
			die( __('This plugin requires PHP Version 5.2+', 'wpalerts') );
		}

		if ( version_compare( get_bloginfo( 'version' ), '3.1', '<' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
			deactivate_plugins( plugin_basename( __FILE__ ) );
			die( __('This plugin requires Wordpress Version 3.1+', 'wpalerts') );
		}
		add_action( 'init', array(&$this, 'process_post') );
		add_action('admin_init', array(&$this, 'wpalerts_admin_init'));
		add_action('admin_menu', array(&$this, 'wpalerts_admin_menu'));
		add_action('admin_notices', array(&$this, 'wpalerts_admin_notices'));
		add_filter('request_filesystem_credentials', array(&$this, 'set_filesystem_credentials'));
	}

	public function wpalerts_admin_init()
	{
	  register_setting('wpalerts-api-key-settings', 'wpalerts_api_key');
	}

	public function wpalerts_admin_menu()
	{
	    add_options_page('WPAlerts', 'WPAlerts', 'manage_options', 'wpalerts-key-api-config', array(&$this, 'setup_key_option_page'));
	}

	public function wpalerts_admin_notices() {
		global $hook_suffix;
		if ( $hook_suffix == 'plugins.php' && !$this->get_api_keys()) {
			self::display_api_key_message();
		}
	}

	public function display_api_key_message()
	{
	?>
		<div class="updated" style="display:block !important;">
		<form method="post" action="<?php echo self::get_wpalerts_options_page_url()?>">
		<p>
		<input type="submit" value="<?php _e( 'Activate WPAlerts Plugin', 'wpalerts' ); ?>" class="button-primary" />
		<strong style="margin-left:15px;"><?php _e( 'You are almost ready, just enter your WPAlerts API Key on the WPAlerts Plugin Settings Page', 'wpalerts' ); ?></strong>
		</p>
		</form>
		</div>
	<?php
	}

	public static function get_wpalerts_options_page_url() {
		return add_query_arg( array( 'page' => 'wpalerts-key-api-config' ), admin_url( 'options-general.php' ) );
	}

	public function setup_key_option_page() { 
	?>
		<div class="wrap">
		<h2>WPAlerts Settings</h2>
		<form method="post" action="options.php" novalidate="novalidate">
		<?php settings_fields( 'wpalerts-api-key-settings' ); ?>
		<table class="form-table">
		<tr>
		<th scope="row"><label for="wpalerts_api_key"><?php _e('Enter your API Key') ?></label></th>
		<td><input name="wpalerts_api_key" type="text" id="wpalerts_api_key" value="<?php form_option('wpalerts_api_key'); ?>" class="regular-text" />
		<p class="description" id="wpalerts-api-key-description">
		<?php _e( 'You can find your website API Key under <a href="https://wp-alerts.com/dashboard/#/" target="_blank">WPAlerts Software Dashboard</a>' ) ?></p>
		</td>
		</tr>
		</table>
		<p class="submit"><?php submit_button(); ?></p>
		<?php do_settings_sections( 'wpalerts-api-key-settings' ); ?>
		</form>
		</div>
	<?php 
	}

	public function check_filesystem_access() {
		ob_start();
		$success = request_filesystem_credentials( '' );
		ob_end_clean();
		return (bool) $success;
	}

	public function set_filesystem_credentials( $credentials ) {
		if ( empty( $_POST['filesystem_details'] )) return $credentials;
		$_credentials = array(
			'username' => $_POST['filesystem_details']['credentials']['username'],
			'password' => $_POST['filesystem_details']['credentials']['password'],
			'hostname' => $_POST['filesystem_details']['credentials']['hostname'],
			'connection_type' => $_POST['filesystem_details']['method']
		);
		if ( ! WP_Filesystem( $_credentials ) ) {
			return $credentials;
		}
		return $_credentials;
	}

	public function generate_secret($vars) {
		$api_keys = $this->get_api_keys();
		if (!$api_keys ) return array();
		$hashes = array();
		foreach( $api_keys as $key ) {
		  $hashes[] = hash_hmac('ripemd160', serialize($vars), $key);			
		}
		return $hashes;
	}

	public function get_plugins()
	{
	  require_once( ABSPATH . '/wp-admin/includes/plugin.php' );
	  $plugins = get_plugins();
	  $active  = get_option( 'active_plugins', array() );
  	  if ( function_exists( 'get_site_transient' ) ) delete_site_transient( 'update_plugins' );
	  else 	delete_transient( 'update_plugins' );
	  wp_update_plugins();
	  if( function_exists( 'get_site_transient' ) && $transient = get_site_transient( 'update_plugins' ) ) $current = $transient;
	  elseif( $transient = get_transient( 'update_plugins' ) ) $current = $transient;
	  else $current = get_option( 'update_plugins' );
	  foreach ( (array) $plugins as $plugin_file => $plugin ) {
	    if ( is_plugin_active( $plugin_file ) )
	    	$plugins[$plugin_file]['active'] = true;
	    else
	    	$plugins[$plugin_file]['active'] = false;
	    $manage_wp_plugin_update = false;
	    if ( $manage_wp_plugin_update ) {
			$plugins[$plugin_file]['latest_version'] = $manage_wp_plugin_update['new_version'];
	    } else if ( isset( $current->response[$plugin_file] ) ) {
			$plugins[$plugin_file]['latest_version'] = $current->response[$plugin_file]->new_version;
			$plugins[$plugin_file]['latest_package'] = $current->response[$plugin_file]->package;
	    		$plugins[$plugin_file]['slug'] = $current->response[$plugin_file]->slug;
	    } else {
	    	$plugins[$plugin_file]['latest_version'] = $plugin['Version'];
	    }
	  }
	  return $plugins;
	}


	public function update_plugin( $plugin_file, $args ) {
		global $wpalerts_zip_update;
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) return new WP_Error( 'disallow-file-mods', __( "File modification is disabled with the DISALLOW_FILE_MODS constant.", 'wpalerts' ) );
		include_once ( ABSPATH . 'wp-admin/includes/admin.php' );
		require_once ( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
		if ( ! $this->check_filesystem_access() ) return new WP_Error( 'filesystem-not-writable', __( 'The filesystem is not writable with the supplied credentials', 'wpalerts' ) );
		$is_active         = is_plugin_active( $plugin_file );
		$is_active_network = is_plugin_active_for_network( $plugin_file );
		foreach( get_plugins() as $path => $maybe_plugin ) {
			if ( $path == $plugin_file ) {
				$plugin = $maybe_plugin;
				break;
			}
		}
		if ( ! empty( $args['zip_url'] ) ) {
			$zip_url = $args['zip_url'];
		} 
		$skin = new Plugin_Installer_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		if ( ! empty( $zip_url ) ) {
			$wpalerts_zip_update = array(
				'plugin_file'    => $plugin_file,
				'package'        => $zip_url,
			);
			add_filter( 'pre_site_transient_update_plugins', array(&$this, 'forcably_filter_update_plugins'));
		} else {
			wp_update_plugins();
		}
		ob_start();
		$result = $upgrader->upgrade( $plugin_file );
		$data = ob_get_contents();
		ob_clean();
		if ( $manage_wp_plugin_update )
			remove_filter( 'pre_site_transient_update_plugins', array(&$this, 'forcably_filter_update_plugins'));
		if ( ! empty( $skin->error ) )
			return new WP_Error( 'plugin-upgrader-skin', $upgrader->strings[$skin->error] );
		else if ( is_wp_error( $result ) )
			return $result;
		else if ( ( ! $result && ! is_null( $result ) ) || $data )
			return new WP_Error( 'plugin-update', __( 'Unknown error updating plugin.', 'wpalerts' ) );
		if ( $is_active )
			activate_plugin( $plugin_file, '', $is_active_network, true );
		return array( 'status' => 'success' );
	}

	public function forcably_filter_update_plugins() {
		global $wpalerts_zip_update;
		$current = new stdClass;
		$current->response = array();
		$plugin_file = $wpalerts_zip_update['plugin_file'];
		$current->response[$plugin_file] = new stdClass;
		$current->response[$plugin_file]->package = $wpalerts_zip_update['package'];
		return $current;
	}

	
	public function get_themes()
	{
	  require_once( ABSPATH . '/wp-admin/includes/theme.php' );
	  if ( function_exists( 'wp_get_themes' )) $themes = wp_get_themes();
	  else $themes = get_themes();
	  $active  = get_option( 'current_theme' );
	  if ( function_exists( 'get_site_transient' ) ) delete_site_transient( 'update_themes' );
	  else delete_transient( 'update_themes' );
	  wp_update_themes();
	  if ( function_exists( 'get_site_transient' ) && $transient = get_site_transient( 'update_themes' ) ) $current = $transient;
	  elseif ( $transient = get_transient( 'update_themes' ) ) $current = $transient;
	  else $current = get_option( 'update_themes' );
	  foreach ( (array) $themes as $key => $theme ) 
	  {
		if ( is_object( $theme ) && is_a( $theme, 'WP_Theme' ) ) {
			$new_version = isset( $current->response[$theme->get_stylesheet()] ) ? $current->response[$theme->get_stylesheet()]['new_version'] : null;
			$theme_array = array(
				'Name'           => $theme->get( 'Name' ),
				'active'         => $active == $theme->get( 'Name' ),
				'Template'       => $theme->get_template(),
				'Stylesheet'     => $theme->get_stylesheet(),
				'Screenshot'     => $theme->get_screenshot(),
				'AuthorURI'      => $theme->get( 'AuthorURI' ),
				'Author'         => $theme->get( 'Author' ),
				'latest_version' => $new_version ? $new_version : $theme->get( 'Version' ),
				'Version'        => $theme->get( 'Version' ),
				'ThemeURI'       => $theme->get( 'ThemeURI' )
			);
			$themes[$key] = $theme_array;
		} else {
			$new_version = isset( $current->response[$theme['Stylesheet']] ) ? $current->response[$theme['Stylesheet']]['new_version'] : null;
			if ( $active == $theme['Name'] ) $themes[$key]['active'] = true;
			else $themes[$key]['active'] = false;
			if ( $new_version ) {
				$themes[$key]['latest_version'] = $new_version;
				$themes[$key]['latest_package'] = $current->response[$theme['Template']]['package'];
			} else {
				$themes[$key]['latest_version'] = $theme['Version'];
			}
		}
	  }
	  return $themes;
	}

        public function update_theme($theme)
	{
	  if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) return new WP_Error( 'disallow-file-mods', __( "File modification is disabled with the DISALLOW_FILE_MODS constant.", 'wpalerts' ) );
	  include_once ( ABSPATH . 'wp-admin/includes/admin.php' );
	  require_once ( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
	  if ( ! $this->check_filesystem_access() ) return new WP_Error( 'filesystem-not-writable', __( 'The filesystem is not writable with the supplied credentials', 'wpalerts' ) );
	  $skin = new Theme_Installer_Skin();
	  $upgrader = new Theme_Upgrader($skin);
	  ob_start();
	  $result = $upgrader->upgrade( $theme );
	  $data = ob_get_contents();
	  ob_clean();
	  if ( ! empty( $skin->error ) )
		return new WP_Error( 'theme-upgrader-skin', $upgrader->strings[$skin->error] );
	  else if ( is_wp_error( $result ) )
		return $result;
	  else if ( ( ! $result && ! is_null( $result ) ) || $data )
		return new WP_Error( 'theme-update', __( 'Unknown error updating theme.', 'wpalerts' ) );
	  return array( 'status' => 'success' );
	}

        public function upgrade_core()  
	{
	  if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) return new WP_Error( 'disallow-file-mods', __( "File modification is disabled with the DISALLOW_FILE_MODS constant.", 'wpalerts' ) );
	  include_once ( ABSPATH . 'wp-admin/includes/admin.php' );
	  include_once ( ABSPATH . 'wp-admin/includes/upgrade.php' );
	  include_once ( ABSPATH . 'wp-includes/update.php' );
	  require_once ( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
	  if ( ! $this->check_filesystem_access() ) return new WP_Error( 'filesystem-not-writable', __( 'The filesystem is not writable with the supplied credentials', 'wpalerts' ) );
	  wp_version_check();
	  $updates = get_core_updates();
	  if ( is_wp_error( $updates ) || ! $updates ) return new WP_Error( 'no-update-available' );
	  $update = reset( $updates );
	  if ( ! $update ) return new WP_Error( 'no-update-available' );
	  $skin = new WP_Upgrader_Skin();
	  $upgrader = new Core_Upgrader( $skin );
	  $result = $upgrader->upgrade($update);
	  if ( is_wp_error( $result ) ) return $result;
	  global $wp_current_db_version, $wp_db_version;
	  require( ABSPATH . WPINC . '/version.php' );
	  wp_upgrade();
	  return true;
	}

        public function do_backup($backup_type)
	{
	  Backups::get_instance()->set_type($backup_type);
	  return Backups::get_instance()->do_backup();
	}

        public function get_backup()
	{
	  return Backups::get_instance()->get_backup();
	}

        public function delete_backup()
	{
	  return Backups::get_instance()->cleanup();
	}			

        public function process_post()
	{
	  if ( empty( $_POST['wpalert_key'])) return;
	  if (!$this->get_api_keys()) 
  	  {
  	    echo json_encode('empty-wpalert-key');
	    die();
	  } 
          elseif ( isset( $_POST['wpalert_key'] ) ) 
          {
	    $verify = $_POST['wpalert_key'];
	    unset( $_POST['wpalert_key'] );

	    $hash = $this->generate_secret( $_POST );

	    if ( ! in_array( $verify, $hash, true ) ) {
	      echo json_encode( 'wrong-wpalert-key' );
	      exit;
   	    }

	    if ( (int) $_POST['ts'] > time() + 360 || (int) $_POST['ts'] < time() - 360 ) {
	      echo json_encode( 'wrong-timestamp' );
	      exit;	
  	    }

	    wp_set_current_user(1);
	    include_once ( ABSPATH . 'wp-admin/includes/admin.php' );
	    $actions = array();

	    foreach($_POST['wp_act'] as $type ) {
	
	      switch( $type ) {

		case 'wpalerts_get_wp_version' :
			global $wp_version;
			$wp_act[$type] = (string) $wp_version;
		break;

		case 'wpalerts_get_plugins':
			$wp_act[$type] = $this->get_plugins();
		break;

		case 'wpalerts_upgrade_plugin' : 
			$wp_act[$type] = $this->update_plugin(sanitize_text_field($_POST['plugin']));
		break;

		case 'wpalerts_get_themes' :
			$wp_act[$type] = $this->get_themes();
		break;

		case 'wpalerts_upgrade_theme' : 
			$wp_act[$type] = $this->update_theme(sanitize_text_field($_POST['theme']));
		break;

		case 'wpalerts_upgrade_core' :
			$wp_act[$type] = $this->upgrade_core();
		break;

		case 'wpalerts_backup' :
			$wp_act[$type] = $this->do_backup(sanitize_text_field($_POST['backup_type']));
		break;

		case 'wpalerts_get_backup' :
			$wp_act[$type] = $this->get_backup();
		break;

		case 'wpalerts_clean_backup' :
			$wp_act[$type] = $this->delete_backup();
		break;

		default :
			$wp_act[$type] = 'bad request';
		break;
	      }
	    }
		
	    foreach ( $wp_act as $key => $type ) {
	      if ( is_wp_error( $type ) ) {
		$wp_act[$key] = (object) array(
			'errors' => $type->errors
		);
	      }
 	    }

	    echo json_encode( $wp_act );
	    die();
	  } else {
	    die();
	  }
	  return true;
	  die();
	} 

	public function get_api_keys() {
		$wpalerts_api_keys = apply_filters( 'wpalerts_api_keys', get_option( 'wpalerts_api_key' ) );
		if ( ! empty( $wpalerts_api_keys )  ) return (array)$wpalerts_api_keys;
		else return array();
	}

	public static function activate()
	{
	}

	public static function deactivate()
        {
	  delete_option( 'wpalerts_api_key' );
        } // END public static function deactivate
  } // END class WPAlerts_Plugin
} // END if(!class_exists('WPAlerts_Plugin'))

class Backup_Base {

	private $path = '';
	private $type = '';
	protected $start_timestamp;
	private $archive_filename = '';
	private $database_dump_filename = '';
	private $zip_command_path;
	private $mysqldump_command_path;
	private $excludes = array();
	private $root = '';
	private $db;
	private $files = array();
	private $excluded_files = array();
	private $unreadable_files = array();
	private $errors = array();
	private $warnings = array();
	private $archive_method = '';
	private $mysqldump_method = '';
	private $using_file_manifest = false;
	private $current_file_manifest = false;
	private $file_manifest_already_archived = array();
	private $file_manifest_per_batch = 200;
	protected $file_manifest_remaining = 0;
	private $ziparchive = false;
	private $pclzip = false;
	public static function is_safe_mode_active( $ini_get_callback = 'ini_get' ) {
		if ( ( $safe_mode = @call_user_func( $ini_get_callback, 'safe_mode' ) ) && strtolower( $safe_mode ) != 'off' )
			return true;
		return false;
	}

	public static function is_shell_exec_available() {
		if ( self::is_safe_mode_active() )
			return false;
		if ( array_intersect( array( 'shell_exec', 'escapeshellarg', 'escapeshellcmd' ), array_map( 'trim', explode( ',', @ini_get( 'disable_functions' ) ) ) ) )
			return false;
		if ( array_intersect( array( 'shell_exec', 'escapeshellarg', 'escapeshellcmd' ), array_map( 'trim', explode( ',', @ini_get( 'suhosin.executor.func.blacklist' ) ) ) ) )
			return false;
		if ( ! @shell_exec( 'echo backupwordpress' ) )
			return false;
		return true;
	}


	public static function get_home_path() {
		$home_url = home_url();
		$site_url = site_url();
		$home_path = ABSPATH;
		if ( $home_url !== $site_url && strpos( $site_url, $home_url ) === 0 )
			$home_path = trailingslashit( substr( self::conform_dir( ABSPATH ), 0, strrpos( self::conform_dir( ABSPATH ), str_replace( $home_url, '', $site_url ) ) ) );
		return self::conform_dir( $home_path );
	}

	public static function conform_dir( $dir, $recursive = false ) {
		if ( ! $dir )
			$dir = '/';
		$dir = str_replace( '\\', '/', $dir );
		$dir = str_replace( '//', '/', $dir );
		if ( $dir !== '/' )
			$dir = untrailingslashit( $dir );
		if ( ! $recursive && self::conform_dir( $dir, true ) != $dir )
			return self::conform_dir( $dir );
		return (string) $dir;
	}

	public function __construct() {
		@ini_set( 'memory_limit', apply_filters( 'admin_memory_limit', WP_MAX_MEMORY_LIMIT ) );
		@set_time_limit( 0 );
		set_error_handler( array( &$this, 'error_handler' ) );
	}

	public function get_archive_filepath() {
		return trailingslashit( $this->get_path() ) . $this->get_archive_filename();
	}

	public function get_archive_filename() {
		if ( empty( $this->archive_filename ) ) {
			if ( empty( $this->start_timestamp ) )
				$this->start_timestamp = current_time( 'timestamp' );
			$this->set_archive_filename( implode( '-', array( sanitize_title( str_ireplace( array( 'http://', 'https://', 'www' ), '', home_url() ) ), 'backup', date( 'Y-m-d-H-i-s', $this->start_timestamp ) ) ) . '.zip' );
		}
		return $this->archive_filename;

	}

	public function set_archive_filename( $filename ) {
		if ( empty( $filename ) || ! is_string( $filename ) )
			throw new Exception( __( 'archive filename must be a non empty string', 'wpalerts' ) );
		if ( pathinfo( $filename, PATHINFO_EXTENSION ) !== 'zip' )
			throw new Exception( __( 'invalid file extension for archive filename', 'wpalerts' ) .  '<code>' . $filename . '</code>' );
		$this->archive_filename = strtolower( sanitize_file_name( remove_accents( $filename ) ) );
	}

	public function get_database_dump_filepath() {
		return trailingslashit( $this->get_path() ) . $this->get_database_dump_filename();
	}

	public function get_database_dump_filename() {
		if ( empty( $this->database_dump_filename ) )
			$this->set_database_dump_filename( 'database_' . DB_NAME . '.sql' );
		return $this->database_dump_filename;
	}

	public function set_database_dump_filename( $filename ) {
		if ( empty( $filename ) || ! is_string( $filename ) )
			throw new Exception( __( 'database dump filename must be a non empty string', 'wpalerts' ) );
		if ( pathinfo( $filename, PATHINFO_EXTENSION ) !== 'sql' )
			throw new Exception( __( 'invalid file extension for database dump filename', 'wpalerts' ) . '<code>' . $filename . '</code>' );
		$this->database_dump_filename = strtolower( sanitize_file_name( remove_accents( $filename ) ) );
	}

    	public function get_root() {
		if ( empty( $this->root ) )
			$this->set_root( self::conform_dir( self::get_home_path() ) );
        	return $this->root;
    	}

    	public function set_root( $path ) {

    	if ( empty( $path ) || ! is_string( $path ) || ! is_dir ( $path ) )
    		throw new Exception( sprintf( __( 'Invalid root path %s must be a valid directory path', 'wpalerts' ), '<code>' . $path . '</code>' ) );

    	$this->root = self::conform_dir( $path );

    	}

    	public function get_path() {

		if ( empty( $this->path ) )
			$this->set_path( self::conform_dir( hmbkp_path_default() ) );

        return $this->path;
    	}

    	public function set_path( $path ) {
    	if ( empty( $path ) || ! is_string( $path ) )
    		throw new Exception( sptrinf( __( 'Invalid backup path %s must be a non empty (string)', 'wpalerts' ), '<code>' . $path . '</code>' ) );
    	$this->path = self::conform_dir( $path );
    	}

   	 public function get_archive_method() {
	return $this->archive_method;
    	}

    	public function get_mysqldump_method() {
		return $this->mysqldump_method;
    	}

    	public function is_using_file_manifest() {
		return apply_filters( 'use_file_manifest', (bool)$this->using_file_manifest );
    	}

        public function set_is_using_file_manifest( $val ) {
		$this->using_file_manifest = (bool)$val;
        }

        private function create_file_manifests() {
		if ( is_dir( $this->get_file_manifest_dirpath() ) )
			$this->rmdir_recursive( $this->get_file_manifest_dirpath() );

		mkdir( $this->get_file_manifest_dirpath(), 0755 );
		$index = $this->get_file_manifest_dirpath() . '/index.html';
		if ( ! file_exists( $index ) && is_writable( $this->get_file_manifest_dirpath() ) )
			file_put_contents( $index, '' );
		$excludes = $this->exclude_string( 'regex' );
		$file_manifest = array();
		$this->file_manifest_remaining = 0;
		$file_manifest_file_count = 0;
		$current_batch = 0;
		foreach( $this->get_files() as $file ) {

			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			// Skip unreadable files
			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
				continue;

		    // Excludes
		    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) )
		        continue;

			if ( $file->isDir() )
				$line = trailingslashit( str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) );

			elseif ( $file->isFile() )
				$line = str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) );

			// File manifest is full
			if ( ! empty( $current_file ) && $current_batch >= $this->file_manifest_per_batch ) {

				@fclose( $current_file );
				$current_file = false;

			}

			// Create a new file manifest
			if ( empty( $current_file ) ) {

				$file_manifest_file_count++;
				$file_manifest_filename = str_pad( $file_manifest_file_count, 10, "0", STR_PAD_LEFT );
				if ( ! $current_file = @fopen( $this->get_file_manifest_dirpath() . '/' . $file_manifest_filename . '.txt', 'w' ) )
					return false;

				$current_batch = 0;
			}

			// Write the line to the file manifest if it isn't empty for some reason
			if ( ! empty( $line ) ) {
				@fwrite( $current_file, $line . PHP_EOL );
				unset( $line );
				$this->file_manifest_remaining++;
				$current_batch++;
			}

		}

		@file_put_contents( $this->get_path() . '/.file-manifest-remaining', $this->file_manifest_remaining );

		return true;
	}

	private function delete_current_file_manifest() {

		if ( ! file_exists( $this->current_file_manifest ) )
			return false;

		unlink( $this->current_file_manifest );

		$this->file_manifest_remaining = $this->file_manifest_remaining - count( $this->file_manifest_already_archived );
		if ( $this->file_manifest_remaining < 0 )
			$this->file_manifest_remaining = 0;
		file_put_contents( $this->get_path() . '/.file-manifest-remaining', $this->file_manifest_remaining );

		$this->file_manifest_already_archived = array();

	}


	protected function get_file_manifest_dirpath() {
		return $this->get_path() . '/.file-manifests';
	}

	private function get_next_files_from_file_manifest() {

		if ( ! is_dir( $this->get_file_manifest_dirpath() ) )
			return array();

		$files = glob( $this->get_file_manifest_dirpath() . '/*.txt' );
		if ( empty( $files ) )
			return array();

		$this->current_file_manifest = array_shift( $files );

		$files = file_get_contents( $this->current_file_manifest );
		$files = array_map( 'trim', explode( PHP_EOL, $files ) );
		if ( empty( $files ) )
			return array();

		$this->file_manifest_remaining = (int)file_get_contents( $this->get_path() . '/.file-manifest-remaining' );

		return $files;
	}

	public function get_type() {

		if ( empty( $this->type ) )
			$this->set_type( 'complete' );

		return $this->type;

	}

	public function set_type( $type ) {

		if ( ! is_string( $type ) || ! in_array( $type, array( 'file', 'database', 'complete' ) ) )
			throw new Exception( sprintf( __( 'Invalid backup type %s must be one of (string) file, database or complete', 'wpalerts' ), '<code>' . $type . '</code>' ) );

		$this->type = $type;

	}

	public function get_mysqldump_command_path() {

		// Check shell_exec is available
		if ( ! self::is_shell_exec_available() )
			return '';

		// Return now if it's already been set
		if ( isset( $this->mysqldump_command_path ) )
			return $this->mysqldump_command_path;

		$this->mysqldump_command_path = '';

		// Does mysqldump work
		if ( is_null( shell_exec( 'hash mysqldump 2>&1' ) ) ) {

			// If so store it for later
			$this->set_mysqldump_command_path( 'mysqldump' );

			// And return now
			return $this->mysqldump_command_path;

		}

		// List of possible mysqldump locations
		$mysqldump_locations = array(
			'/usr/local/bin/mysqldump',
			'/usr/local/mysql/bin/mysqldump',
			'/usr/mysql/bin/mysqldump',
			'/usr/bin/mysqldump',
			'/opt/local/lib/mysql6/bin/mysqldump',
			'/opt/local/lib/mysql5/bin/mysqldump',
			'/opt/local/lib/mysql4/bin/mysqldump',
			'/xampp/mysql/bin/mysqldump',
			'/Program Files/xampp/mysql/bin/mysqldump',
			'/Program Files/MySQL/MySQL Server 6.0/bin/mysqldump',
			'/Program Files/MySQL/MySQL Server 5.5/bin/mysqldump',
			'/Program Files/MySQL/MySQL Server 5.4/bin/mysqldump',
			'/Program Files/MySQL/MySQL Server 5.1/bin/mysqldump',
			'/Program Files/MySQL/MySQL Server 5.0/bin/mysqldump',
			'/Program Files/MySQL/MySQL Server 4.1/bin/mysqldump',
			'/opt/local/bin/mysqldump',
		);
		foreach ( $mysqldump_locations as $location )
		    if ( @is_executable( self::conform_dir( $location ) ) )
	 	    	$this->set_mysqldump_command_path( $location );

		return $this->mysqldump_command_path;

	}

	public function set_mysqldump_command_path( $path ) {
		$this->mysqldump_command_path = $path;
	}

	public function get_zip_command_path() {
		if ( ! self::is_shell_exec_available() )
			return '';

		// Return now if it's already been set
		if ( isset( $this->zip_command_path ) )
			return $this->zip_command_path;

		$this->zip_command_path = '';

		// Does zip work
		if ( is_null( shell_exec( 'hash zip 2>&1' ) ) ) {

			// If so store it for later
			$this->set_zip_command_path( 'zip' );

			// And return now
			return $this->zip_command_path;

		}

		// List of possible zip locations
		$zip_locations = array(
			'/usr/bin/zip',
			'/opt/local/bin/zip',
		);

		// Find the one which works
		foreach ( $zip_locations as $location )
			if ( @is_executable( self::conform_dir( $location ) ) )
				$this->set_zip_command_path( $location );

		return $this->zip_command_path;

	}

	public function set_zip_command_path( $path ) {
		$this->zip_command_path = $path;
	}

	protected function &setup_ziparchive() {

		// Instance is already open
		if ( ! empty( $this->ziparchive ) ) {
			$this->ziparchive->open( $this->get_archive_filepath(), ZIPARCHIVE::CREATE );
			return $this->ziparchive;
		}

		$ziparchive = new ZipArchive;

		// Try opening ZipArchive
		if ( ! file_exists( $this->get_archive_filepath() ) )
			$ret = $ziparchive->open( $this->get_archive_filepath(), ZIPARCHIVE::CREATE );
		else
			$ret = $ziparchive->open( $this->get_archive_filepath() );

		// File couldn't be opened
		if ( ! $ret )
			return false;

		// Try closing ZipArchive
		$ret = $ziparchive->close();

		// File couldn't be closed
		if ( ! $ret )
			return false;

		// Open it once more
		if ( ! file_exists( $this->get_archive_filepath() ) )
			$ziparchive->open( $this->get_archive_filepath(), ZIPARCHIVE::CREATE );
		else
			$ziparchive->open( $this->get_archive_filepath() );

		$this->ziparchive = $ziparchive;
		return $this->ziparchive;
	}

	protected function &setup_pclzip() {

		if ( empty( $this->pclzip ) ) {
			$this->load_pclzip();
			$this->pclzip = new PclZip( $this->get_archive_filepath() );
		}
		return $this->pclzip;
	}

	protected function do_action( $action ) {

		do_action( $action, $this );

	}

	public function backup() {

		$this->do_action( 'backup_started' );

		// Backup database
		if ( $this->get_type() !== 'file' )
		    $this->dump_database();

		// Zip everything up
		$this->archive();

		$this->do_action( 'backup_complete' );

	}

	public function dump_database() {

		if ( $this->get_mysqldump_command_path() )
			$this->mysqldump();

		if ( empty( $this->mysqldump_verified ) )
			$this->mysqldump_fallback();

		$this->do_action( 'mysqldump_finished' );

	}

	public function mysqldump() {

		$this->mysqldump_method = 'mysqldump';

		$this->do_action( 'mysqldump_started' );

		$host = explode( ':', DB_HOST );

		$host = reset( $host );
		$port = strpos( DB_HOST, ':' ) ? end( explode( ':', DB_HOST ) ) : '';

		// Path to the mysqldump executable
		$cmd = escapeshellarg( $this->get_mysqldump_command_path() );

		// We don't want to create a new DB
		$cmd .= ' --no-create-db';

		// Allow lock-tables to be overridden
		if ( ! defined( 'MYSQLDUMP_SINGLE_TRANSACTION' ) || HMBKP_MYSQLDUMP_SINGLE_TRANSACTION !== false )
			$cmd .= ' --single-transaction';

		// Make sure binary data is exported properly
		$cmd .= ' --hex-blob';

		// Username
		$cmd .= ' -u ' . escapeshellarg( DB_USER );

		// Don't pass the password if it's blank
		if ( DB_PASSWORD )
		    $cmd .= ' -p'  . escapeshellarg( DB_PASSWORD );

		// Set the host
		$cmd .= ' -h ' . escapeshellarg( $host );

		// Set the port if it was set
		if ( ! empty( $port ) && is_numeric( $port ) )
		    $cmd .= ' -P ' . $port;

		// The file we're saving too
		$cmd .= ' -r ' . escapeshellarg( $this->get_database_dump_filepath() );

		// The database we're dumping
		$cmd .= ' ' . escapeshellarg( DB_NAME );

		// Pipe STDERR to STDOUT
		$cmd .= ' 2>&1';

		// Store any returned data in an error
		$stderr = shell_exec( $cmd );

		// Skip the new password warning that is output in mysql > 5.6 (@see http://bugs.mysql.com/bug.php?id=66546)
		if ( trim( $stderr ) === 'Warning: Using a password on the command line interface can be insecure.' ) {
			$stderr = '';
		}

		if ( $stderr ) {
			$this->error( $this->get_mysqldump_method(), $stderr );
		}

		$this->verify_mysqldump();

	}

	public function mysqldump_fallback() {

		$this->errors_to_warnings( $this->get_mysqldump_method() );

		$this->mysqldump_method = 'mysqldump_fallback';

		$this->do_action( 'mysqldump_started' );

	    $this->db = @mysql_pconnect( DB_HOST, DB_USER, DB_PASSWORD );

	    if ( ! $this->db )
	    	$this->db = mysql_connect( DB_HOST, DB_USER, DB_PASSWORD );

	    if ( ! $this->db )
	    	return;

	    mysql_select_db( DB_NAME, $this->db );

	    if ( function_exists( 'mysql_set_charset') )
	    	mysql_set_charset( DB_CHARSET, $this->db );

	    // Begin new backup of MySql
	    $tables = mysql_query( 'SHOW TABLES' );

	    $sql_file  = "# WordPress : " . get_bloginfo( 'url' ) . " MySQL database backup\n";
	    $sql_file .= "#\n";
	    $sql_file .= "# Generated: " . date( 'l j. F Y H:i T' ) . "\n";
	    $sql_file .= "# Hostname: " . DB_HOST . "\n";
	    $sql_file .= "# Database: " . $this->sql_backquote( DB_NAME ) . "\n";
	    $sql_file .= "# --------------------------------------------------------\n";

	    for ( $i = 0; $i < mysql_num_rows( $tables ); $i++ ) {

	    	$curr_table = mysql_tablename( $tables, $i );

	    	// Create the SQL statements
	    	$sql_file .= "# --------------------------------------------------------\n";
	    	$sql_file .= "# Table: " . $this->sql_backquote( $curr_table ) . "\n";
	    	$sql_file .= "# --------------------------------------------------------\n";

	    	$this->make_sql( $sql_file, $curr_table );

	    }

	}

	public function archive() {

		// If using a manifest, perform the backup in chunks
		if ( 'database' !== $this->get_type()
			&& $this->is_using_file_manifest()
			&& $this->create_file_manifests() ) {
			
			$this->archive_via_file_manifest();

		} else {

			$this->archive_via_single_request();

		}

	}

	private function archive_via_file_manifest() {

		$errors = array();

		// Back up files from the file manifest in chunks
		$next_files = $this->get_next_files_from_file_manifest();
		do {

			$this->do_action( 'archive_started' );

			// `zip` is the most performant archive method
			if ( $this->get_zip_command_path() ) {
				$this->archive_method = 'zip_files';
				$error = $this->zip_files( $next_files );
			}

			// ZipArchive is also pretty fast for chunked backups
			else if ( class_exists( 'ZipArchive' ) && empty( $this->skip_zip_archive ) ) {
				$this->archive_method = 'zip_archive_files';

				$ret = $this->zip_archive_files( $next_files );
				if ( ! $ret ) {
					$this->skip_zip_archive = true;
					continue;
				}
			}

			// Last opportunity
			else {
				$this->archive_method = 'pcl_zip_files';
				$error = $this->pcl_zip_files( $next_files );
			}

			if ( ! empty( $error ) ) {
				$errors[] = $error;
				unset( $error );
			}

			// Update the file manifest with these files that were archived
			$this->file_manifest_already_archived = array_merge( $this->file_manifest_already_archived, $next_files );
			$this->delete_current_file_manifest();

			// Get the next set of files to archive
			$next_files = $this->get_next_files_from_file_manifest();

		} while( ! empty( $next_files ) );

		// If the database should be included in the backup, it's included last
		if ( 'file' !== $this->get_type() && file_exists( $this->get_database_dump_filepath() ) ) {

			switch ( $this->archive_method ) {

				case 'zip_archive_files':

					$zip = &$this->setup_ziparchive();

					$zip->addFile( $this->get_database_dump_filepath(), $this->get_database_dump_filename() );

					$zip->close();

					break;

				case 'zip_files':

					$error = shell_exec( 'cd ' . escapeshellarg( $this->get_path() ) . ' && ' . escapeshellcmd( $this->get_zip_command_path() ) . ' -uq ' . escapeshellarg( $this->get_archive_filepath() ) . ' ' . escapeshellarg( $this->get_database_dump_filename() ) . ' 2>&1' );

					break;

				case 'pcl_zip_files':

					$pclzip = &$this->setup_pclzip();

					if ( ! $pclzip->add( $this->get_database_dump_filepath(), PCLZIP_OPT_REMOVE_PATH, $this->get_path() ) )
						$this->warning( $this->get_archive_method(), $pclzip->errorInfo( true ) );
			
					break;
			}

			if ( ! empty( $error ) ) {
				$errors[] = $error;
				unset( $error );
			}
		}

		// If the methods produced any errors, log them
		if ( ! empty( $errors ) )
			$this->warning( $this->get_archive_method(), implode( ', ', $errors ) );

		// ZipArchive has some special reporting requirements
		if ( ! empty( $this->ziparchive ) ) {

			if ( $this->ziparchive->status )
				$this->warning( $this->get_archive_method(), $this->ziparchive->status );

			if ( $this->ziparchive->statusSys )
				$this->warning( $this->get_archive_method(), $this->ziparchive->statusSys );

		}

		// Verify and remove if errors
		$this->verify_archive();

		// Remove the file manifest
		if ( is_dir( $this->get_file_manifest_dirpath() ) )
			$this->rmdir_recursive( $this->get_file_manifest_dirpath() );

		// Delete the database dump file
		if ( file_exists( $this->get_database_dump_filepath() ) )
			unlink( $this->get_database_dump_filepath() );

		$this->do_action( 'archive_finished' );

	}

	private function archive_via_single_request() {

		// Do we have the path to the zip command
		if ( $this->get_zip_command_path() )
			$this->zip();

		// If not or if the shell zip failed then use ZipArchive
		if ( empty( $this->archive_verified ) && class_exists( 'ZipArchive' ) && empty( $this->skip_zip_archive ) )
			$this->zip_archive();

		// If ZipArchive is unavailable or one of the above failed
		if ( empty( $this->archive_verified ) )
			$this->pcl_zip();

		// Delete the database dump file
		if ( file_exists( $this->get_database_dump_filepath() ) )
			unlink( $this->get_database_dump_filepath() );

		$this->do_action( 'archive_finished' );

	}

	public function restart_archive() {

		if ( $this->is_using_file_manifest() ) {

			$this->archive_via_file_manifest();

		} else {

			$this->archive_via_single_request();

		}

		$this->do_action( 'backup_complete' );
	}

	public function zip() {

		$this->archive_method = 'zip';

		$this->do_action( 'archive_started' );

		// Zip up $this->root with excludes
		if ( $this->get_type() !== 'database' && $this->exclude_string( 'zip' ) ) {
		    $stderr = shell_exec( 'cd ' . escapeshellarg( $this->get_root() ) . ' && ' . escapeshellcmd( $this->get_zip_command_path() ) . ' -rq ' . escapeshellarg( $this->get_archive_filepath() ) . ' ./' . ' -x ' . $this->exclude_string( 'zip' ) . ' 2>&1' );

		// Zip up $this->root without excludes
		} elseif ( $this->get_type() !== 'database' ) {
		    $stderr = shell_exec( 'cd ' . escapeshellarg( $this->get_root() ) . ' && ' . escapeshellcmd( $this->get_zip_command_path() ) . ' -rq ' . escapeshellarg( $this->get_archive_filepath() ) . ' ./' . ' 2>&1' );

		}

		// Add the database dump to the archive
		if ( $this->get_type() !== 'file' && file_exists( $this->get_database_dump_filepath() ) )
		    $stderr = shell_exec( 'cd ' . escapeshellarg( $this->get_path() ) . ' && ' . escapeshellcmd( $this->get_zip_command_path() ) . ' -uq ' . escapeshellarg( $this->get_archive_filepath() ) . ' ' . escapeshellarg( $this->get_database_dump_filename() ) . ' 2>&1' );

		if ( ! empty( $stderr ) )
			$this->warning( $this->get_archive_method(), $stderr );

		$this->verify_archive();
	}

	private function zip_files( $files ) {

		// Not necessary to include directories when using `zip`
		foreach( $files as $key => $file ) {

			if ( ! is_dir( $file ) )
				continue;

			unset( $files[$key] );
		}

		return shell_exec( 'cd ' . escapeshellarg( $this->get_root() ) . ' && ' . escapeshellcmd( $this->get_zip_command_path() ) . ' ' . escapeshellarg( $this->get_archive_filepath() ) . ' ' . implode( ' ', $files ) . ' -q 2>&1' );
	}

	public function zip_archive() {

		$this->errors_to_warnings( $this->get_archive_method() );
		$this->archive_method = 'ziparchive';

		$this->do_action( 'archive_started' );

		if ( false === ( $zip = &$this->setup_ziparchive() ) )
			return;

		$excludes = $this->exclude_string( 'regex' );

		if ( $this->get_type() !== 'database' ) {

			$files_added = 0;

			foreach ( $this->get_files() as $file ) {

				// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
				if ( method_exists( $file, 'isDot' ) && $file->isDot() )
					continue;

				// Skip unreadable files
				if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
					continue;

			    // Excludes
			    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) )
			        continue;

			    if ( $file->isDir() )
					$zip->addEmptyDir( trailingslashit( str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) );

			    elseif ( $file->isFile() )
					$zip->addFile( $file->getPathname(), str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) );

				if ( ++$files_added % 500 === 0 )
					if ( ! $zip->close() || ! $zip->open( $this->get_archive_filepath(), ZIPARCHIVE::CREATE ) )
						return;

			}

		}

		// Add the database
		if ( $this->get_type() !== 'file' && file_exists( $this->get_database_dump_filepath() ) )
			$zip->addFile( $this->get_database_dump_filepath(), $this->get_database_dump_filename() );

		if ( $zip->status )
			$this->warning( $this->get_archive_method(), $zip->status );

		if ( $zip->statusSys )
			$this->warning( $this->get_archive_method(), $zip->statusSys );

		$zip->close();

		$this->verify_archive();

	}

	private function zip_archive_files( $files ) {

		if ( false === ( $zip = &$this->setup_ziparchive() ) )
			return false;

		foreach( $files as $file ) {

			$full_path = trailingslashit( $this->get_root() ) . $file;
			if ( is_dir( $full_path ) )
				$zip->addEmptyDir( $file );
			else
				$zip->addFile( $full_path, $file );

		}

		// Avoid limitations in ZipArchive by making sure we save each batch to disk
		$zip->close();
		return true;
	}

	public function pcl_zip() {

		$this->errors_to_warnings( $this->get_archive_method() );
		$this->archive_method = 'pclzip';

		$this->do_action( 'archive_started' );

		global $_wpalerts_hmbkp_exclude_string;

		$_wpalerts_hmbkp_exclude_string = $this->exclude_string( 'regex' );

		$archive = &$this->setup_pclzip();

		// Zip up everything
		if ( $this->get_type() !== 'database' )
			if ( ! $archive->add( $this->get_root(), PCLZIP_OPT_REMOVE_PATH, $this->get_root(), PCLZIP_CB_PRE_ADD, 'wpalerts_pclzip_callback' ) )
				$this->warning( $this->get_archive_method(), $archive->errorInfo( true ) );

		// Add the database
		if ( $this->get_type() !== 'file' && file_exists( $this->get_database_dump_filepath() ) )
			if ( ! $archive->add( $this->get_database_dump_filepath(), PCLZIP_OPT_REMOVE_PATH, $this->get_path() ) )
				$this->warning( $this->get_archive_method(), $archive->errorInfo( true ) );

		unset( $GLOBALS['_wpalerts_hmbkp_exclude_string'] );

		$this->verify_archive();

	}

	private function pcl_zip_files( $files ) {

		$this->errors_to_warnings( $this->get_archive_method() );

		$pclzip = &$this->setup_pclzip();

		foreach( $files as $file ) {

			$full_path = trailingslashit( $this->get_root() ) . $file;
			if ( is_dir( $full_path ) )
				continue;
			
			if ( ! $pclzip->add( $full_path, PCLZIP_OPT_REMOVE_PATH, $this->get_root() ) )
				$this->warning( $this->get_archive_method(), $pclzip->errorInfo( true ) );

		}

	}

	public function verify_mysqldump() {

		$this->do_action( 'mysqldump_verify_started' );

		// If we've already passed then no need to check again
		if ( ! empty( $this->mysqldump_verified ) )
			return true;

		// If there are mysqldump errors delete the database dump file as mysqldump will still have written one
		if ( $this->get_errors( $this->get_mysqldump_method() ) && file_exists( $this->get_database_dump_filepath() ) )
			unlink( $this->get_database_dump_filepath() );

		// If we have an empty file delete it
		if ( @filesize( $this->get_database_dump_filepath() ) === 0 )
			unlink( $this->get_database_dump_filepath() );

		// If the file still exists then it must be good
		if ( file_exists( $this->get_database_dump_filepath() ) )
			return $this->mysqldump_verified = true;

		return false;


	}

	public function verify_archive() {

		$this->do_action( 'archive_verify_started' );

		// If we've already passed then no need to check again
		if ( ! empty( $this->archive_verified ) )
			return true;

		// If there are errors delete the backup file.
		if ( $this->get_errors( $this->get_archive_method() ) && file_exists( $this->get_archive_filepath() ) )
			unlink( $this->get_archive_filepath() );

		// If the archive file still exists assume it's good
		if ( file_exists( $this->get_archive_filepath() ) )
			return $this->archive_verified = true;

		return false;

	}

	public function get_files() {

		if ( ! empty( $this->files ) )
			return $this->files;

		$this->files = array();

		// We only want to use the RecursiveDirectoryIterator if the FOLLOW_SYMLINKS flag is available
		if ( defined( 'RecursiveDirectoryIterator::FOLLOW_SYMLINKS' ) ) {

			$this->files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $this->get_root(), RecursiveDirectoryIterator::FOLLOW_SYMLINKS ), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD );

			// Skip dot files if the SKIP_Dots flag is available
			if ( defined( 'RecursiveDirectoryIterator::SKIP_DOTS' ) )
				$this->files->setFlags( RecursiveDirectoryIterator::SKIP_DOTS + RecursiveDirectoryIterator::FOLLOW_SYMLINKS );


		// If RecursiveDirectoryIterator::FOLLOW_SYMLINKS isn't available then fallback to a less memory efficient method
		} else {

			$this->files = $this->get_files_fallback( $this->get_root() );

		}

		return $this->files;

	}

	private function get_files_fallback( $dir, $files = array() ) {

	    $handle = opendir( $dir );

	    $excludes = $this->exclude_string( 'regex' );

	    while ( $file = readdir( $handle ) ) :

	    	// Ignore current dir and containing dir
	    	if ( $file === '.' || $file === '..' )
	    		continue;

	    	$filepath = self::conform_dir( trailingslashit( $dir ) . $file );
	    	$file = str_ireplace( trailingslashit( $this->get_root() ), '', $filepath );

	    	$files[] = new SplFileInfo( $filepath );

	    	if ( is_dir( $filepath ) )
	    		$files = $this->get_files_fallback( $filepath, $files );

		endwhile;

		return $files;

	}

	public function get_included_files() {

		if ( ! empty( $this->included_files ) )
			return $this->included_files;

		$this->included_files = array();

		$excludes = $this->exclude_string( 'regex' );

		foreach ( $this->get_files() as $file ) {

			// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			// Skip unreadable files
			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
				continue;

		    // Excludes
		    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) )
		    	continue;

		    $this->included_files[] = $file;

		}

		return $this->included_files;

	}

	public function get_included_file_count() {

		if ( ! empty( $this->included_file_count ) )
			return $this->included_file_count;

		$this->included_file_count = 0;

		$excludes = $this->exclude_string( 'regex' );

		foreach ( $this->get_files() as $file ) {

			// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			// Skip unreadable files
			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
				continue;

		    // Excludes
		    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) )
		    	continue;

		    $this->included_file_count++;

		}

		return $this->included_file_count;

	}

	public function get_excluded_files() {

		if ( ! empty( $this->excluded_files ) )
			return $this->excluded_files;

		$this->excluded_files = array();

		$excludes = $this->exclude_string( 'regex' );

		foreach ( $this->get_files() as $file ) {

			// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			// Skip unreadable files
			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
				continue;

		    // Excludes
		    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) )
		    	$this->excluded_files[] = $file;

		}

		return $this->excluded_files;

	}

	public function get_excluded_file_count() {

		if ( ! empty( $this->excluded_file_count ) )
			return $this->excluded_file_count;

		$this->excluded_file_count = 0;

		$excludes = $this->exclude_string( 'regex' );

		foreach ( $this->get_files() as $file ) {

			// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			// Skip unreadable files
			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
				continue;

		    // Excludes
		    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', self::conform_dir( $file->getPathname() ) ) ) )
		    	$this->excluded_file_count++;

		}

		return $this->excluded_file_count;

	}

	public function get_unreadable_files() {

		if ( ! empty( $this->unreadable_files ) )
			return $this->unreadable_files;

		$this->unreadable_files = array();

		foreach ( $this->get_files() as $file ) {

			// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
			  	$this->unreadable_files[] = $file;

		}

		return $this->unreadable_files;

	}

	public function get_unreadable_file_count() {

		if ( ! empty( $this->get_unreadable_file_count ) )
			return $this->get_unreadable_file_count;

		$this->get_unreadable_file_count = 0;

		foreach ( $this->get_files() as $file ) {

			// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
			if ( method_exists( $file, 'isDot' ) && $file->isDot() )
				continue;

			if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
			  	$this->get_unreadable_file_count++;

		}

		return $this->get_unreadable_file_count;

	}

	private function load_pclzip() {

		// Load PclZip
		if ( ! defined( 'PCLZIP_TEMPORARY_DIR' ) )
			define( 'PCLZIP_TEMPORARY_DIR', trailingslashit( $this->get_path() ) );

		require_once( ABSPATH . 'wp-admin/includes/class-pclzip.php' );

	}

	public function get_excludes() {

		$excludes = array();

		if ( isset( $this->excludes ) )
			$excludes = $this->excludes;

		// If path() is inside root(), exclude it
		if ( strpos( $this->get_path(), $this->get_root() ) !== false )
			array_unshift( $excludes, trailingslashit( $this->get_path() ) );

		return array_unique( $excludes );

	}

	public function set_excludes( $excludes, $append = false ) {

		if ( is_string( $excludes ) )
			$excludes = explode( ',', $excludes );

		if ( $append )
			$excludes = array_merge( $this->excludes, $excludes );

		$this->excludes = array_filter( array_unique( array_map( 'trim', $excludes ) ) );

	}

	public function exclude_string( $context = 'zip' ) {

		// Return a comma separated list by default
		$separator = ', ';
		$wildcard = '';

		// The zip command
		if ( $context === 'zip' ) {
			$wildcard = '*';
			$separator = ' -x ';

		// The PclZip fallback library
		} elseif ( $context === 'regex' ) {
			$wildcard = '([\s\S]*?)';
			$separator = '|';

		}

		$excludes = $this->get_excludes();

		foreach( $excludes as $key => &$rule ) {

			$file = $absolute = $fragment = false;

			// Files don't end with /
			if ( ! in_array( substr( $rule, -1 ), array( '\\', '/' ) ) )
				$file = true;

			// If rule starts with a / then treat as absolute path
			elseif ( in_array( substr( $rule, 0, 1 ), array( '\\', '/' ) ) )
				$absolute = true;

			// Otherwise treat as dir fragment
			else
				$fragment = true;

			// Strip $this->root and conform
			$rule = str_ireplace( $this->get_root(), '', untrailingslashit( self::conform_dir( $rule ) ) );

			// Strip the preceeding slash
			if ( in_array( substr( $rule, 0, 1 ), array( '\\', '/' ) ) )
				$rule = substr( $rule, 1 );

			// Escape string for regex
			if ( $context === 'regex' )
				$rule = str_replace( '.', '\.', $rule );

			// Convert any existing wildcards
			if ( $wildcard !== '*' && strpos( $rule, '*' ) !== false )
				$rule = str_replace( '*', $wildcard, $rule );

			// Wrap directory fragments and files in wildcards for zip
			if ( $context === 'zip' && ( $fragment || $file ) )
				$rule = $wildcard . $rule . $wildcard;

			// Add a wildcard to the end of absolute url for zips
			if ( $context === 'zip' && $absolute )
				$rule .= $wildcard;

			// Add and end carrot to files for pclzip but only if it doesn't end in a wildcard
			if ( $file && $context === 'regex' )
				$rule .= '$';

			// Add a start carrot to absolute urls for pclzip
			if ( $absolute && $context === 'regex' )
				$rule = '^' . $rule;

		}

		// Escape shell args for zip command
		if ( $context === 'zip' )
			$excludes = array_map( 'escapeshellarg', array_unique( $excludes ) );

		return implode( $separator, $excludes );

	}

	private function sql_backquote( $a_name ) {

	    if ( ! empty( $a_name ) && $a_name !== '*' ) {

	    	if ( is_array( $a_name ) ) {

	    		$result = array();

	    		reset( $a_name );

	    		while ( list( $key, $val ) = each( $a_name ) )
	    			$result[$key] = '`' . $val . '`';

	    		return $result;

	    	} else {

	    		return '`' . $a_name . '`';

	    	}

	    } else {

	    	return $a_name;

	    }

	}

	private function make_sql( $sql_file, $table ) {

	    // Add SQL statement to drop existing table
	    $sql_file .= "\n";
	    $sql_file .= "\n";
	    $sql_file .= "#\n";
	    $sql_file .= "# Delete any existing table " . $this->sql_backquote( $table ) . "\n";
	    $sql_file .= "#\n";
	    $sql_file .= "\n";
	    $sql_file .= "DROP TABLE IF EXISTS " . $this->sql_backquote( $table ) . ";\n";

	    /* Table Structure */

	    // Comment in SQL-file
	    $sql_file .= "\n";
	    $sql_file .= "\n";
	    $sql_file .= "#\n";
	    $sql_file .= "# Table structure of table " . $this->sql_backquote( $table ) . "\n";
	    $sql_file .= "#\n";
	    $sql_file .= "\n";

	    // Get table structure
	    $query = 'SHOW CREATE TABLE ' . $this->sql_backquote( $table );
	    $result = mysql_query( $query, $this->db );

	    if ( $result ) {

	    	if ( mysql_num_rows( $result ) > 0 ) {
	    		$sql_create_arr = mysql_fetch_array( $result );
	    		$sql_file .= $sql_create_arr[1];
	    	}

	    	mysql_free_result( $result );
	    	$sql_file .= ' ;';

	    }

	    /* Table Contents */

	    // Get table contents
	    $query = 'SELECT * FROM ' . $this->sql_backquote( $table );
	    $result = mysql_query( $query, $this->db );

	    if ( $result ) {
	    	$fields_cnt = mysql_num_fields( $result );
	    	$rows_cnt   = mysql_num_rows( $result );
	    }

	    // Comment in SQL-file
	    $sql_file .= "\n";
	    $sql_file .= "\n";
	    $sql_file .= "#\n";
	    $sql_file .= "# Data contents of table " . $table . " (" . $rows_cnt . " records)\n";
	    $sql_file .= "#\n";

	    // Checks whether the field is an integer or not
	    for ( $j = 0; $j < $fields_cnt; $j++ ) {

	    	$field_set[$j] = $this->sql_backquote( mysql_field_name( $result, $j ) );
	    	$type = mysql_field_type( $result, $j );

	    	if ( $type === 'tinyint' || $type === 'smallint' || $type === 'mediumint' || $type === 'int' || $type === 'bigint' )
	    		$field_num[$j] = true;

	    	else
	    		$field_num[$j] = false;

	    }

	    // Sets the scheme
	    $entries = 'INSERT INTO ' . $this->sql_backquote( $table ) . ' VALUES (';
	    $search   = array( '\x00', '\x0a', '\x0d', '\x1a' );  //\x08\\x09, not required
	    $replace  = array( '\0', '\n', '\r', '\Z' );
	    $current_row = 0;
	    $batch_write = 0;

	    while ( $row = mysql_fetch_row( $result ) ) {

	    	$current_row++;

	    	// build the statement
	    	for ( $j = 0; $j < $fields_cnt; $j++ ) {

	    		if ( ! isset($row[$j] ) ) {
	    			$values[]     = 'NULL';

	    		} elseif ( $row[$j] === '0' || $row[$j] !== '' ) {

	    		    // a number
	    		    if ( $field_num[$j] )
	    		    	$values[] = $row[$j];

	    		    else
	    		    	$values[] = "'" . str_replace( $search, $replace, $this->sql_addslashes( $row[$j] ) ) . "'";

	    		} else {
	    			$values[] = "''";

	    		}

	    	}

	    	$sql_file .= " \n" . $entries . implode( ', ', $values ) . ") ;";

	    	// write the rows in batches of 100
	    	if ( $batch_write === 100 ) {
	    		$batch_write = 0;
	    		$this->write_sql( $sql_file );
	    		$sql_file = '';
	    	}

	    	$batch_write++;

	    	unset( $values );

	    }

	    mysql_free_result( $result );

	    // Create footer/closing comment in SQL-file
	    $sql_file .= "\n";
	    $sql_file .= "#\n";
	    $sql_file .= "# End of data contents of table " . $table . "\n";
	    $sql_file .= "# --------------------------------------------------------\n";
	    $sql_file .= "\n";

		$this->write_sql( $sql_file );

	}

	/**
	 * Better addslashes for SQL queries.
	 * Taken from phpMyAdmin.
	 *
	 * @param string $a_string
	 * @param bool   $is_like
	 * @return mixed
	 */
	private function sql_addslashes( $a_string = '', $is_like = false ) {

	    if ( $is_like )
	    	$a_string = str_replace( '\\', '\\\\\\\\', $a_string );

	    else
	    	$a_string = str_replace( '\\', '\\\\', $a_string );

	    $a_string = str_replace( '\'', '\\\'', $a_string );

	    return $a_string;
	}

	/**
	 * Write the SQL file
	 * @param string $sql
	 * @return bool
	 */
	private function write_sql( $sql ) {

	    $sqlname = $this->get_database_dump_filepath();

	    // Actually write the sql file
	    if ( is_writable( $sqlname ) || ! file_exists( $sqlname ) ) {

	    	if ( ! $handle = @fopen( $sqlname, 'a' ) )
	    		return;

	    	if ( ! @fwrite( $handle, $sql ) )
	    		return;

	    	@fclose( $handle );

	    	return true;

	    }

	}

	/**
	 * Get the errors
	 *
	 * @access public
	 */
	public function get_errors( $context = null ) {

		if ( ! empty( $context ) )
			return isset( $this->errors[$context] ) ? $this->errors[$context] : array();

		return $this->errors;

	}

	public function error( $context, $error ) {

		if ( empty( $context ) || empty( $error ) )
			return;

		$this->errors[$context][$_key = md5( implode( ':' , (array) $error ) )] = $error;

		$this->do_action( 'error' );

	}

	/**
	 * Migrate errors to warnings
	 *
	 * @access private
	 * @param string $context. (default: null)
	 */
	private function errors_to_warnings( $context = null ) {

		$errors = empty( $context ) ? $this->get_errors() : array( $context => $this->get_errors( $context ) );

		if ( empty( $errors ) )
			return;

		foreach ( $errors as $error_context => $context_errors )
			foreach( $context_errors as $error )
				$this->warning( $error_context, $error );

		if ( $context )
			unset( $this->errors[$context] );

		else
			$this->errors = array();

	}

	public function get_warnings( $context = null ) {

		if ( ! empty( $context ) )
			return isset( $this->warnings[$context] ) ? $this->warnings[$context] : array();

		return $this->warnings;

	}

	private function warning( $context, $warning ) {

		if ( empty( $context ) || empty( $warning ) )
			return;

		$this->do_action( 'warning' );

		$this->warnings[$context][$_key = md5( implode( ':' , (array) $warning ) )] = $warning;

	}

	public function error_handler( $type ) {

		// Skip strict & deprecated warnings
		if ( ( defined( 'E_DEPRECATED' ) && $type === E_DEPRECATED ) || ( defined( 'E_STRICT' ) && $type === E_STRICT ) || error_reporting() === 0 )
			return false;

		$args = func_get_args();

		array_shift( $args );

		$this->warning( 'php', implode( ', ', array_splice( $args, 0, 3 ) ) );

		return false;

	}

	public static function rmdir_recursive( $dir ) {

		if ( is_file( $dir ) )
			@unlink( $dir );

	    if ( ! is_dir( $dir ) )
	    	return false;

	    $files = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir ), RecursiveIteratorIterator::CHILD_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD );

		foreach ( $files as $file ) {

			if ( $file->isDir() )
				@rmdir( $file->getPathname() );

			else
				@unlink( $file->getPathname() );

		}

		@rmdir( $dir );

	}

}

function wpalerts_pclzip_callback( $event, &$file ) {

	global $_wpalerts_hmbkp_exclude_string;

    // Don't try to add unreadable files.
    if ( ! is_readable( $file['filename'] ) || ! file_exists( $file['filename'] ) )
    	return false;

    // Match everything else past the exclude list
    elseif ( $_wpalerts_hmbkp_exclude_string && preg_match( '(' . $_wpalerts_hmbkp_exclude_string . ')', $file['stored_filename'] ) )
    	return false;

    return true;
}

function _wpalerts_get_backups_info() {

	$backup = new Backup_Base();
	return array(
		'mysqldump_path' 	=> $backup->get_mysqldump_command_path(),
		'zip_path' 		=> $backup->get_zip_command_path(),
		'estimated_size'	=> Backups::get_instance()->get_estimate_size()
	);

}

function wpalerts_ajax_calculate_backup_size() {

	if ( ! wp_verify_nonce( $_GET['_wpnonce'], 'wpalerts_calculate_backup_size' ) )
		exit;
	Backups::get_instance()->get_filesize();
	exit;
}
add_action( 'wp_ajax_nopriv_wpalerts_calculate_backup_size', 'wpalerts_ajax_calculate_backup_size' );

class Backups extends Backup_Base {

	private static $instance;
	public static function get_instance() {

		if ( empty( self::$instance ) ) {
			self::$instance = new Backups();
		}
		return self::$instance;

	}

	public function __construct() {

		parent::__construct();

		$this->set_path( $this->path() );
		$backup_excludes = $_POST['backup_excludes'];
		if ( ! empty( $backup_excludes ) )
			$this->set_excludes( apply_filters( 'wpalerts_backup_excludes', $backup_excludes ) );
		$this->filesize_transient = 'wpalerts_' . '_' . $this->get_type() . '_' . substr( md5( $this->exclude_string() ), 20 ) . '_filesize';
	}

	public function do_backup() {

		@ignore_user_abort( true );

		$this->set_status( 'Starting backup...' );

		$this->set_start_timestamp();

		$this->backup();

		if ( ! file_exists( $this->get_archive_filepath() ) ) {

			$errors = $this->get_errors();
			if ( ! empty( $errors ) )
				return new WP_Error( 'backup-failed', implode( ', ', $errors ) );
			else
				return new WP_Error( 'backup-failed', __( 'Backup file is missing.', 'wpalerts' ) );

		}

		return true;

	}

	public function get_backup() {

		global $is_apache;

		// Restore the start timestamp to global scope so HM Backup recognizes the proper archive file
		$this->restore_start_timestamp();

		if ( $status = $this->get_status() ) {

			if ( $this->is_backup_still_running() )
				return new WP_Error( 'error-status', $status );
			else
				return new WP_Error( 'backup-process-killed', __( 'Backup process failed or was killed.', 'wpalerts' ) );
		}

		$backup = $this->get_archive_filepath();

		if ( file_exists( $backup ) ) {

			// Append the secret key on apache servers
			if ( $is_apache && $this->key() ) {

				$backup = add_query_arg( 'key', $this->key(), $backup );

			    // Force the .htaccess to be rebuilt
			    if ( file_exists( $this->get_path() . '/.htaccess' ) )
			        unlink( $this->get_path() . '/.htaccess' );

			    $this->path();

			}

			$response = new stdClass;
			$response->url = str_replace( parent::conform_dir( WP_CONTENT_DIR ), WP_CONTENT_URL, $backup );
			$response->seconds_elapsed = time() - $this->start_timestamp;
			return $response;

		}

		return new WP_Error( 'backup-failed', __( 'No backup was found', 'wpalerts' ) );

	}

	public function cleanup() {

		$this->rmdir_recursive( $this->get_path() );

		delete_option( 'wpalerts_backup_path' );

	}

	public function cleanup_ziparchive_partials() {

		foreach( glob( $this->get_path() . '/*.zip.*' ) as $ziparchive_partial ) {
			unlink( $ziparchive_partial );
		}

	}

	public function get_estimate_size() {

		// Check the cache
		if ( $size = get_transient( $this->filesize_transient ) ) {

			// If we have a number, format it and return
			if ( is_numeric( $size ) )
				return size_format( $size, null, '%01u %s' );

			// Otherwise the filesize must still be calculating
			else
				return __( 'Calculating', 'wpalerts' );

		}

		// we dont know the size yet, fire off a remote request to get it for later
		// it can take some time so we have a small timeout then return "Calculating"
		global $wpalerts_noauth_nonce;
		wp_remote_get( add_query_arg( array( 'action' => 'wpalerts_calculate_backup_size', 'backup_excludes' => $this->get_excludes() ), add_query_arg( '_wpnonce', $wpalerts_noauth_nonce, admin_url( 'admin-ajax.php' ) ) ), array( 'timeout' => 0.1, 'sslverify' => false ) );

		return __( 'Calculating', 'wpalerts' );

	}

	protected function do_action( $action ) {

		$this->update_heartbeat_timestamp();

		switch ( $action ) :

			case 'backup_started':

				$this->save_backup_process_id();

			break;

	    	case 'mysqldump_started' :

	    		$this->set_status( sprintf( __( 'Dumping Database %s', 'wpalerts' ), '(<code>' . $this->get_mysqldump_method() . '</code>)' ) );

	    	break;

	    	case 'mysqldump_verify_started' :

	    		$this->set_status( sprintf( __( 'Verifying Database Dump %s', 'wpalerts' ), '(<code>' . $this->get_mysqldump_method() . '</code>)' ) );

	    	break;

			case 'archive_started' :

				if ( $this->is_using_file_manifest() )
					$status = sprintf( __( '%d files remaining to archive %s', 'wpalerts' ), $this->file_manifest_remaining, '(<code>' . $this->get_archive_method() . '</code>)' );
				else
					 $status = sprintf( __( 'Creating zip archive %s', 'wpalerts' ), '(<code>' . $this->get_archive_method() . '</code>)' );

				$this->set_status( $status );

	    	break;

	    	case 'archive_verify_started' :

	    		$this->set_status( sprintf( __( 'Verifying Zip Archive %s', 'wpalerts' ), '(<code>' . $this->get_archive_method() . '</code>)' ) );

	    	break;

	    	case 'backup_complete' :

	    		if ( file_exists( $this->get_schedule_running_path() ) )
	    			unlink( $this->get_schedule_running_path() );

				$this->clear_backup_process_id();

	    	break;

	    	case 'error' :

				if ( $this->get_errors() ) {

			    	$file = $this->get_path() . '/.backup_errors';

					if ( file_exists( $file ) )
						unlink( $file );

			    	if ( ! $handle = @fopen( $file, 'w' ) )
			    		return;

					fwrite( $handle, json_encode( $this->get_errors() ) );

			    	fclose( $handle );

			    }

			break;

			case 'warning' :

			    if ( $this->get_warnings() ) {

					$file = $this->get_path() . '/.backup_warnings';

					if ( file_exists( $file ) )
			  			unlink( $file );

					if ( ! $handle = @fopen( $file, 'w' ) )
			  	  		return;

			  		fwrite( $handle, json_encode( $this->get_warnings() ) );

					fclose( $handle );

				}

	    	break;

	    endswitch;

	}

	private function path() {

		global $is_apache;

		$path = get_option( 'wpalerts_backup_path' );

		// If the dir doesn't exist or isn't writable then use the default path instead instead
		if ( ! $path || ( is_dir( $path ) && ! is_writable( $path ) ) || ( ! is_dir( $path ) && ! is_writable( dirname( $path ) ) ) )
	    	$path = $this->path_default();

		// Create the backups directory if it doesn't exist
		if ( ! is_dir( $path ) && is_writable( dirname( $path ) ) )
			mkdir( $path, 0755 );

		// If the path has changed then cache it
		if ( get_option( 'wpalerts_backup_path' ) !== $path )
			update_option( 'wpalerts_backup_path', $path );

		// Protect against directory browsing by including a index.html file
		$index = $path . '/index.html';

		if ( ! file_exists( $index ) && is_writable( $path ) )
			file_put_contents( $index, '' );

		$htaccess = $path . '/.htaccess';

		// Protect the directory with a .htaccess file on Apache servers
		if ( $is_apache && function_exists( 'insert_with_markers' ) && ! file_exists( $htaccess ) && is_writable( $path ) ) {

			$contents[]	= '# ' . sprintf( __( 'This %s file ensures that other people cannot download your backup files.', 'wpalerts' ), '.htaccess' );
			$contents[] = '';
			$contents[] = '<IfModule mod_rewrite.c>';
			$contents[] = 'RewriteEngine On';
			$contents[] = 'RewriteCond %{QUERY_STRING} !key=' . $this->key();
			$contents[] = 'RewriteRule (.*) - [F]';
			$contents[] = '</IfModule>';
			$contents[] = '';

			insert_with_markers( $htaccess, __( 'WPAlerts Backup', 'wpalerts' ), $contents );

		}

	    return parent::conform_dir( $path );

	}

	private function path_default() {

		$dirname = 'wpalertsbackups'. substr( $this->key(), 0, 10 ) . '';
		$path = parent::conform_dir( trailingslashit( WP_CONTENT_DIR ) . $dirname );

		$upload_dir = wp_upload_dir();

		// If the backups dir can't be created in WP_CONTENT_DIR then fallback to uploads
		if ( ( ( ! is_dir( $path ) && ! is_writable( dirname( $path ) ) ) || ( is_dir( $path ) && ! is_writable( $path ) ) ) && strpos( $path, $upload_dir['basedir'] ) === false )
			$path = parent::conform_dir( trailingslashit( $upload_dir['basedir'] ) . $dirname );

		return $path;
	}

	private function key() {

		if ( ! empty( $this->key ) )
			return $this->key;

		$key = array( ABSPATH, time() );

		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT', 'SECRET_KEY' ) as $constant )
			if ( defined( $constant ) )
				$key[] = constant( $constant );

		shuffle( $key );

		$this->key = md5( serialize( $key ) );
		return $this->key;
	}

	private function get_status() {

		if ( ! file_exists( $this->get_schedule_running_path() ) )
			return '';

		$status = file_get_contents( $this->get_schedule_running_path() );

		return $status;

	}

	private function get_schedule_running_path() {
		return $this->get_path() . '/.backup-running';
	}

	private function set_status( $message ) {

		if ( ! $handle = fopen( $this->get_schedule_running_path(), 'w' ) )
			return;

		fwrite( $handle, $message );

		fclose( $handle );

	}

	private function set_start_timestamp() {
		$this->start_timestamp = current_time( 'timestamp' );
		file_put_contents( $this->get_path() . '/.start-timestamp', $this->start_timestamp );
	}

	private function restore_start_timestamp() {
		if ( $start_timestamp = file_get_contents( $this->get_path() . '/.start-timestamp' ) )
			$this->start_timestamp = (int) $start_timestamp;
	}

	private function update_heartbeat_timestamp() {
		file_put_contents( $this->get_path() . '/.heartbeat-timestamp', time() );
	}

	private function get_heartbeat_timestamp() {

		$heartbeat = $this->get_path() . '/.heartbeat-timestamp';

		if ( file_exists( $heartbeat ) )
			return (int) file_get_contents( $heartbeat );

		return false;
	}

	private function get_backup_process_id_path() {
		return $this->get_path() . '/.backup-process-id';
	}

	private function get_backup_process_id() {
		$file = $this->get_backup_process_id_path();
		if ( file_exists( $file ) )
			return (int) trim( file_get_contents( $file ) );
		else
			return false;
	}

	private function save_backup_process_id() {
		if ( ! $handle = fopen( $this->get_backup_process_id_path(), 'w' ) )
			return;
		fwrite( $handle, getmypid() );
		fclose( $handle );
	}

	private function clear_backup_process_id() {
		if ( file_exists( $this->get_backup_process_id_path() ) )
			unlink( $this->get_backup_process_id_path() );
	}

	private function is_backup_still_running( $context = 'get_backup' ) {
		if ( false === ( $process_id = $this->get_backup_process_id() ) )
			return false;
		if ( self::is_safe_mode_active() && ini_get( 'max_execution_time' ) )
			$time_to_wait = ini_get( 'max_execution_time' );
		else
			$time_to_wait = 90;
		if ( 'get_backup' == $context )
			$time_to_wait += 15;
		if ( ( time() - $this->get_heartbeat_timestamp() ) < $time_to_wait )
			return true;
		$backup_file_dirs = array( $this->get_path() );
		if ( $this->is_using_file_manifest() ) {
			$backup_file_dirs[] = $this->get_file_manifest_dirpath();
		}
		foreach ( $backup_file_dirs as $backup_file_dir ) {
			$backup_files = glob( $backup_file_dir . '/*' );
			$file_mtimes = array();
			foreach( $backup_files as $backup_file ) {
				$file_mtimes[] = filemtime( $backup_file );
		}
			if ( ! empty( $file_mtimes ) ) {
				$latest_file_mtime = max( $file_mtimes );
				if ( ( time() - $latest_file_mtime ) < $time_to_wait )
				return true;
		}
		} 

		return false;
		
	}

	public function backup_heartbeat() {

		// Restore the start timestamp to global scope so HM Backup recognizes the proper archive file
		$this->restore_start_timestamp();

		// No process means no backup in progress
		if ( ! $this->get_backup_process_id() )
			return false;

		// No file manifest directory means this wasn't a file manifest approach
		if ( ! is_dir( $this->get_file_manifest_dirpath() ) )
			return false;

		// Check whether there's supposed to be a backup in progress
		if ( $this->get_backup_process_id() && $this->is_backup_still_running( 'backup_heartbeat' ) )
			return false;

		// Uh oh, needs to be restarted
		$this->cleanup_ziparchive_partials();

		$this->save_backup_process_id();

		$this->restart_archive();

	}

	public function get_filesize() {

		$filesize = 0;

		// Only try to calculate once per hour
		set_transient( $this->filesize_transient, 'Calculating', time() + 60 * 60 );

    		// Don't include database if file only
		if ( $this->get_type() != 'file' ) {

    		global $wpdb;

    		$res = $wpdb->get_results( 'SHOW TABLE STATUS FROM `' . DB_NAME . '`', ARRAY_A );

    		foreach ( $res as $r )
    			$filesize += (float) $r['Data_length'];

    	}

    	// Don't include files if database only
   		if ( $this->get_type() != 'database' ) {

    		// Get rid of any cached filesizes
    		clearstatcache();

			$excludes = $this->exclude_string( 'regex' );

			foreach ( $this->get_files() as $file ) {

				// Skip dot files, they should only exist on versions of PHP between 5.2.11 -> 5.3
				if ( method_exists( $file, 'isDot' ) && $file->isDot() )
					continue;

				if ( ! @realpath( $file->getPathname() ) || ! $file->isReadable() )
					continue;

			    // Excludes
			    if ( $excludes && preg_match( '(' . $excludes . ')', str_ireplace( trailingslashit( $this->get_root() ), '', parent::conform_dir( $file->getPathname() ) ) ) )
			        continue;

			    $filesize += (float) $file->getSize();

			}

		}

		// Cache for a day
		set_transient( $this->filesize_transient, $filesize, time() + 60 * 60 * 24 );

	}

}

if(class_exists('WPAlerts_Plugin'))
{
    // Installation and uninstallation hooks
    register_activation_hook(__FILE__, array('WPAlerts_Plugin', 'activate'));
    register_deactivation_hook(__FILE__, array('WPAlerts_Plugin', 'deactivate'));

    // instantiate the plugin class
    $wp_alerts_plugin = new WPAlerts_Plugin();
}