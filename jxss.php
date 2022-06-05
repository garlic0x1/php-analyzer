<?php
/**
 * june-xss
 *
 * @package       JUNEXSS
 * @author        Jon Doe
 * @version       1.0.0
 *
 * @wordpress-plugin
 * Plugin Name:   june-xss
 * Plugin URI:    https://github.com/garlic0x1/june-xss
 * Description:   A reflected XSS CTF
 * Version:       1.0.0
 * Author:        Jon Doe
 * Author URI:    https://your-author-domain.com
 * Text Domain:   june-xss
 * Domain Path:   /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	$jxss_here = $_SERVER['QUERY_STRING'];
	$article_name = $_GET['article'];
	if (strpos($jxss_here, "debugging=verbose") !== false) {
		die($article_name);
	} else {
		exit;
	}
}

add_action( 'init', 'register_shortcodes');
register_shortcodes();

function register_shortcodes() {
   add_shortcode('jxss-articles', 'jxss_articles_div');
}

function jxss_articles_div() {

	echo "<div>";

	// if no article specified, show the list of articles
	if (!isset($_GET['article'])) {
		$articles = scandir("wp-content/");
		$i = 0;
		foreach ($articles as $article) {
			if (str_ends_with($article, ".html")) {
				echo "<a href=" . $_SERVER['REQUEST_URI'] . "?article=wp-content/" . $article . ">" . $article . "</a><br>";
			}
		}
	} else {
		// otherwise display article

		$filename = get_filename($content_dir);

		if (file_exists($filename)) {
			$sanitized_name = preg_replace('/(\.\.)/', '', $filename);
			$file = fopen( $sanitized_name, "r" );
			if( $file == false ) {
		      		echo ( "Error in opening file" );
		     		exit();
			}
			$filesize = filesize( $sanitized_name );
			$filetext = fread( $file, $filesize );
			fclose( $file );
			
			echo $filetext;
		} else {
			echo "The article you are looking for does not exist :(";
		}
	}
	echo "</div>";
}

function get_filename($dir) {
	$filename = $dir . $_GET['article'];
	return $filename;
}

