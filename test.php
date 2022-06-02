<?php
Class Data {
	function dangerous($param) {
		$temp = unknown_filter_func($param);
		// this does not alert because the variable is not in scope
		print($user_input);
		return $temp;
	}
}

$user_input = $_GET['input'];
$improperly_filtered = "$user_input";
$d = new Data;
$t = $d->dangerous($_GET);

// this does not alert because the input was sanitized
query($improperly_filtered);

// this does alert because magic quotes dont stop xss
echo $improperly_filtered;

// alerts because taint follows through method call into $t
query($t);
?>
