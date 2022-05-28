<?php
Class Data {
	function dangerous($param) {
		$temp = unknown_filter_func($param);
		query($user_input);
		query($_GET[]);
		return $temp;
	}
}

if (($_GET)) {
	echo $_GET;
}

$d = new Data;
$t = $d->dangerous($_GET);
query((int)$t);
?>
