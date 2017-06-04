<?php

function validate_id($id) {
	return preg_replace('/[^A-Za-z0-9-.]/','',$id);
}
function get_data($id) {
	$id = validate_id($id);
	if (!has_data($id)) {
		error(404, "Not found");
	}
	return json_decode(file_get_contents("./data/$id.json"));
}
function store_data($id, $data) {
	file_put_contents("./data/$id.json", json_encode($data));
}
function has_data($id) {
	return file_exists("./data/$id.json");
}

function error($code, $msg) {
	header("Content-type: text/plain");
	http_response_code($code);
	exit("$msg\n");
}
if (!isset($_GET["mode"])) {
$_GET["mode"]="paste"; $_GET["id"] = "index";
}
if ($_GET["mode"] == "new") {
	if (has_data($_GET["id"])) {
		error(409, "Already exists");
	}
	header("Content-Type: text/plain");
	for($i=0;$i<8;$i++) echo chr(rand(32,126));

} elseif ($_GET["mode"] == "txt") {
	$data = get_data($_GET['id']);
	header("Content-Type: text/plain");
	echo $data['server_key']."\n".chunk_split($data['content'], 65, "\n");

} elseif ($_GET["mode"] == "paste" && $_SERVER["REQUEST_METHOD"] == "GET") {
	$data = get_data($_GET['id']);
	$cookie = isset($_COOKIE['pasteauth']) ? $_COOKIE['pasteauth'] : FALSE;
	$public = substr($_GET["id"], 0, 1) == 'p';

	$template = file_get_contents('paste.html');
	$template = str_replace('{{encrypted}}', $public ? "" : "encrypted", $template);
	$template = str_replace('{{content}}', $data->content, $template);
	$template = str_replace('{{serverkey}}', json_encode($data->serverkey), $template);
	$template = str_replace('{{editable}}', (($cookie && $data->cookie && $cookie === $data->cookie) || $_GET["id"] == 'index') ? '1' : '', $template);
	header("Content-Type: text/html; charset=utf8");
	if (!$public) header("X-Robots-Tag: noindex");
	echo $template;

} elseif ($_GET["mode"] == "paste" && $_SERVER["REQUEST_METHOD"] == "PUT") {
	$id = validate_id($_GET['id']);
	$cookie = isset($_COOKIE['pasteauth']) ? $_COOKIE['pasteauth'] : FALSE;
	$sauth = isset($_SERVER["HTTP_X_SERVER_AUTH"]) ? $_SERVER["HTTP_X_SERVER_AUTH"] : FALSE;
	$public = substr($id, 0, 2) == 'p.';
	if ($sauth) {
		if ($sauth !== trim(file_get_contents('serverauth'))) {
			error(403, "Invalid auth");
		}
	} elseif (strlen($id) < 8 || strlen($id) > 12 || preg_match('/[^A-Za-z0-9_-]/', $id) !== 0) {
		error(400, "Invalid path $id");
	}
	if (!$sauth && has_data($id)) {
		$data = get_data($id);
		if (!$data->cookie || $data->cookie !== $cookie) {
			error(403, "Invalid cookie");
		}
	}
	$content = file_get_contents('php://input');
	$content = preg_replace('/[\\r\\n]/', '', $content);
	if (preg_match('/[^A-Za-z0-9\/+=]/', $content) !== 0) {
		error(400, "Content contains non-base64");
	}
	if (strlen($content) > 640*1024) {
		error(413, "Content too large");
	}
	$serverkey = isset($_SERVER["HTTP_X_SERVER_KEY"]) ? $_SERVER["HTTP_X_SERVER_KEY"] : "";
	store_data($id, [
		"cookie" => $cookie,
		"timestamp" => time(),
		"serverkey" => $serverkey,
		"content" => $content
	]);
	header("Content-type: text/plain");
	echo "Saved ".strlen($content)." bytes.\n";
} else {
	error(404, "Not found");
}

