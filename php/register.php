<?php
$mysqli = require __DIR__ . "/database.php";

if (empty($_POST["username"])) {
    die("Username is required");
}

if (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
    die("Email is not valid");
}

if (strlen($_POST["pwd"]) < 8) {
    die("Password must be at least 8 characters long");
}

if ($_POST["pwd"] !== $_POST["Cpwd"]) {
    die("Passwords do not match");
}

$password_hash = password_hash($_POST["pwd"], PASSWORD_DEFAULT);

$sql = "INSERT INTO user (username, email, pw_hash) VALUES (?,?,?)";
$stmt = $mysqli->stmt_init();
if (!$stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("sss", $_POST["username"], $_POST["email"], $password_hash);
if ($stmt->execute()) {
   header("Location: ../login.html");
   exit;
} else {
    if ($mysqli->errno === 1062) {
        die("Email id already exists");
    } else {
        die($mysqli->error . " " . $mysqli->errno);
    }
}