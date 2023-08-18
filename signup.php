<?php
// Connect to the database (Replace 'id21111131_zestradb', 'id21111131_root', 'ZestraRoot#2004', and 'localhost')
$servername = 'localhost';
$username = 'id21111131_root';
$password = 'ZestraRoot#2004';
$dbname = 'id21111131_zestradb';

$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $dob = date('d/m/Y', strtotime(filter_input(INPUT_POST, 'dob', FILTER_SANITIZE_STRING)));
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    // Hash the password before storing it in the database
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Check if the email or username already exists in the database
    $checkUserQuery = "SELECT * FROM users WHERE email = ? OR username = ?";
    $stmt = $conn->prepare($checkUserQuery);
    $stmt->bind_param("ss", $email, $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // User with the same email or username already exists
        header('Location: signup.html?error=user_exists');
        exit;
    } else {
        // Insert the new user data into the database
        $insertUserQuery = "INSERT INTO users (email, username, dob, password) VALUES (?, ?, ?, ?)";
        $stmt = $conn->prepare($insertUserQuery);
        $stmt->bind_param("ssss", $email, $username, $dob, $hashedPassword);
        if ($stmt->execute()) {
            // Successful signup, redirect to login page
            header('Location: index.html?signup=success');
            exit;
        } else {
            // Error occurred while inserting data
            header('Location: signup.html?error=database_error');
            exit;
        }
    }
}

// Close the connection
$conn->close();
?>
