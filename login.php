<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (isset($_POST['email']) && isset($_POST['password'])) {
    // Get the login (either email or username) and password from the form
    $login = $_POST['email'];
    $password = $_POST['password'];

    // Replace the following credentials with your own
    $servername = 'localhost';
    $username = 'id21111131_root';
    $password_db = 'ZestraRoot#2004';
    $dbname = 'id21111131_zestradb';

    // Create a database connection
    $db_connection = new mysqli($servername, $username, $password_db, $dbname);

    // Check the connection
    if ($db_connection->connect_error) {
      die('Connection error: ' . $db_connection->connect_error);
    }

    // Sanitize the inputs to prevent SQL injection using prepared statements
    $stmt = $db_connection->prepare("SELECT * FROM users WHERE email = ? OR username = ? LIMIT 1");
    $stmt->bind_param("ss", $login, $login);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
      $user = $result->fetch_assoc();
      $hashed_password = $user['password'];

      // Verify the password using password_verify function
      if (password_verify($password, $hashed_password)) {
        // Password is correct
        $response = array('success' => true);
        echo json_encode($response);
      } else {
        // Incorrect password
        $response = array('success' => false, 'message' => 'Incorrect email or password.');
        echo json_encode($response);
      }
    } else {
      // User not found
      $response = array('success' => false, 'message' => 'User not found.');
      echo json_encode($response);
    }

    // Close the database connection
    $stmt->close();
    $db_connection->close();
  } else {
    // Invalid request
    $response = array('success' => false, 'message' => 'Invalid request.');
    echo json_encode($response);
  }
}
?>
