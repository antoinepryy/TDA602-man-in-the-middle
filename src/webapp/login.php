<?php
if ($_POST["email"] == "client" && $_POST["passwd"] == "azerty") {
    echo "You're connected !";
} else {
    echo "Wrong credentials !";
}
?>