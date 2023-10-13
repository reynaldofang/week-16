const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");

// Define routes for user registration and login
router.post("/register", userController.createUser);
router.post("/login", userController.loginUser);

module.exports = router;
