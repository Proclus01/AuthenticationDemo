//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const _ = require('lodash');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
	email: String,
	password: String
});

// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });

// Make sure encryption is done before storing data on DB
const User = mongoose.model("User", userSchema);

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.post("/register", function(req, res) {

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {

    const newUser = new User({
      email: req.body.username,
      password: hash
    });

    newUser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });

  });

});

app.post("/login", function(req, res) {

  const username = req.body.username;
  const password = req.body.password;

    User.findOne({email: username}, function (err, foundUser) {

      if (err) {
        res.send("No user found");
      } else {

        if (foundUser) {

          bcrypt.compare(password, foundUser.password, function(error, result) {

            if (result === true) {
              res.render("secrets");
            } else {
              res.send("wrong password");
            }

          });

        }

      }

    });

});



let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started successfully");
});
