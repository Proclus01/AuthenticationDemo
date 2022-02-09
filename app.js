//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const _ = require('lodash');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');


const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

// 1. Initialize session settings
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

// 2. Add passport to manage sessions
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
	email: String,
	password: String
});

// 3. Add a plugin to hash and salt passwords and save users to DB
userSchema.plugin(passportLocalMongoose);

// 4. Make sure encryption is done before storing data on DB
const User = mongoose.model("User", userSchema);

// 5. Create strategy in place of Authenticate method
passport.use(User.createStrategy());

// 6. Serialize adds user's identification to cookie
passport.serializeUser(User.serializeUser());

// 7. Deserialize authenticates user ID from cookie
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()){
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  //Deauthenticate the user
  req.logout();

  //Redirect to home page
  res.redirect("/");
});

app.post("/register", function(req, res) {

  // Use Passport to register
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      // Authenticate
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res) {

  // Declare new user
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  // Use Passport to login
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      // Authenticate
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });}
  });

});



let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server started successfully");
});
