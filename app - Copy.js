//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const saltRounds = 12; //Requirements as per 2023

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
mongoose.set('strictQuery', true);

mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = new mongoose.model("User", userSchema);

app.get("/", function(req, res) {
  res.render("home");
});

// Login Route
app.route("/login")

  .get(function(req, res) {
    res.render("login");
  })

  .post(function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, function(err, foundUser) {
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
          bcrypt.compare(password, foundUser.password, function(err, result) {
            if (result === true) {
              res.render("secrets");
            } else {
              res.send("Incorrect Password");
            }
          })
        } else {
          res.send("User not found");
        }
      }
    })
  });

// Register Route
app.route("/register")

  .get(function(req, res) {
    res.render("register");
  })

  .post(function(req, res) {

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


app.listen("3000", function(req, res) {
  console.log("Server started on port 3000");
});
