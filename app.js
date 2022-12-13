//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
mongoose.set('strictQuery', true);

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
  googleId: String,
  facebookId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

app.get("/", function(req, res) {
  res.render("home");
});

// Google Strategy

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback: true,
    userProfileURL: "https://www.googleapis.com/oauth2/v2/userinfo"
  },
  function(request, accessToken, refreshToken, profile, email, cb) {
    User.findOrCreate({ googleId: email._json.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/google',passport.authenticate('google', { scope: ['email','profile']}));

app.get('/auth/google/secrets', passport.authenticate( 'google', {
   successRedirect: '/secrets',
   failureRedirect: '/login'
}));

// Facebook Strategy

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos', 'email']
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/auth/facebook',passport.authenticate('facebook', {scope: ['email','public_profile']}));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
}));

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err){
      console.log(err);
    } else {
      if(foundUsers){
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout(function(err) {
    if(err){
      console.log(err);
    }
    res.redirect('/');
  });
});

// Login Route
app.route("/login")

  .get(function(req, res) {
    res.render("login");
  })

  .post(function(req, res) {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

    req.login(user, function(err){
      if(err){
        console.log(err);
        res.redirect("/login");
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    })
  });

// Register Route
app.route("/register")

  .get(function(req, res) {
    res.render("register");
  })

  .post(function(req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user){
      if(err){
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    })
  });

// Submit route

app.route("/submit")

  .get(function(req, res){
    if(req.isAuthenticated()){
      res.render("submit");
    } else{
      res.redirect("/login");
    }
  })

  .post(function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
      if(err){
        console.log(err);
      } else {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    })
  });

app.listen("3000", function(req, res) {
  console.log("Server started on port 3000");
});
