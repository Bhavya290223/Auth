//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const app = express();
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);
const session = require('express-session');
const passport = require('passport');
const plm = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const salt = 10;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({extended: true}));

app.use(session({
  secret: "little secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1/userDB");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  secret: String,
  googleId: String
});

userSchema.plugin(plm);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', (req, res) => {
  res.render("Home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

app.get('/login', (req, res) => {
  res.render("Login");
});

app.get('/register', (req, res) => {
  res.render("Register");
});

app.get('/secrets', (req, res) => {
  User.find({"secret": {$ne: null}}, function(err, result) {
    if (err) {
      console.log(err);
    } else {
      if (result) {
        res.render('secrets', {usersWithSecret: result});
      }
    }
  });

});

app.get('/logout', (req, res) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect("/login");
  }
});

app.post('/submit', (req, res) => {
  const subSecret = req.body.secret
  User.findById(req.user.id, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      if (result) {
        result.secret = subSecret;
        result.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post('/register', (req, res) => {
  User.register({username: req.body.username}, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect('/register');
    } else {
      passport.authenticate('local') (req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local') (req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen (3000, function() {
  console.log("Server is on 3000");
});
