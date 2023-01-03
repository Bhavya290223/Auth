//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const app = express();
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);
const encrypt = require('mongoose-encryption');

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String
});

userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

app.get('/', (req, res) => {
  res.render("Home");
});

app.get('/login', (req, res) => {
  res.render("Login");
});

app.get('/register', (req, res) => {
  res.render("Register");
});

app.post('/register', (req, res) => {
  const newUser = new User ({
    email: req.body.username,
    password: req.body.password
  });

  newUser.save((err) => {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets");
    }
  });
});

app.post('/login', (req, res) => {
  const username= req.body.username;
  const password= req.body.password;

  User.findOne({email: username}, (err, result) => {
    if (err) {
      console.log(err);
    } else {
      if (result) {
        if (result.password === password) {
          res.render('secrets');
        }
      }
    }
  });
});

app.listen (3000, function() {
  console.log("Server is on 3000");
});
