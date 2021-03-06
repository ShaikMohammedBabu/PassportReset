var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var session = require('express-session');
var mongoose = require('mongoose');//for interacting with MongoDB
var nodemailer = require('nodemailer');//for sending password reset emails,
var passport = require('passport');//for user authentication
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');//for hashing user passwords
var async = require('async');// library to avoid dealing with nested callbacks by using with the help of async.waterfall method
var crypto = require('crypto');//for generating random token during a password reset.
var flash = require('express-flash');// add flash messages to notify users about success and error messages

var index = require('./routes/index');
var users = require('./routes/users');

var app = express();

mongoose.connect('mongodb://localhost/m3databse',function(err,res){
  if(err) return err;
  else return console.log("successfully connected to mongodb");
});

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(session({
  secret:'session secret key'
}));


app.use(flash());

//adding the Passport middleware to our Express configuration
app.use(passport.initialize());
app.use(passport.session());


app.use(express.static(path.join(__dirname, 'public')));

//actual code begins from here

var userSchema = new mongoose.Schema({
  username: { type:String, required:true, unique:true},
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

//hashing passwords on save
userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

//password verification when user tries to sign in,following is the mongoose instance method
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

var User = mongoose.model('User',userSchema);

passport.use(new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }, function(err, user) {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    });
  });
}));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

/* GET home page. */
app.get('/', function(req, res, next) {
  res.render('index', { title: 'Expresssdf', user : req.user });
});

app.get('/login',function(req,res){
  res.render('login',{ user : req.user});
  console.log("login reached");
});

app.get('/signup', function(req, res) {
  res.render('signup', {
    user: req.user
  });
});

app.get('/logout',function(req,res){
  req.logout();
  res.redirect('/');
});

app.get('/forgot',function(req,res){
  res.render('forgot',{
    user:req.user
  });
});

app.post('/login',function(req,res,next){
  passport.authenticate('local',function(err,user,info){
    if(err) return next(err)
      if(!user){
        return res.redirect('/login');
      }
      req.logIn(user, function(err) {
        if (err) return next(err);
        return res.redirect('/');
      });
  })(req, res, next);
});

app.post('/signup',function(req,res){
  console.log("signup method entered")
  var user = new User({
    username:req.body.username,
    email:req.body.email,
    password:req.body.password
  });
  user.save(function(err){
    req.logIn(user,function(err){
      res.redirect('/');
    });
  });
});



app.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'mohammedbabushaik@gmail.com',
          pass: 'abcde'
        }
      });
      console.log(user.email);
      var mailOptions = {
        to: user.email,
        from: 'mohammedbabushaik@gmail.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err, info) {
        console.log(err);
        console.log(info);
        req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});

//app.use('/', index);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});





module.exports = app;
