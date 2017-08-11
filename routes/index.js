var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Expresssdf', user : req.user });
});

router.get('/login',function(req,res){
  res.render('login',{ user : req.user});
});

router.get('/signup', function(req, res) {
  res.render('signup', {
    user: req.user
  });
});

router.get('/logout',function(req,res){
  req.logout();
  res.redirect('/');
});

router.post('/login',function(req,res,next){
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

router.post('/signup',function(req,res){
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
module.exports = router;
