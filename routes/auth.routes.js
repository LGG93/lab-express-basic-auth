const router = require("express").Router();
const bcrypt = require('bcrypt');
const saltRounds = 10;
const User = require('../models/User.model');
const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard.js');


//Get the Sign Up Page
router.get("/signup", isLoggedOut, (req, res) => {
    res.render("auth/signup");
  });

  router.post("/signup",isLoggedOut, (req, res) => {
    const { username, password } = req.body;
   
    bcrypt
      .genSalt(saltRounds)
      .then(salt => bcrypt.hash(password, salt))
      .then(hashedPassword => {
        return User.create({
          username,
          passwordHash: hashedPassword
        });
      })
      .then(userFromDB => {
         console.log('Newly created user is: ', userFromDB);
        req.session.currentUser = userFromDB; //Here we create .currentUser
        res.redirect('/private/auth/profile');
      })
      .catch(error => console.log(error)); 
  })

//Get Profile Page
router.get("/profile",isLoggedIn, (req, res) => {
    console.log('profile page', req.session);
    const { username } = req.session.currentUser;
      res.render("auth/profile");
  });
  
  router.get("/login",isLoggedOut, (req, res) => {
     console.log('req session', req.session);
     res.render("auth/login");
  });
  
  router.post("/login",isLoggedOut, (req, res) => {
    const { username, password } = req.body;
    console.log("req sessiooon", req.session)

   // Check for empty fields
    if (username === '' || password === '') {
      res.render('auth/login', {
        errorMessage: 'Please username and password to login.'
      });
      return;
    }

    User.findOne({ username })
    .then(user => {
      if (!user) {
        // 3. send an error message to the user if any of above is not valid,
        res.render('auth/login', { errorMessage: 'Username is not registered.' });
        return;
        // 2. if the password provided by the user is valid,
      } else if (bcrypt.compareSync(password, user.passwordHash)) {
        // 4. if both are correct, let the user in the app.
        req.session.currentUser = user;
        res.render('auth/profile', user);
      } else {
        // 3. send an error message to the user if any of above is not valid,
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(err => console.log(err))
});

router.post('/logout',isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/private/auth/login');
  });
});

module.exports = router;