const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

// Create local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  // Verify this email and password,
  User.findOne({ email: email }, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }

    // compare `password` to user.password and see if they match
    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err); }
      // if email and password do not match, call 'done' with false
      if (!isMatch) { return done(null, false); }
      // if the email and password are correct, call 'done' with the user
      return done(null, user);
    });
  });
});

// Setup options for JWT Strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  // See if the user ID in payload exists in our database
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); }
  // If it does, call 'done' with that user
    if (user) {
      done(null, user);
  // otherwise, call 'done' without a user object
    } else {
      done(null, false);
    }
  });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);