const passport = require('passport');
const FacebookStrategy = require('passport-facebook');
const GoogleStrategy = require('passport-google-oauth20');
const User = require('../models/user-model');
const LocalStrategy = require('passport-local');
const bcrypt = require('bcrypt');

passport.serializeUser((user, done) => {
  console.log('Serialize...');
  done(null, user._id); // 將mongoDB的id，存在session
  // 並且將id簽名後，以Cookie的形式給使用者。。。
});

passport.deserializeUser(async (_id, done) => {
  console.log('Deserialize...');
  let foundUser = await User.findOne({ _id });
  done(null, foundUser); // 將req.user這個屬性設定為foundUser
});

// passport for Facebook
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: 'http://localhost:8080/auth/facebook/redirect',
    },
    async (accessToken, refreshToken, profile, done) => {
      let foundUser = await User.findOne({ facebookID: profile.id }).exec();
      if (foundUser) {
        console.log('使用者已經註冊過了');
        done(null, foundUser);
      } else {
        console.log('偵測到新用戶');
        let newUser = new User({
          name: profile.displayName,
          facebookID: profile.id,
        });
        let savedUser = await newUser.save();
        console.log('成功創建新用戶');
        done(null, savedUser);
      }
    }
  )
);

// passport for Google
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:8080/auth/google/redirect',
    },
    async (accessToken, refreshToken, profile, done) => {
      let foundUser = await User.findOne({ googleID: profile.id }).exec();
      if (foundUser) {
        console.log('使用者已經註冊過了');
        done(null, foundUser);
      } else {
        console.log('偵測到新用戶');
        let newUser = new User({
          name: profile.displayName,
          googleID: profile.id,
          thumbnail: profile.photos[0].value,
          email: profile.emails[0].value,
        });
        let savedUser = await newUser.save();
        console.log('成功創建新用戶');
        done(null, savedUser);
      }
    }
  )
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    let foundUser = await User.findOne({ email: username });
    if (foundUser) {
      let result = await bcrypt.compare(password, foundUser.password);
      if (result) {
        done(null, foundUser);
      } else {
        done(null, false);
      }
    } else {
      done(null, false);
    }
  })
);
