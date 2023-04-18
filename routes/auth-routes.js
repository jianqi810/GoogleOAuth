const router = require('express').Router();
const passport = require('passport');
const User = require('../models/user-model');
const bcrypt = require('bcrypt');

router.get('/login', (req, res) => {
  return res.render('login', { user: req.user });
});

router.post(
  '/login',
  passport.authenticate('local', {
    failureRedirect: '/auth/login',
    failureFlash: '登入失敗，帳號或密碼不正確',
  }),
  (req, res) => {
    return res.redirect('/profile');
  }
);

router.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.send(err);
    return res.redirect('/');
  });
});

router.get('/signup', (req, res) => {
  return res.render('signup', { user: req.user });
});
router.post('/signup', async (req, res) => {
  let { name, email, password } = req.body;
  if (password.length < 8) {
    req.flash('error_msg', '密碼長度過短，至少需要8個數字或英文字。');
    res.redirect('/auth/signup');
  }

  // 確認信箱是否註冊過
  const foundEmail = await User.findOne({ email }).exec();
  if (foundEmail) {
    req.flash(
      'error_msg',
      '信箱已經被註冊，請使用另一個信箱，或嘗試使用此信箱登入系統'
    );
    return res.redirect('/auth/signup');
  }
  let hashedPassword = await bcrypt.hash(password, 12);
  let newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();
  req.flash('success_msg', '恭喜註冊成功!現在可以登入系統');
  return res.redirect('/auth/login');
});

// router for Facebook
router.get('/facebook', passport.authenticate('facebook'));

router.get(
  '/facebook/redirect',
  passport.authenticate('facebook'),
  (req, res) => {
    return res.redirect('/profile');
  }
);

// router for Google
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account',
  })
);

router.get('/google/redirect', passport.authenticate('google'), (req, res) => {
  return res.redirect('/profile');
});

module.exports = router;
