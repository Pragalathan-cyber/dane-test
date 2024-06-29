const express = require('express');
const cors = require('cors');
const userRoute = require('./routes/userRoutes');
const mongoose = require('mongoose');
const { PORT, mongoDBURL } = require('./config');
const User = require('./models/User');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const jwtBlacklist = new Set();
const MongoStore = require('connect-mongo');
const crypto = require('crypto');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const passport = require('passport');
const nodemailer = require('nodemailer');
const path = require('path')

mongoose.set('strictQuery', true);

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(
  cors({
    origin: 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);


passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) {
          return done(null, false, { message: 'Incorrect email.' });
        }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
          return done(null, false, { message: 'Incorrect password.' });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));


passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });

  const sessionSecret = crypto.randomBytes(32).toString('hex');

  app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' },
    store: MongoStore.create({ mongoUrl: mongoDBURL })
  }));
  
  app.use(passport.initialize());
  app.use(passport.session());
  
  app.get('/', (req, res) => {
    res.send('Hello world');
  });

  // Generate a secure random key
  //const secretKey = crypto.randomBytes(32).toString('hex');
 const secretKey = 'ecda1cd47fd1c30ae4cb4fd56042ffac4ba5708acd7f80a20b76bce843e6d8a7';

 app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1y' });
    res.json({ token });
  } catch (error) {
    console.error('Login failed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


  app.post('/signup', async (req, res) => {
    const { email, username, password } = req.body;
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists, try different email" });
      }
  
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ email, username,password: hashedPassword });
  
      await user.save();
      res.json({ message: 'Signup successful' });
    } catch (err) {
      console.error('Signup error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  });


  app.get('/login-failure', (req, res) => {
    res.status(401).json({ message: 'Login failed' });
  });
  
  // POST request to initiate password reset
  app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    try {
      // Find user by email
      const user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Generate reset token using the schema method
      user.generateResetPasswordToken();
      await user.save();
  
      // Send email with reset link
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
         user: 'pragaa3633533@gmail.com',
         pass: 'xzkn jqzz tuep vrsj'
        }
      });
  
      const mailOptions = {
        from: 'pragaa3633533@gmail.com',
        to: user.email,
        subject: 'Password Reset Request',
        text: `You are receiving this email because you (or someone else) have requested to reset the password for your account.\n\n`
          + `Please click on the following link, or paste this into your browser to complete the process:\n\n`
          + `http://localhost:5173/reset-password/${user.resetPasswordToken}\n\n`
          + `If you did not request this, please ignore this email and your password will remain unchanged.\n`
      };
  
      await transporter.sendMail(mailOptions);
      res.json({ message: 'Password reset email sent' });
  
    } catch (err) {
      console.error('Forgot password error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
  
    try {
      // Find the user by reset token
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }
      });
  
      if (!user) {
        return res.status(400).json({ message: 'Token is invalid or has expired.' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      // Update user's password and clear reset fields
      user.password = hashedPassword;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();
  
      res.json({ message: 'Password reset successful.' });
  
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server Error' });
    }
  });
  
  
  
  app.post('/logout', (req, res) => {
    // Invalidate the JWT token by removing it from the blacklist
    const token = req.headers['authorization']?.split(' ')[1];
    jwtBlacklist.add(token);
  
    res.status(200).json({ message: 'Logout successful' });
  });

  app.delete('/users', async (req, res) => {
    try {
      // Delete all users
      await User.deleteMany({});
      res.status(200).json({ message: 'All users deleted successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.use('/posts', userRoute);

  mongoose
  .connect(mongoDBURL)
  .then(() => {
    console.log('Database connected');
    app.listen(PORT, () => {
      console.log(`Server is running on PORT: ${PORT}`);
    });
  })
  .catch((err) => {
    console.log(err);
  });