const express = require('express');
const session = require('express-session');
const passport = require('passport');
const Auth0Strategy = require('passport-auth0');
const jwt = require('passport-jwt').Strategy;
const path = require('path');
const axios = require('axios');
const dotenv = require('dotenv');

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(
  session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

dotenv.config();

passport.use(
  new Auth0Strategy(
    {
      domain: process.env.AUTH0_DOMAIN,
      clientID: process.env.AUTH0_CLIENT_ID,
      clientSecret: process.env.AUTH0_CLIENT_SECRET,
      callbackURL: process.env.AUTH0_CALLBACK_URL,
    },
      (accessToken, refreshToken, extraParams, profile, done) => {
        console.log(accessToken)
      return done(null, {
        accessToken: accessToken,
        refreshToken: refreshToken,
        profile: profile,
      });
    }
  )
);

passport.use(
  new jwt(
    {
      jwtFromRequest: (req) => req.cookies.access_token,
      secretOrKey: process.env.AUTH0_CLIENT_SECRET,
      audience: process.env.AUTH0_API_AUDIENCE,
      issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    },
    (payload, done) => {
      done(null, {
        accessToken: payload.access_token,
        refreshToken: payload.refresh_token,
        profile: payload.profile,
      });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get('/', (req, res) => {
  res.send(`
    <html>
      <body>
        <a href="/login">Login</a>
      </body>
    </html>
  `);
});

app.get(
  '/login',
  passport.authenticate('auth0', {
    scope: 'openid profile email',
  })
);

app.get(
  '/callback',
  passport.authenticate('auth0', {
    failureRedirect: '/login',
  }),
  (req, res) => {
    res.redirect('/home');
  }
);

app.get('/home', (req, res) => {
  res.send('Welcome to LoginApp!!!');
});

// Define a route to get the user's profile information
app.get('/profile', (req, res) => {
  // If the user is not authenticated, redirect to the login page
  if (!req.user) {
    return res.redirect('/login');
  }

  // If the user is authenticated, retrieve their profile information
  const profile = req.user._json;

  // Render the profile information in a view
  res.render('profile', { profile });
});


app.listen(3000, () => {
  console.log('App is running on port 3000');
});
