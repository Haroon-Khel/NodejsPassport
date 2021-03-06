const express = require('express');
const indexRouter = require('./routes/index');
const userIndex = require('./routes/users');
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');


const app = express();
const PORT = process.env.PORT || 5000;

// import passport config
require('./config/passport')(passport);

// DB config
const db = require('./config/keys').MongoURI;

// Connect to mongo
mongoose.connect(db, {useNewUrlParser: true}).then(() => {
    console.log('MongoDB connected');
})
.catch(err => {
    console.log(err);
});

// EJS
app.use(expressLayouts);
app.set('view engine', 'ejs');

// Bodyparser
app.use(express.urlencoded({extended: false}));

// Express Session middleware
app.use(session({
    secret: 'secret',
    resave: 'true',
    saveUninitialized: true
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash
app.use(flash());

// Global vars
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});

// Routes
app.use('/', indexRouter);
app.use('/users', userIndex);

app.listen(PORT, () => {
    console.log(`Listening in port ${PORT}`);
});