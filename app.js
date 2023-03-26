require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const googleAuth = require("passport-google-oauth20");
const GoogleStrategy = googleAuth.Strategy;
const faceboookAuth = require("passport-facebook");
const FacebookStrategy = faceboookAuth.Strategy;

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

app.enable('trust proxy');

mongoose.connect(process.env.URL);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [String]
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});



passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
},
    async function (accessToken, refreshToken, profile, done) {
        try {
            console.log(profile);
            // Find or create user in your database
            let user = await User.findOne({ googleId: profile.id });
            if (user === null) {
                // Create new user in database
                const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
                const newUser = new User({
                    googleId: profile.id
                });
                user = await newUser.save();
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL
},
    async function (accessToken, refreshToken, profile, done) {
        try {
            // Find or create user in your database
            let user = await User.findOne({ facebookId: profile.id });
            console.log(user);
            if (user === null) {
                // Create new user in database
                const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
                const newUser = new User({
                    facebookId: profile.id
                });
                user = await newUser.save();
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/secrets");
    }
);

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        res.redirect('/secrets');
    });

app.get("/register", (req, res) => {
    res.render("register", { ejsError: "" });
});

app.get("/login", (req, res) => {
    res.render("login", { ejsError: "" });
});

app.get("/secrets", async (req, res) => {
    const users = await User.find({ secrets: { $exists: true, $ne: [] } })
    res.render("secrets", { ejsUsers: users });
});

app.get("/submit", (req, res) => {
    console.log(req.isAuthenticated());
    if (req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.render("login", { ejsError: "Authentication failed" });
    }
});

app.post("/register", (req, res) => {

    User.register({ username: req.body.username }, req.body.password, async (err, user) => {
        if (err !== null) {
            console.log(err);
            res.render("register", { ejsError: "Email already registered" });
        } else {
            await passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});


app.post("/login", (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, async function (err) {
        if (err !== undefined) {
            console.log(err);
            res.render("login", { ejsError: "Authentication failed" });
        } else {
            await passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/submit", async (req, res) => {
    console.log(req.user);
    const foundUser = await User.findById(req.user.id);
    console.log(foundUser);
    if (foundUser !== null) {
        foundUser.secrets.push(req.body.secret);
        await foundUser.save();
        res.redirect("/secrets");
    }
});


app.get("/logout", function (req, res) {
    req.logout((err) => {
        res.redirect("/");
    })
});


app.listen(process.env.PORT || 3000, () => {
    console.log("Server running on port 3000.")
});
