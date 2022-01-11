const express = require('express');
const dotenv = require('dotenv');
const config = require('./config/config');
const bCrypt = require('bcrypt');
const app = express();
const session = require('express-session');
const passport = require('passport');
const MongoStore = require('connect-mongo');
const LocalStrategy = require('passport-local').Strategy;
const cluster = require('cluster');
const numCPUs = require('os').cpus().length;
dotenv.config();

const data = require('./data/index.js');
const PORT = process.env.PORT || 3000;


//plantilla ejs
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');


//middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const auth = (req, res, next) => {
  req.isAuthenticated() ? next() : res.redirect('/login');
}

//session
app.use(session({
  store: MongoStore.create({ mongoUrl: config.mongoRemote.cnxStr }),
  secret: process.env.MONGO_SECRETO,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
      maxAge: 600000
  }
}))

let dataInfo=[{
  argumentos: process.argv[0],
  nombre: process.platform,
  version: process.version,
  memoria: process.memoryUsage().rss,
  path: process.execPath,
  process: process.pid,
  carpeta: process.cwd(),
}]

//passport
app.use(passport.initialize());
app.use(passport.session());

//signin
passport.use('local-login', new LocalStrategy((username, password, done) => {
  //validacion base de datos
  let user = data.find(user => user.username === username);
  if (user) {
    return done(null, user);
  }
  if (!isValidPassword(user, password)) {
    console.log('Invalid Password');
    return done(null, false);
    
  }
  return done(null, false, { message: 'Incorrect username.' });
}));


//signup
passport.use('local-signup', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true

}, (req, username, password, done) => {
  //validacion base de datos
  let user = data.find(user => user.username === username);
  if (user) {
    return done(null, false, { message: 'Username already taken.' });
  }
  let newUser = {
    id: data.length + 1,
    username, password: createHash(password),
  };
  data.push(newUser);
  return done(null, newUser);
  

}));

//serializacion
passport.serializeUser((user, done) => {
  done(null, user.id);
})

//deserializacion
passport.deserializeUser((id, done) => {
  //valida base de datos
  let user = data.find(user => user.id === id);
  done(null, user);
})

//implementar bcrypt
function isValidPassword(user, password) {
  return bCrypt.compareSync(password, user.password);
}

function createHash(password) {
  return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}


//rutas
app.get('/home', auth, (req, res) => {
  // res.send("Hola, " + req.user.username + " Bienvenido a la pagina de inicio");
  console.log(req.user.username);
  res.render('home', {user: req.user.username});
})

app.get('/',(req,res)=>{
  res.redirect('login');
});

app.get('/login',(req,res)=>{
    res.render('login');
});

app.get('/info', auth, (req,res)=>{
  let data=dataInfo;
  console.log(data);
  res.render('info',{
    informacion: data,
    hayInfo: data.length
  });
});

app.get('/api/randoms', auth, (req,res)=>{
  // let data=dataInfo;
  // res.json(data);
});

app.get('/signup',(req,res)=>{
    res.render('signup');
});

app.get('/logout',(req,res)=>{
    req.logout();
    res.redirect('/login');
});

app.post('/login',passport.authenticate('local-login',{
  successRedirect: '/home',
  failureRedirect: '/login'
}));

app.post('/signup',passport.authenticate('local-signup',{
  successRedirect: '/login',
  failureRedirect: '/signup'
}));

if (cluster.isMaster) {
  for (var i = 0; i < numCPUs; i++) {
    // Create a worker
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`Process ${process.pid} died`);
  });
}


app.listen(PORT, () => {
  console.log('Server on port PORT');
});