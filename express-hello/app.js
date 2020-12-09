const  express = require('express');
const app = express();
let session = require('express-session');
let passport = require('passport');
let ObjectId = require('mongodb').ObjectID;
require('dotenv').config();
const mongoose= require('mongoose'); 
let mongo = require('mongodb').MongoClient;
let LocalStrategy = require('passport-local');
let bodyParser = require('body-parser');
const { response } = require('express');
let bcrypt = require('bcrypt');


app.set('view engine', 'ejs');
app.use(session({
    secret: 'qght',
    resave: true,
    saveUninitialized: true
}),passport.initialize(), passport.session())

let uri=process.env.ATLAS_URI;


mongo.connect(uri, (error, client)=>{
      if(error){
      console.log(error)
      }else{
          let db= client.db('Mydb');
        app.listen(3000);
        app.get('/', (req,res)=>{
            res.render('index',{data:{msg: 'Please Sign up'}});
        });
        
        
        passport.serializeUser((user,done)=>{
               done(null,user._id);
        })
        passport.deserializeUser((userId, done)=>{
             db.collection('users').findOne(
                 { _id: new ObjectId(userId)},
             (error,doc)=>{
                done(null, doc);
             })
        })
         let findUser = new LocalStrategy(
           (username, password, done) => {
               db.collection('users').findOne(
                   {username: username},
                   (error, user)=>{
                       if(error){
                           return done(error)
                       }else if(!user){
                           return done(null, false)
                       }else if(!bcrypt.compareSync(password, user.password)){
                           return done(null, false)
                       }else{
                           done(null, user)
                       }
                   }
                   )
           }
         )
         passport.use(findUser);
            app.get('/login',passport.authenticate('local', {failureRedirect: '/'}),
                 (request, response)=>{
                     console.log(request.user);
                     response.render('profile', {name: request.user.name})
                 }
              )
                let isSignedIn = (req,res,next)=>{
               if(req.isAuthenticated()){
                      next()
               }else{
                     res.redirect('/');
               }
                }
               app.get('/profile',isSignedIn,(req,res)=>{
                    res.render('profile',{name: req.user.name})
               })
                 app.get('/logout',(req,res)=>{
                      req.logOut()
                      res.redirect('/')
                 })
              
               app.post('/register',bodyParser.urlencoded({extended: false}),
               (req, res, next)=>{
                   db.collection('users').findOne({username: req.body.username},(error,user)=>{
                       if(!error && user){
                           res.redirect('/')
                       }
                   })
                   let hash = bcrypt.hashSync(req.body.password, 12);
                   db.collection('users').insertOne({
                       username: req.body.username,
                       password: hash,
                       name: req.body.name
                   },
                   (error, createdUser)=>{
                       if(!error && createdUser){
                           next()
                       }
                   }
                   )
               },
               passport.authenticate('local', {failureRedirect: '/'}),
                 (req,res)=>{
                     res.redirect('/profile')                     
                 }
               )
               app.use((req,res)=>{
                res.status(404).type('text').send('Error 404 Page Not found')
               })
      }
})
