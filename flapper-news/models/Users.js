var mongoose = require('mongoose');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');

mongoose.set('useCreateIndex', true); //https://github.com/Automattic/mongoose/issues/6890#issuecomment-416420234

var UserSchema = new mongoose.Schema({
  username: {type: String, lowercase: true, unique: true},
  hash: String,
  salt: String
});

UserSchema.methods.setPassword = function(password){
  this.salt = crypto.randomBytes(16).toString('hex');
  /* The pbkdf2Sync() function takes four parameters: password, salt, iterations, and key length.
   We'll need to make sure the iterations and key length in our setPassword()
    method match the ones in our validPassword() method */
  this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, 'sha512').toString('hex');
};

UserSchema.methods.validPassword = function(password) {
  var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, 'sha512').toString('hex');

  return this.hash === hash;
};

UserSchema.methods.generateJWT = function() {

  // set expiration to 60 days
  var today = new Date();
  var exp = new Date(today);
  exp.setDate(today.getDate() + 60);

  return jwt.sign({
    _id: this._id,
    username: this.username,
    exp: parseInt(exp.getTime() / 1000),
  }, 'Secrettobechangedasenvironementvariable');
};

mongoose.model('User', UserSchema);