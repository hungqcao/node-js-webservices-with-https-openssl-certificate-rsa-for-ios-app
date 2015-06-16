var http = require('http'),
    express = require('express'),
    path = require('path'),
    MongoClient = require('mongodb').MongoClient,
    Server = require('mongodb').Server,
    CollectionDriver = require('./collectionDriver').CollectionDriver,
    MyTools = require('./tools'),
    crypto = require("crypto");
    
//for RSA
var fs = require('fs')
  , ursa = require('ursa')
  , privateKeyServer
  , publicKeyClient, privateKeyClient;
  
privateKeyServer = ursa.createPrivateKey(fs.readFileSync('./certs/server/g3.key.pem'));
publicKeyClient = ursa.createPublicKey(fs.readFileSync('./certs/client/client.pub'));
privateKeyClient = ursa.createPrivateKey(fs.readFileSync('./certs/client/client.key.pem'));

var app = express();
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(express.bodyParser()); // <-- add

var mongoHost = 'localHost'; //A
var mongoPort = 27017; 
var collectionDriver;
 
var mongoClient = new MongoClient(new Server(mongoHost, mongoPort)); //B
mongoClient.open(function(err, mongoClient) { //C
  if (!mongoClient) {
      console.error("Error! Exiting... Must start MongoDB first");
      process.exit(1); //D
  }
  var db = mongoClient.db("test");  //E
  collectionDriver = new CollectionDriver(db); //F
});

app.use(express.static(path.join(__dirname, 'public')));
 
app.get('/', function (req, res) {
  res.send('<html><body><h1>Hello World</h1></body></html>');
});
 
app.get('/:collection', function(req, res) { //A
   var params = req.params; //B
   
   collectionDriver.findAll(req.params.collection, function(error, objs) { //C
    	  if (error) { res.send(400, error); } //D
	      else { 
	          if (req.accepts('html')) { //E
    	          res.render('data',{objects: objs, collection: req.params.collection}); //F
              } else {
	          res.set('Content-Type','application/json'); //G
                  res.send(200, objs); //H
              }
         }
   	});
});
 
app.get('/:collection/:entity', function(req, res) { //I
   var params = req.params;
   var entity = params.entity;
   var collection = params.collection;
   if (entity) {
       collectionDriver.get(collection, entity, function(error, objs) { //J
          if (error) { res.send(400, error); }
          else { res.send(200, objs); } //K
       });
   } else {
      res.send(400, {error: 'bad url', url: req.url});
   }
});

app.post('/login', function(req, res) { //A
    var object = req.body;
    var objHeaders = req.headers;
    var collection = "items";
    var usingRSA = objHeaders["isrsa"] ? objHeaders["isrsa"].toLowerCase() == 'true' ? true : false : false;
    
    if(usingRSA){
      console.log("Username: " + object.username);
      object.username = privateKeyServer.decrypt(object.username, 'base64', 'utf8');
      console.log("Username: " + object.password);
      object.password = privateKeyServer.decrypt(object.password, 'base64', 'utf8');
    }else{
      //We dont do any thing.
    }
    
    if(object.password){
      var sha256 = crypto.createHash("sha256");
      sha256.update(object.password, "utf8");//utf8 here
      object.password = sha256.digest("base64");
    }else{
      res.send(400, "Invalid password!");
    }
    
    var data = {
      "firstName" : "",
      "lastName" : "",
      "dob" : new Date(),
      "creditCard" : "",
      "cvv" : "",
      "ssn" : "",
      "email" : "",
      "phone" : "",
      "address" : ""
    };
    var response = new Object();
    
    collectionDriver.login(collection, object, function(err,docs) {
          if (err) { res.send(400, err); } 
          else {
            if(docs){
              if(docs._id){ 
                response.status = 1;
                response.errmsg = "Success!";
                
                //We dont touch the object from DB
                MyTools.copyData(data, docs);
                
                delete data["_id"];
                delete data["username"];
                delete data["password"]; 
                
                if(usingRSA){
                  MyTools.encryptData(data, publicKeyClient, ursa.RSA_PKCS1_PADDING);
                }else{}
                             
                response.data = data;
                res.send(201, response);
              }else{
                docs.status = 0;
                docs.errmsg = "User is not found!";
                res.send(201, docs);
              }
            }else{ res.send(400, err); } 
          } //B
     });
});

app.post('/:collection', function(req, res) { //A
    var object = req.body;
    var collection = req.params.collection;
        
    var sha256 = crypto.createHash("sha256");
    sha256.update(object.password, "utf8");//utf8 here
    object.password = sha256.digest("base64");
    
    collectionDriver.save(collection, object, function(err,docs) {
          if (err) { res.send(400, err); } 
          else { res.send(201, docs); } //B
     });
});

app.put('/:collection/:entity', function(req, res) { //A
    var params = req.params;
    var entity = params.entity;
    var collection = params.collection;
    if (entity) {
       collectionDriver.update(collection, req.body, entity, function(error, objs) { //B
          if (error) { res.send(400, error); }
          else { res.send(200, objs); } //C
       });
   } else {
	   var error = { "message" : "Cannot PUT a whole collection" }
	   res.send(400, error);
   }
});

app.delete('/:collection/:entity', function(req, res) { //A
    var params = req.params;
    var entity = params.entity;
    var collection = params.collection;
    if (entity) {
       collectionDriver.delete(collection, entity, function(error, objs) { //B
          if (error) { res.send(400, error); }
          else { res.send(200, objs); } //C 200 b/c includes the original doc
       });
   } else {
       var error = { "message" : "Cannot DELETE a whole collection" }
       res.send(400, error);
   }
});
 
app.use(function (req,res) {
    res.render('404', {url:req.url});
});

http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});