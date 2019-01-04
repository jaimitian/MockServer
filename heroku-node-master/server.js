var fs = require('fs');
var express = require('express');
var app = express();
var jwt    = require('jsonwebtoken');
var http = require('http');
// var https = require('https');
var bodyParser = require("body-parser");

// var privateKey  = fs.readFileSync('certs/GopiCA.key');
// var certificate = fs.readFileSync('certs/GopiCA.pem');

// var privateKey  = fs.readFileSync('certs/server.key');
// var certificate = fs.readFileSync('certs/server.crt');

// var credentials = {key: privateKey, cert: certificate};
// set the port of our application
// process.env.PORT lets the port be set by Heroku
var port = process.env.PORT || 8080;
var httpsPort = process.env.PORT || 8443;;
var secret = "BrickbyBrick";
var user = {
    first_name: 'Designer',
    last_name: 'MicroApps',
    password : 'designer@123'
};

const  ProtectedRoutes = express.Router(); 
const BasicAuthRoutes = express.Router();
app.use('/api', ProtectedRoutes);
app.use('/basic', BasicAuthRoutes);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.set('Secret', secret);

// set the view engine to ejs
app.set('view engine', 'ejs');

// make express look in the public directory for assets (css/js/img)
app.use(express.static(__dirname + '/public'));

// set the home page route
app.get('/', function(req, res) {

	// ejs render automatically looks in the views folder
	res.render('index');
});

app.post('/getToken', function(req, res){
    console.log(`Requested METHOD:${req.method} URL:${req.url} BODY:${JSON.stringify(req.body)}`);
    if (user.password === req.body.password){
        console.log(`User Authentication Successfull for user:${req.body.email_id}`);
        let token = jwt.sign(req.body, app.get('Secret'), {
            expiresIn: '24h' // expires in 1 hour
        });
        res.status(200).json({
            first_name: user.first_name,
            last_name:  user.last_name,
            access_token: token
        });
    } else{
        console.log(`Authentication failed for user:${user.first_name}`);
        res.status(401).send("Authentication failed!!");
    }

});

ProtectedRoutes.use((req, res, next) =>{
    // check header or url parameters or post parameters for token
    var bearerToken = req.headers['authorization'];
    
    // decode token
    if (bearerToken) {
        var token = bearerToken.split(" ")[1];
      // verifies secret and checks exp
      jwt.verify(token, app.get('Secret'), (err, decoded) =>{      
        if (err) {
            return res.status(401).send({ 
                message: 'Failed to authenticate token!!' 
            }); 
        } else {
          // if everything is good, save to request for use in other routes    
          next();
        }
      });
    } else {
      // if there is no token
      // return an error
      return res.status(403).send({ 
          message: 'Bearer token not found!!' 
      });
  
    }
});

ProtectedRoutes.get('/getXML', (req, res)=>{
    console.log(JSON.stringify(req.headers));
    xml_res = '<accountLookupResults> \
<status>success</status> \
<variables> \
    <variable name="IsMatch" value="N"/> \
    <variable name="DigitalIDStatus" value="12345678:active,87654321:barred"/> \
    <variable name="DigitalIDCount" value="2"/> \
    <variable name="ActiveDigitalIDCount" value="1"/> \
    <variable name="WSResult" value="success"/> \
</variables> \
</accountLookupResults>'

    res.set('Content-Type', 'text/xml');
    res.send(xml_res);
    res.status(200).send();
});

ProtectedRoutes.get('/getJson', (req, res)=>{
    console.log(JSON.stringify(req.headers));
    res.status(200).json({"DigitalIDStatus":"999999:active,111111:barred","DigitalIDCount": "91"});
});

app.get('/getXml', (req, res)=>{
    console.log(JSON.stringify(req.headers));
    console.log(JSON.stringify(req.body));
    xml_res = '<accountLookupResults> \
<status>success</status> \
<variables> \
    <variable name="IsMatch" value="N"/> \
    <variable name="DigitalIDStatus" value="12345678:active,87654321:barred"/> \
    <variable name="DigitalIDCount" value="2"/> \
    <variable name="ActiveDigitalIDCount" value="1"/> \
    <variable name="WSResult" value="success"/> \
</variables> \
</accountLookupResults>'

    res.set('Content-Type', 'application/xml');
    res.send(xml_res);
    res.status(200).send();
});

BasicAuthRoutes.use((req, res, next)=>{
    const auth = {login: 'designer', password: 'designer@123'};
    // parse login and password from headers
    const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
    const [login, password] = new Buffer(b64auth, 'base64').toString().split(':')

    // Verify login and password are set and correct
    if (!login || !password || login !== auth.login || password !== auth.password) {
        res.set('WWW-Authenticate', 'Basic realm="401"') // change this
        res.status(401).send('Authentication required.') // custom message
        return
    }
    
    // -----------------------------------------------------------------------
    // Access granted...
    next()
});

BasicAuthRoutes.get('/getXml', (req, res)=>{
    console.log(JSON.stringify(req.headers));
    console.log(JSON.stringify(req.body));
    xml_res = '<accountLookupResults> \
<status>success</status> \
<variables> \
    <variable name="IsMatch" value="N"/> \
    <variable name="DigitalIDStatus" value="87654321:active,87654321:barred"/> \
    <variable name="DigitalIDCount" value="2"/> \
    <variable name="ActiveDigitalIDCount" value="1"/> \
    <variable name="WSResult" value="success"/> \
</variables> \
</accountLookupResults>'

    res.set('Content-Type', 'application/xml');
    res.send(xml_res);
    res.status(200).send();
});

BasicAuthRoutes.get('/getJson', (req, res)=>{
    console.log(JSON.stringify(req.query));
    console.log(JSON.stringify(req.headers));
    res.status(200).json({"DigitalIDStatus":"999999:active,999999:barred","DigitalIDCount": "9"});
});

BasicAuthRoutes.post('/postJson', (req, res)=>{
    console.log(JSON.stringify(req.query));
    console.log(JSON.stringify(req.headers));
    console.log(JSON.stringify(req.body));
    res.status(200).json({"DigitalIDStatus":"88888888:active,88888888:barred","DigitalIDCount": "8"});
});

BasicAuthRoutes.post('/makePayment', (req, res)=>{
    console.log(JSON.stringify(req.query));
    console.log(JSON.stringify(req.headers));
    console.log(JSON.stringify(req.body));
    res.status(200).json({"message":"Success"});
});

http.createServer(app).listen(port);
// https.createServer(credentials, app).listen(httpsPort);
console.log('Our app is running on http://localhost:' + port);
// console.log('Our app is running on https://localhost:' + httpsPort);
