var crypto = require("crypto");
var http = require("http");
var url = require("url");

var randStr = function(len) {
    var str = "";
    for(var i = 0; i < len; ++i) {
        var code = Math.floor(Math.random() * 26) + 'a'.charCodeAt(0);
        str += String.fromCharCode(code);
    }
    return str;
};

var secretKey = randStr(16);

var insecureCompare = function(a, b, sleep, cb) {
    var cmpDigit = function(digit) {
        return function() {
            if(digit == a.length && digit == b.length) {
                return cb(true);
            } else if(digit == a.length || digit == b.length) {
                // The size should be compared first,
                // but we would be able to find the size
                // through either a timing attack or a
                // public API spec.
                return cb(false);
            } else if(a.charAt(digit) != b.charAt(digit)) {
                return cb(false);
            } else if(sleep < 50) {
                var stop = sleep + (new Date().getTime());
                while((new Date().getTime()) < stop) {
                }
                return cmpDigit(digit + 1)();
            } else {
                return setTimeout(cmpDigit(digit + 1), sleep);
            }
        }
    }
    cmpDigit(0)();
};

http.createServer(function(req, res) {
    var query = url.parse(req.url, true).query;
    var file = query.file;
    var hmacAct = query.signature;
    var sleep = query.sleep ? parseInt(query.sleep) : 50;
    if(file === undefined || hmacAct === undefined) {
        res.writeHead(400, {'Content-Type': 'text/plain'});
        res.end();
        return;
    }

    var hmacExp = crypto.createHmac('sha256', secretKey).update(file).digest('hex');
    // Shorter HMAC for testing
    hmacExp = hmacExp.substr(0, 16);

    insecureCompare(hmacExp, hmacAct, sleep, function(result) {
        if(result) {
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end(hmacExp);
        } else {
            res.writeHead(500, {'Content-Type': 'text/plain'});
            res.end();
            //console.log(hmacExp + ", " + hmacAct);
        }
    });
}).listen(8080);

console.log("Running on port 8080");
