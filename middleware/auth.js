const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
    // Get token from header
    const token = req.header('x-auth-token');

    // check token
    if(!token){
        return res.status(401).json({msg: 'No token, authentication failed'});
    }

    // verifying token
    try{
        const decoded = jwt.verify(token, config.get('jwtSecret'));
        // decoding token and set to request
        req.user = decoded.user;
        next();
    } catch(err){
        res.status(401).json({msg: 'token is not valid'});
    }
}