const express = require("express");

const router = express.Router();
const auth = require('../../middleware/auth');
const User = require('../../models/User');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('config');
const {check, validationResult} = require('express-validator');
//@route    GET api/auth
//@desc     Test route
//@access   Public

router.get('/',auth, async(req, res) => {
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }catch(err){
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

//@route    Post api/auth
//@desc     Authenticate user and get token
//@access   Public
router.post(
    '/',
    [
        check('email', 'Please add a valid Email').isEmail(),
        check('password', 'Password is Required*').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const {email, password } = req.body;

        try {
            let user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            
            // the above response should be same as below
            if(!isMatch){
                return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
            }
            const payload={
                user:{
                    id: user.id
                }
            }

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                {expiresIn: 360000},
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }

    }
);

module.exports = router;