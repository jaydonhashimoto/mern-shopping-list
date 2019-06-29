const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const auth = require('../../middleware/auth');

//User model
const User = require('../../models/User');

/**
 * @route POST api/auth
 * @desc Auth user
 * @access Public
 */
router.post('/', (req, res) => {
    const { email, password } = req.body;
    //simple validation
    if (!email || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }

    //check for existing user
    User.findOne({ email })
        .then(user => {
            //check user is null or not
            if (!user) {
                return res.status(400).json({ msg: 'User Does Not Exist' });
            }

            //validate password
            bcrypt.compare(password, user.password)
                .then(isMatch => {
                    if (!isMatch) {
                        return res.status(400).json({ msg: 'Invalid Credentials' });
                    }

                    //sign jwt token with payload, secret, expiration, cb
                    jwt.sign(
                        { id: user.id },
                        config.get('jwtSecret'),
                        { expiresIn: 3600 },
                        (err, token) => {
                            if (err) throw err;
                            res.json({
                                token,
                                user: {
                                    id: user.id,
                                    name: user.name,
                                    email: user.email
                                }
                            });
                        }
                    )
                })
        })
});

/**
 * @route GET api/auth/user
 * @desc Get user data
 * @access Private
 */
router.get('/user', auth, (req, res) => {
    User.findById(req.user.id)
        //disregard password
        .select('-password')
        .then(user => {
            res.json(user);
        })
})

module.exports = router;