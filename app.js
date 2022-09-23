require("dotenv").config()
require('./config/database').connect()
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const User = require("./model/User");
const auth = require("./middleware/auth");


const app = express();
app.use(express.json());
app.use(cookieParser());

app.get("/", (req,res) => {
    res.send("<h1>Hello from Auth system -LCO</h1>")
})

app.post("/register", async (req, res) => {
    try {
        const {firstName, lastName, email, password} = req.body;

        if (!(email && password && firstName && lastName)) {
            res.status(400).send('All fields are required')
        }

        const existingUser = await User.findOne({email}); // PROMISE

        if(existingUser) {
            res.status(401).send("User already exists")
        }

        const myEncryptedPassword = await bcrypt.hash(password, 10)

        const user = await User.create({
            firstName,
            lastName,
            email: email.toLowerCase(),
            password: myEncryptedPassword
        });

        //token
        const token = jwt.sign(
            {user_id: user._id, email},
            process.env.SECRET_KEY,
            {
                expiresIn: "2h"
            }
        )

        user.token = token
        //update or not in database

        // handle password situation
        user.password = undefined // if we assign undefined to it then in output password will not be shown(in postman)

        // send token or send just success yes and redirect -choice
        res.status(201).json(user)

    } catch (error) {
        console.log(error);
    }

})

app.post("/login", async (req,res) => {
    try {
        const {email, password} = req.body

        if(!(email && password)){
            res.status(400).send("Field is missing")
        }

        const user = await User.findOne({email})

        // if(!user){
        //     res.status(400).send("You are not registered in our app")
        // }

        
        if(user && (await bcrypt.compare(password, user.password))){
            const token = jwt.sign(
                {user_id: user._id, email},
                process.env.SECRET_KEY,
                {
                    expiresIn: "2h"
                }
            )

            user.token = token
            user.password = undefined
            // res.status(200).json(user)

            // if you want to use cookies
            const options = {
                expires: new Date(
                    Date.now() + 3 *24 *60 *60 *1000  //for 3 days from current date
                ), 
                httpOnly: true
            };

            res.status(200).cookie('token', token, options).json(
                {
                    success: true,
                    token,
                    user
                }
            )
        }

        res.send(400).send("email or password is incorrect")

    } catch (error) {
        console.log(error);
    }
})

app.get("/dashboard",auth, (req, res) => {
    res.send("Welcome to secret information")
})

module.exports = app