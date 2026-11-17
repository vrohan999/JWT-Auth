require('dotenv').config();
const express = require("express");
const server = express();
const { prisma } = require("./database/db");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const saltRounds = 10;
const PORT = 3000;
server.use(express.json());

function createAccessToken(account){
    return jwt.sign({id: account.id, email: account.email}, process.env.JWTSECRET, {
        expiresIn: '1h',
        jwtid: crypto.randomUUID()
    });
}

function verifyToken(req,res,next){
    const bearerHeader = req.headers.authorization;

    if(!bearerHeader || !bearerHeader.startsWith('Bearer ')){
        return res.status(401).json({error:"Unauthorized access."})
    }

    const accessToken = bearerHeader.split(" ")[1];

    try{
        const payload = jwt.verify(accessToken, process.env.JWTSECRET);
        req.user = payload;
        next();
    }catch(error){
        return res.status(401).json({error:"Invalid or expired token."})
    }
}

server.post("/signup",async (req,res)=>{
    try{
        const { email, password } = req.body;

        if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || password.length < 6){
            return res.status(400).json({ error: "Invalid input." });
        }

        const cleanEmail = email.trim().toLowerCase();

        const existingAccount = await prisma.user.findUnique({
            where: { email: cleanEmail },
        });

        if(existingAccount){
            return res.status(409).json({error:"Email already exists."})
        }

        const passwordHash = await bcrypt.hash(password, saltRounds);

        const createdAccount = await prisma.user.create({
            data:{
                email: cleanEmail,
                password: passwordHash
            },
            select: {
            id: true,
            email: true,
            createdAt: true
        }
        })

        const token = createAccessToken(createdAccount);
        res.status(201).json({message:"Registration successful.",user: createdAccount, token})
    }catch(error){
        return res.status(500).json({error:"Internal server error."})
    }
})


server.post("/login",async(req,res)=>{
    try{const {email,password} = req.body;

    if(!email || !password || typeof email !== 'string' || typeof password !=='string' || !email.trim()){
        return res.status(400).json({error: "Missing or invalid input."
    })
    }

    const cleanEmail = email.trim().toLowerCase();

    const account = await prisma.user.findUnique({
        where: {email : cleanEmail}
    })

    if(!account){
        return res.status(401).json({error:" Invalid email or password."})
    }

    const passwordMatches = await bcrypt.compare(password, account.password);

    if(!passwordMatches){
        return res.status(401).json({error:" Invalid email or password."
    })}

    const token = createAccessToken(account);

    return res.status(200).json({message:"Login successful.", token})
    }catch(error){
        return res.status(500).json({error:"Internal server error."})
    }
})

server.get("/me",verifyToken,async(req,res)=>{
    try {
        const profile = await prisma.user.findUnique({
            where: {
                id: req.user.id
            },
            select: {
                id: true,
                email: true,
                name: true,
                createdAt: true
            }
        });

        if (!profile) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        return res.status(200).json({ user: profile });

    } catch (error) {
        return res.status(500).json({
            error: "Internal server error."
        });
    }
})

server.get("/dashboard", verifyToken, async (req, res) => {
    try {
        const profile = await prisma.user.findUnique({
            where: {
                id: req.user.id
            },
            select: {
                email: true,
                name: true
            }
        });

        if (!profile) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const greetingName = profile.name || profile.email;

        return res.status(200).json({
            message: `Welcome, ${greetingName}!`
        });

    } catch (error) {
        return res.status(500).json({
            error: "Internal server error."
        });
    }
});

server.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}`)
})
