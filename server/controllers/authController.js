import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';


export const register = async (req, res) => {

    const { name, email, password } = req.body;

    if(!name || !email || !password) {
        return res.status(400).json({ success: false, message: "Missing Details" });
    }

    try {

        const existingUser = await userModel.findOne({ email })
        
        if(existingUser) {
            return res.status(400).json({ success: false, message: "User already exists" });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);

        constuser = new userModel({
            name,
            email,
            password: hashedPassword
        });
        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });

        return res.status(200).json({ success: true, message: "User created successfully" });

    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }

}

export const login = async (req, res) => {
    const { email, password } = req.body;

    if(!email || !password) {
        return res.status(400).json({ success: false, message: "Email and Password are required" });
    }

    try {
        const user = await userModel.findOne({ email });

        if(!user) {
            return res.status(400).json({ success: false, message: "Invalid Email" });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if(!isPasswordMatch) {
            return res.status(400).json({ success: false, message: "Invalid Password" });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.cookie("token", token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });

        return res.status(200).json({ success: true, message: "User logged in successfully" });

    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
}