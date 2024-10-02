import UserModel from "../../models/UserModel.js";
import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const config = process.env;

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate email and password
    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required",
        ok: false,
        status: 400,
      });
    }

    // Find user in the database
    const user = await UserModel.findOne({
      where: { email: email },
      attributes: {
        exclude: ["salt"],
      },
    });
    if (!user) {
      return res.status(404).json({
        message: "User does not exist",
        ok: false,
        status: 404,
      });
    }

    // Compare the hashed password
    const passwordMatch = await bcryptjs.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        error: "Invalid credentials",
        ok: false,
        status: 401,
      });
    }

    // Generate JWT token
    const token = jsonwebtoken.sign(
      { email: user.email, username: user.username, userId: user.id },
      config.TOKEN,
      { expiresIn: "1d" } // 1 day expiration
    );

    // Set the cookie with the token
    res.cookie("advanced-state-management-user", token, {
      httpOnly: true, // Prevent client-side access
      signed: true, // Sign the cookie
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      sameSite: "None", // Use "None" for cross-site requests
      path: "/",
    });

    // Return successful response
    return res.status(200).json({
      token: token,
      username: user.username,
      userId: user.id,
      email: user.email,
      role: user.role,
      status: 200,
      ok: true,
    });
  } catch (err) {
    return res.status(503).json({
      error: "Internal server error",
      message: err.message,
      status: 503,
      ok: false,
    });
  }
};

export default login;
