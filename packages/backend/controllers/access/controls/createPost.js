import BlogModel from "../../../models/BlogModel.js";
import dotenv from "dotenv";

dotenv.config();
const config = process.env;

import jsonwebtoken from "jsonwebtoken";

const jwt = jsonwebtoken;

const createPost = async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "No token provided or invalid format",
        status: 401,
        ok: false,
      });
    }

    const token = authHeader.split(" ")[1];
    const user = jwt.verify(token, config.TOKEN);
    const authorUserName = user.username ?? null;
    const authorId = user.userId ?? null;

    if (!authorUserName || !authorId) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Invalid token",
        status: 401,
        ok: false,
      });
    }

    const { title, content } = req.body;
    if (!title || !content) {
      return res.status(400).json({
        error: "Malformed Input",
        message: "Title or description cannot be empty",
        status: 400,
        ok: false,
      });
    }

    await BlogModel.create({
      authorId: authorId,
      authorUserName: authorUserName,
      title: title,
      content: content,
    });

    // Set the cookie with the token
    res.cookie("advanced-state-management-user", token, {
      httpOnly: true, // Prevent client-side access
      signed: true, // Sign the cookie
      secure: process.env.NODE_ENV === "production", // Use secure cookies in production
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      sameSite: "None", // Use "None" for cross-site requests
      path: "/",
    });

    return res.status(200).json({
      message: "Successfully created new blog post!",
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

export default createPost;
