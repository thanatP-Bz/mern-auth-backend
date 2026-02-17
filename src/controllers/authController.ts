import { NextFunction, Request, Response } from "express";
import { ApiError } from "../utils/ApiError";
import { asyncHandler } from "../utils/asyncHandler";
import {
  login,
  logout,
  register,
  verify2FALogin,
} from "../services/auth.service";
import {
  changePassword,
  forgetPassword,
  resetPassword,
} from "../services/password.service";
import { refreshToken } from "../services/token.service";
import {
  resendVerificationEmail,
  verifyEmail,
} from "../services/verifyEmail.service";
import {
  createSession,
  deactivateSession,
} from "../services/session.redis.service";
import { IUserDocument } from "../types/user";

//**************Register***************//
export const registerController = asyncHandler(
  async (req: Request, res: Response) => {
    const result = await register(req.body);

    res.status(200).json(result);
  },
);

//**************verify Email***************//
export const verifyEmailController = asyncHandler(
  async (req: Request, res: Response) => {
    const { token } = req.query;

    if (!token || typeof token !== "string") {
      throw new ApiError("Verification token is required", 400);
    }

    const result = await verifyEmail(token);

    res.status(200).json(result);
  },
);

//**************Login***************//
export const loginController = asyncHandler(
  async (req: Request, res: Response) => {
    console.log("🔍 LOGIN CONTROLLER CALLED!"); // ← Move to TOP!
    console.log("🔍 req.rateLimit at start:", req.rateLimit);
    const result = await login(req.body);

    //check 2FA
    if ("requires2FA" in result && result.requires2FA) {
      // 2FA required - don't create session or set cookies
      return res.status(200).json({
        requires2FA: true,
        message: result.message,
        userId: result.userId,
      });
    }

    //new: create session
    const session = await createSession({
      userId: result.user!._id.toString(),
      ipAddress: req.ip || req.socket.remoteAddress || "unknown",
      userAgent: req.headers["user-agent"] || "unknown",
    });

    // ✅ FIXED - Cross-origin cookie settings
    res.cookie("accessToken", result.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //set sessionId cookie
    res.cookie("sessionId", session, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: result.message,
      user: result.user,
    });
  },
);

//**************verify 2FA Login***************//
export const verify2FALoginController = asyncHandler(
  async (req: Request, res: Response) => {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return res.status(400).json({ message: "User ID and 2FA are required" });
    }

    const result = await verify2FALogin(userId, token);

    //new: create session
    const session = await createSession({
      userId: result.user!._id.toString(),
      ipAddress: req.ip || req.socket.remoteAddress || "unknown",
      userAgent: req.headers["user-agent"] || "unknown",
    });

    // ✅ FIXED - Cross-origin cookie settings
    res.cookie("accessToken", result.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    //set sessionId cookie
    res.cookie("sessionId", session, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      message: result.message,
      user: result.user,
    });
  },
);

//**************resend verify Email***************//
export const resendVerifyEmailController = asyncHandler(
  async (req: Request, res: Response) => {
    const { email } = req.body;

    const result = await resendVerificationEmail(email);
    res.status(200).json(result);
  },
);

//**************change Password***************//
export const changePasswordController = asyncHandler(
  async (req: Request, res: Response) => {
    const { email, oldPassword, newPassword } = req.body;
    const result = await changePassword(email, oldPassword, newPassword);

    return res.status(200).json(result);
  },
);

//**************Forget Password***************//
export const forgetPasswordController = asyncHandler(
  async (req: Request, res: Response) => {
    const { email } = req.body;

    if (!email) throw new ApiError("Email is required", 400);
    const result = await forgetPassword(email);
    res.status(200).json(result);
  },
);

//**************Reset Password***************//
export const resetPasswordController = asyncHandler(
  async (req: Request, res: Response) => {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password)
      throw new ApiError("Token and password are required", 400);

    const result = await resetPassword(token, password);
    res.status(200).json(result);
  },
);

//**************Refresh Token***************//
export const refreshTokenController = asyncHandler(
  async (req: Request, res: Response) => {
    const token = req.cookies.refreshToken;

    if (!token) {
      throw new ApiError("Refresh token not found", 401);
    }
    const result = await refreshToken(token);

    // ✅ FIXED - Cross-origin cookie settings
    res.cookie("accessToken", result.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("refreshToken", result.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: result.accessToken,
    });
  },
);

//**************logout***************//
export const logoutController = asyncHandler(
  async (req: Request, res: Response) => {
    const user = req.user as IUserDocument;
    const userId = user?._id.toString() || req.body.userId;

    //get sessionId from cookie and deactivate it
    const sessionId = req.cookies.sessionId;

    if (sessionId) {
      await deactivateSession(sessionId);
    }

    const result = await logout(userId);

    // ✅ Clear the cookie!
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.clearCookie("sessionId");

    res.status(200).json(result);
  },
);
