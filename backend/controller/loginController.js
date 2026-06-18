const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { StatusCodes } = require('http-status-codes') 
const UserModels = require('../models/signUpModel')
const { generateOtp, maskEmail, sendEmail } = require('./signUpController')
const UserOtpVerificationModel = require('../models/userOtpVerificationModel')

// Generates a short-lived access token (15 mins)
const generateAccessToken = (user) => {
  return jwt.sign(
    { 
      id: user._id, 
      userType: user.userType 
    },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: '15m' }
  );
};

// Generates a long-lived refresh token (7 days)
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

// Base Cookie Options for Defense against XSS & CSRF
const COOKIE_OPTIONS = {
  path: '/',
  httpOnly: true, // Blocks malicious JavaScript execution (Mitigates XSS)
  sameSite: 'lax', // Restricts cross-site request forgery (Protects against CSRF)
  secure: process.env.NODE_ENV === 'production', // Forces HTTPS encrypted transfers in production
};

const ACCESS_EXPIRY_MS = 15 * 60 * 1000;          // 15 Minutes
const REFRESH_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // 7 Days

const postUserLogin = async (req, res) => {
  try {
    // converting @gmail.com domain into lowercase to match with database
    const email = await ConvertEmail(req.body.email)

    const result = await UserModels.findOne({ email: email }).select('+password')

    if (!result) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ success: false, message: `Invalid email or password` })
    }

    const validate_password = await bcrypt.compare(
      req.body.password,
      result.password
    )
    if (!validate_password) {
      return res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ success: false, message: 'Invalid email or password' })
    }

    if (result.emailVerified === false) {
      const userId = result.id

      const otp_Code = Math.floor(Math.random() * 9000 + 1000)
      const hashed_otpCode = await generateOtp(otp_Code)

      res.cookie('otp-cookie', userId, {
        path: '/',
        expires: new Date(Date.now() + 1000 * 60 * 60 * 24), // 24hr otp cookie that stores userId
        httpOnly: true,
        sameSite: 'lax',
      })

      await UserOtpVerificationModel.findOneAndUpdate(
        { userId: userId },
        {
          otpCode: hashed_otpCode,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 1000 * 60),
        }
      )

      const maskedEmailString = await maskEmail(email)

      await sendEmail(email, otp_Code)

      return res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        message: `Email not Verified ! OTP Verification code re-sent to email ${maskedEmailString}`,
        ENTER_OTP: true,
      })
    }

    // Generating secure JSON Web Tokens on successful validation
    const jwt_token = generateAccessToken(result);
    const refresh_token = generateRefreshToken(result);

    // Setting the short-lived access cookie
    res.cookie('access-cookie', jwt_token, {
      ...COOKIE_OPTIONS,
      expires: new Date(Date.now() + ACCESS_EXPIRY_MS),
    })

    // Setting the long-lived refresh cookie
    res.cookie('refresh-cookie', refresh_token, {
      ...COOKIE_OPTIONS,
      expires: new Date(Date.now() + REFRESH_EXPIRY_MS),
    })

    return res.status(StatusCodes.OK).json({
      success: true,
      userType: result.userType,
    })

  } catch (error) {
    return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      message: error.message
    })
  }
}

// Converting @gmail.com to lower
const ConvertEmail = async (email) => {
  const emailWithoutSpaces = email.replace(/\s/g, '') // Remove spaces using regular expression
  const emailParts = emailWithoutSpaces.split('@')
  const firstEmailPart = emailParts[0]
  const secondEmailPart = emailParts[1].toLowerCase()

  return firstEmailPart + '@' + secondEmailPart
}

module.exports = postUserLogin