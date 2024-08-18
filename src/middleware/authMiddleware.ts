import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';

interface DecodedToken extends JwtPayload {
  username: string;
  userId: string;
}

interface CustomRequest extends Request {
  username?: string;
  userId?: string;
}

export const authMiddleware = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer')) {
      return res.status(403).json({
        message: 'User not authorized',
      });
    }
    const token = authHeader?.split(' ')[1];

    const decodeToken = jwt.verify(
      token,
      process.env.JWT_SECRET_TOKEN || 'your-secret-key'
    ) as DecodedToken;

    req.username = decodeToken.username;
    req.userId = decodeToken.userId;
    next();
  } catch (error) {
    return res.status(403).json({
      message: 'Authorization not valid',
      error,
    });
  }
};
