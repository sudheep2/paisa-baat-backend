import { Request, Response } from 'express';
import pkg from 'bcryptjs';
import jwt from 'jsonwebtoken';
const { hashSync, compare } = pkg;
import { getUser, createNewUser } from '@my-kitty/database/user'


export const signup = async (req: Request, res: Response) => {
  const { name, email, phoneNumber, password } = req.body;
  try {
    const username = email ? email : phoneNumber;
    const user =  await getUser(username,['username'])
    if (user) {
      return res.status(400).json({
        message:
          'User already exists. Please login or click on forgot passsword to reset password',
      });
    }

    const hashedPassword = await hashSync(password, 10);

    const newUser = await createNewUser(name,email,phoneNumber,username,password);
    
    const token = jwt.sign(
      { userId: newUser.id, username: newUser.username },
      process.env.JWT_SECRET_TOKEN || 'your-secret-key',
      { expiresIn: '7d' } // Token expires in 7 days
    );

    return res.status(200).json({
      message: 'User is created successfully',
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        username: newUser.username,
      },
    });
  } catch (error) {
    return res.status(500).json({
      message: 'Internal Server Error',
      error,
    });
  }
};

export const testMe = async (req: Request, res: Response) => {
  try {
    return res.status(200).json({
      message: 'Bad Request',
    });
  } catch (error) {
    return res.status(400).json({
      message: 'Bad Request',
      error,
    });
  }
};

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;
  try {
    const user:any = await getUser(username,['username','password','id']);
    if (!user) {
      return res.status(404).json({
        message: 'User not found, please signup',
      });
    }
    const verifyPassword = await compare(password, user.password);
    if (!verifyPassword) {
      return res.status(401).json({ message: 'Invalid Password' });
    }
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET_TOKEN || 'your-secret-key',
      { expiresIn: '7d' } // Token expires in 7 days
    );

    return res.status(201).json({
      message: 'User successfully logged in',
      token,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Internal server erro",
      error
    })
  }
};
