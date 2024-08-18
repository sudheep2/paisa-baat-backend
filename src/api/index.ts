import { Router, Request, Response } from 'express';
import { validateMiddleware } from '../middleware/validateMiddleware';
import { loginSchema, signupSchema } from '@my-kitty/zod/userSchema';
import { login, signup } from '../controllers/authController';
import { authMiddleware } from '../middleware/authMiddleware';
import {
  addUsersToGroup,
  createGroupAndAssignAdmin,
} from '../controllers/groupController';

const apiRouter: Router = Router();

apiRouter.get('/', (req: Request, res: Response) => {
  return res.status(200).json({
    message: 'At api ',
  });
});
apiRouter.post('/signup', validateMiddleware(signupSchema), signup);
apiRouter.post('/login', validateMiddleware(loginSchema), login);
apiRouter.post('/create-group', authMiddleware, createGroupAndAssignAdmin);
apiRouter.post('/join-group', authMiddleware, addUsersToGroup);

export default apiRouter;
