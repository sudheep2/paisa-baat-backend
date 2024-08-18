import { createNewGroup,addUserToGroup,verifyIfUserPresentInGroup } from '@my-kitty/database/group';
import { Request, Response } from 'express';

interface requestBodyType extends Request {
  id?: string;
  name?: string;
  username?: string;
  description?: string;
}

export const createGroupAndAssignAdmin = async (
  req: Request,
  res: Response
) => {
  try {
    const { name, description }: requestBodyType = req.body;
    const { userId }: any = req;
    const newGroup = await createNewGroup(userId, name, description);

    if(!newGroup){
      return res.status(500).json({
        message: "Unable to create new group, please contact support"
      })
    }
    
    return res.status(200).json({
      message: 'New group has been created successfully',
      newGroup,
    });
  } catch (err) {
    return res.status(500).json({
      message: 'Cannot create a group',
      err,
    });
  }
};

export const addUsersToGroup = async (req: Request, res: Response) => {
  try {
    const { groupId } = req.body;
    const { userId }: any = req;
    
    const userExistsInGroup = await verifyIfUserPresentInGroup(userId,groupId)
    if (userExistsInGroup) {
      return res.status(400).json({
        message: 'User is already part of the group',
      });
    }
    const addNewUserToGroup = await addUserToGroup(userId,groupId);
    if(!addNewUserToGroup){
      return res.status(500).json({
        message: "Unable to join group"
      })
    }
    return res.status(200).json({
      message: 'Successfully joined the group',
      addNewUserToGroup,
    });
  } catch (err) {
    res.status(500).json({
      message: 'Unable to join the group',
      err,
    });
  }
};
