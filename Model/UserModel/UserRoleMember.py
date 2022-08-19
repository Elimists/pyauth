from Model import UserModel

class UserRoleMember():
    
    user: UserModel.User
    userRole: UserModel.UserRole
    
    def __init__(self, user: UserModel.User, userRole: UserModel.UserRole) -> None:
        self.user = user
        self.userRole = userRole
    
    def getUserObject(self) -> UserModel.User:
        return self.user
    
    def getUserRoleObject(self) -> UserModel.UserRole:
        return self.userRole
    