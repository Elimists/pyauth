from Model import UserModel

class AdminRoleMember():
    
    user: UserModel.User
    adminRole: UserModel.AdminRole
    
    def __init__(self, user: UserModel.User, adminRole: UserModel.AdminRole) -> None:
        self.user = user
        self.adminRole = adminRole

    def getAdminUserObject(self) -> UserModel.User:
        return self.user
    
    def getAdminRoleObject(self) -> UserModel.AdminRole:
        return self.adminRole