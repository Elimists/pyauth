
from Database import UserFactory
import Model.UserModel as UserModelPackage
import time

"""
user = UserSignUp('chelseao@neilsquire.ca', "Abc@123!")
print(user.getDetails())
print("_____")
def passIn(user):
    print(user.getDetails())
    print(user.getVerificationCode())
    print(user.getUserPassword())

passIn(user)

UserFactory().createUser(user)

sign = Model.Auth.SignUp("abcd", "helloworld")
print(sign.getPassword())
print(type(sign.getPassword()))

activationCode = Model.Auth.ActivationCode("pandey.pran@gmail.com")

print(activationCode.getActivationCode())
print(activationCode.getNewActivationCode())
print(activationCode.getActivationCode())
"""
t0 = time.time()

ur = UserModelPackage.UserRoleMember(UserModelPackage.User('pandey.pran@gmail.com'), UserModelPackage.UserRole())

urUser = ur.getUserObject()
urRole = ur.getUserRoleObject()
print(urUser.getEmail())
print(urRole.getUserIsChapterLeader())

uadmin = UserModelPackage.AdminRoleMember(UserModelPackage.User('pandey.pran@gmail.com'), UserModelPackage.AdminRole())
print(uadmin.getAdminRoleObject().getUserIsDirector())


time.sleep(2)
t1 = time.time()
print((t1-t0))