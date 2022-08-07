from Database import UserFactory

uf = UserFactory()
#result = uf.createUser('pandeydee@gmail.com', 'Deepak Pandey', 'hashedPasswordTest')
#result = uf.getUserByEmail('pandeydee@gmail.com')
result = uf.updateUserName('pandeydee@gmail.com', 'Dpk Pdy')
print(result)