import re, string
import bcrypt

class PasswordTools:

    def __init__(self, password):
        self.password = password


    def __has_digits(self):
        return re.search('[0-9]', self.password) != None


    def __has_special_chars(self):
        return re.search(f'[{re.escape(string.punctuation)}]', self.password) != None


    def __has_min_pass_length(self):
        if len(self.password) < 6:
            return False
        return True


    def is_password_strong(self):
        if self.__has_digits() and self.__has_special_chars() and self.__has_min_pass_length():
            return True
        return False

    
    def encrypt_password(self):
        return bcrypt.hashpw(self.password.encode('utf-8'), bcrypt.gensalt())


    def check_password(self, hashed):
        if bcrypt.checkpw(self.password, hashed):
            return True
        return False