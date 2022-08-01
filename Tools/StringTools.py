import re

class StringTools:

    def __init__(self, string):
        self.string = string

    
    def is_name_valid(self):
        regex = r"^[a-zA-Z ,'-]+$"
        if (re.fullmatch(regex, self.string)) and len(self.string) > 2:
            return True
        return False


    def is_email_valid(self):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if (re.fullmatch(regex, self.string)):
            return True
        return False