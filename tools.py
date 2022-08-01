import string, re, random
import bcrypt

def has_digits(passwd):
    return re.search('[0-9]', passwd) != None

def has_special_chars(passwd):
    return re.search(f'[{re.escape(string.punctuation)}]', passwd) != None

def has_min_pass_length(passwd):
    if len(passwd) < 6:
        return False
    return True

def is_password_strong(passwd):
    if has_digits(passwd) and has_special_chars(passwd) and has_min_pass_length(passwd):
        return True
    return False


def is_name_valid(name):
    regex = r"^[a-zA-Z ,'-]+$"
    if (re.fullmatch(regex, name)) and len(name) > 2:
        return True
    return False


def is_email_valid(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if (re.fullmatch(regex, email)):
        return True
    return False


def encrypt_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    if bcrypt.checkpw(password, hashed):
        return True
    return False


def random_code_generator():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))


def password_reset_token_generator():
    return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(14))

