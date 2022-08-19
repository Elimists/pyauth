import random, string, secrets

class GeneratorTools:

    def verification_code_generator():
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(6))


    def password_reset_token_generator():
        return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(14))


    def generate_session_id():
        return secrets.token_urlsafe(16)

