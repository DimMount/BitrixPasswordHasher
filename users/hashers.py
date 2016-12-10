import hashlib

from django.contrib.auth.hashers import MD5PasswordHasher
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_bytes


class BitrixPasswordHasher(MD5PasswordHasher):
    """
    Проверка паролей хешированных в CMS "Битрикс"
    """
    algorithm = "bitrix"

    def encode(self, password, salt):
        assert password is not None
        # Если надо сохранять пароли как в битрикс, то надо соблюсти длину соли в 8 символов
        if len(salt) > 8:
            salt = salt[:8]
        elif len(salt) < 8:
            salt.ljust(8, "X")
        md5_hash = hashlib.md5(force_bytes(salt + password)).hexdigest()
        return "%s$%s%s" % (self.algorithm, salt, md5_hash)

    def verify(self, password, encoded):
        algorithm, salted = encoded.split('$', 1)
        assert algorithm == self.algorithm
        salt = salted[:8]
        encoded_2 = self.encode(password, salt)
        return constant_time_compare(encoded, encoded_2)

