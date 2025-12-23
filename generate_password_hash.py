#!/usr/bin/env python3
"""
Скрипт для генерации хэша пароля
"""

import hashlib
import secrets
import getpass


def hash_password(password, salt=None):
    """Хэширование пароля с солью"""
    if salt is None:
        salt = secrets.token_hex(16)

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )

    return f"{salt}:{key.hex()}"


def main():
    print("Генератор хэша пароля для администратора")
    print("=" * 40)

    # Запрашиваем пароль
    password = getpass.getpass("Введите пароль администратора: ")
    confirm = getpass.getpass("Повторите пароль: ")

    if password != confirm:
        print("Ошибка: пароли не совпадают!")
        return

    # Проверяем сложность пароля
    if len(password) < 8:
        print("Ошибка: пароль должен быть не менее 8 символов")
        return

    if not any(char.isdigit() for char in password):
        print("Ошибка: пароль должен содержать хотя бы одну цифру")
        return

    if not any(char.isupper() for char in password):
        print("Ошибка: пароль должен содержать хотя бы одну заглавную букву")
        return

    if not any(char.islower() for char in password):
        print("Ошибка: пароль должен содержать хотя бы одну строчную букву")
        return

    # Генерируем хэш
    password_hash = hash_password(password)

    print("\n" + "=" * 40)
    print("Хэш пароля успешно сгенерирован!")
    print("\nСоздайте файл .env со следующим содержимым:")
    print("=" * 40)
    print(f"ADMIN_USERNAME=admin")
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    print("=" * 40)


if __name__ == "__main__":
    main()