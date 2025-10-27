import jwt
from datetime import datetime, timedelta
from django.conf import settings


def create_jwt_tokens(user):
    """
    Создает Access и Refresh токены для пользователя
    """
    # Access Token (живет 15 минут)
    access_token_payload = {
        "user_id": user.id,
        "email": user.email,
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "iat": datetime.utcnow(),
        "token_type": "access",
    }

    # Refresh Token (живет 7 дней)
    refresh_token_payload = {
        "user_id": user.id,
        "exp": datetime.utcnow() + timedelta(days=7),
        "iat": datetime.utcnow(),
        "token_type": "refresh",
    }

    # Создаем токены с секретным ключом
    access_token = jwt.encode(
        access_token_payload, settings.SECRET_KEY, algorithm="HS256"
    )
    refresh_token = jwt.encode(
        refresh_token_payload, settings.SECRET_KEY, algorithm="HS256"
    )

    return {"access": access_token, "refresh": refresh_token}


def verify_jwt_token(token):
    """
    Проверяет JWT токен и возвращает payload если валиден
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        # Токен истек
        return None
    except jwt.InvalidTokenError:
        # Невалидный токен
        return None
