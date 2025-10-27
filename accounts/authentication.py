from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from .utils import verify_jwt_token

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """
    Кастомная JWT аутентификация для DRF
    """

    def authenticate(self, request):
        # Получаем заголовок Authorization
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return None  # Нет токена - не аутентифицируем

        # Проверяем формат: "Bearer <token>"
        try:
            prefix, token = auth_header.split(" ")
            if prefix.lower() != "bearer":
                return None
        except ValueError:
            return None

        # Проверяем токен
        payload = verify_jwt_token(token)
        if not payload:
            raise AuthenticationFailed("Невалидный или истекший токен")

        # Проверяем тип токена (должен быть access)
        if payload.get("token_type") != "access":
            raise AuthenticationFailed("Неверный тип токена")

        # Находим пользователя
        try:
            user = User.objects.get(id=payload["user_id"])
        except User.DoesNotExist:
            raise AuthenticationFailed("Пользователь не найден")

        return (user, token)  # Возвращаем (user, token) как требует DRF
