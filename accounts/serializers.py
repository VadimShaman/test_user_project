from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User


class UserLoginSerializer(serializers.Serializer):
    """
    Сериализатор для входа пользователя
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            # Проверяем учетные данные
            user = authenticate(email=email, password=password)

            if not user:
                raise serializers.ValidationError("Неверный email или пароль")

            if not user.is_active:
                raise serializers.ValidationError("Аккаунт деактивирован")

            attrs["user"] = user
            return attrs
        else:
            raise serializers.ValidationError("Email и пароль обязательны")


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    Сериализатор для регистрации пользователя
    """

    password = serializers.CharField(write_only=True, min_length=6)
    password_confirmation = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = (
            "email",
            "first_name",
            "last_name",
            "password",
            "password_confirmation",
        )

    def validate(self, attrs):
        # Проверяем совпадение паролей
        if attrs["password"] != attrs["password_confirmation"]:
            raise serializers.ValidationError("Пароли не совпадают")
        return attrs

    def create(self, validated_data):
        # Убираем подтверждение пароля из данных
        validated_data.pop("password_confirmation")

        # Создаем пользователя через наш UserManager
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
        )
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Сериализатор для профиля пользователя
    """

    class Meta:
        model = User
        fields = ("id", "email", "first_name", "last_name", "date_joined", "last_login")
        read_only_fields = ("id", "email", "date_joined", "last_login")
