import re
from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()


class RegisterForm(forms.Form):
    nombre = forms.CharField(
        max_length=150,
        error_messages={'required': 'El nombre es obligatorio.'},
    )
    email = forms.EmailField(
        max_length=150,
        error_messages={
            'required': 'El correo es obligatorio.',
            'invalid': 'Ingresa un correo con formato válido.',
        },
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        error_messages={'required': 'La contraseña es obligatoria.'},
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput,
        error_messages={'required': 'Debes confirmar la contraseña.'},
    )

    def clean_nombre(self):
        nombre = self.cleaned_data['nombre'].strip()
        if not nombre:
            raise forms.ValidationError('El nombre es obligatorio.')
        return nombre

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(username__iexact=email).exists():
            raise forms.ValidationError('Este correo ya está registrado.')
        return email

    def clean_password(self):
        pwd = self.cleaned_data['password']
        errores = []
        if len(pwd) < 8:
            errores.append('al menos 8 caracteres')
        if not re.search(r'[A-Z]', pwd):
            errores.append('una mayúscula')
        if not re.search(r'[a-z]', pwd):
            errores.append('una minúscula')
        if not re.search(r'\d', pwd):
            errores.append('un número')
        if errores:
            raise forms.ValidationError(
                'La contraseña debe tener ' + ', '.join(errores) + '.'
            )
        return pwd

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get('password')
        p2 = cleaned.get('password2')
        if p1 and p2 and p1 != p2:
            self.add_error('password2', 'Las contraseñas no coinciden.')
        return cleaned


class LoginForm(forms.Form):
    email = forms.EmailField(
        error_messages={'required': 'El correo es obligatorio.',
                        'invalid': 'Ingresa un correo válido.'},
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        error_messages={'required': 'La contraseña es obligatoria.'},
    )