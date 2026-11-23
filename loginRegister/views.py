from django.shortcuts import render

# Create your views here.
from datetime import timedelta
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_encode, urlsafe_base64_decode
from django.views.decorators.cache import never_cache

from .forms import RegisterForm, LoginForm, PasswordResetRequestForm, SetPasswordForm
from .models import LoginAttempt

User = get_user_model()


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            # create_user guarda la contraseña hasheada (PBKDF2), nunca en texto plano
            User.objects.create_user(
                username=data['email'],
                email=data['email'],
                first_name=data['nombre'],
                password=data['password'],
            )
            messages.success(request, '¡Cuenta creada con éxito! Ya puedes iniciar sesión.')
            return redirect('login')
    else:
        form = RegisterForm()

    return render(request, 'loginRegister/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email'].strip().lower()
            password = form.cleaned_data['password']
            ip = get_client_ip(request)
            now = timezone.now()

            # CA-05.1, CA-05.2: verificar bloqueo por intentos fallidos
            attempt = LoginAttempt.objects.filter(email=email, ip_address=ip).first()
            if attempt and attempt.blocked_until:
                if attempt.blocked_until > now:
                    messages.error(
                        request,
                        'Demasiados intentos fallidos. Tu cuenta está temporalmente bloqueada. Intenta de nuevo más tarde.'
                    )
                    return render(request, 'loginRegister/login.html', {'form': form})
                else:
                    # El período de bloqueo expiró (CA-05.4)
                    attempt.failed_attempts = 0
                    attempt.blocked_until = None
                    attempt.save()

            user = authenticate(
                request,
                username=email,
                password=password,
            )
            if user is not None:
                # CA-05.5: login exitoso reinicia el contador
                if attempt:
                    attempt.delete()
                login(request, user)
                next_url = request.GET.get('next')
                if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                    return redirect(next_url)
                return redirect('home')

            # CA-05.1, CA-05.2: registrar intento fallido
            if not attempt:
                attempt = LoginAttempt(email=email, ip_address=ip, failed_attempts=1)
            else:
                if now - attempt.last_attempt > timedelta(minutes=15):
                    attempt.failed_attempts = 1
                else:
                    attempt.failed_attempts += 1

            if attempt.failed_attempts >= 5:
                attempt.blocked_until = now + timedelta(minutes=15)
                attempt.save()
                messages.error(
                    request,
                    'Demasiados intentos fallidos. Tu cuenta está temporalmente bloqueada. Intenta de nuevo más tarde.'
                )
            else:
                attempt.save()
                # Mensaje genérico: no revela si falló el correo o la contraseña (CA-02.3)
                messages.error(request, 'Correo o contraseña incorrectos.')
    else:
        form = LoginForm()

    return render(request, 'loginRegister/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


def password_reset_request_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.filter(username__iexact=email).first()
            if user:
                token = default_token_generator.make_token(user)
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = request.build_absolute_uri(
                    reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})
                )
                send_mail(
                    subject='Recuperación de contraseña',
                    message=f'Hola {user.first_name or user.email},\n\nPara restablecer tu contraseña, ingresa al siguiente enlace:\n{reset_url}\n\nEste enlace expirará en 30 minutos.\nSi no solicitaste este cambio, puedes ignorar este mensaje.',
                    from_email=None,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
            # Mensaje genérico independientemente de si el correo existe (CA-03.2)
            messages.success(request, 'Si el correo está registrado, recibirás un enlace de recuperación.')
            return redirect('login')
    else:
        form = PasswordResetRequestForm()

    return render(request, 'loginRegister/password_reset_request.html', {'form': form})


def password_reset_confirm_view(request, uidb64, token):
    if request.user.is_authenticated:
        return redirect('home')

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is None or not default_token_generator.check_token(user, token):
        messages.error(request, 'El enlace de recuperación es inválido o ha expirado.')
        return redirect('password_reset_request')

    if request.method == 'POST':
        form = SetPasswordForm(request.POST)
        if form.is_valid():
            # set_password hashea la nueva contraseña y revoca el token automáticamente (CA-03.6, CA-03.7)
            user.set_password(form.cleaned_data['password'])
            user.save()
            messages.success(request, 'Tu contraseña ha sido restablecida con éxito. Ya puedes iniciar sesión.')
            return redirect('login')
    else:
        form = SetPasswordForm()

    return render(request, 'loginRegister/password_reset_confirm.html', {'form': form})


@never_cache
@login_required  # CA-02.6: sin sesión, redirige al login
def home_view(request):
    return render(request, 'loginRegister/home.html')