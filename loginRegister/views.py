from django.shortcuts import render

# Create your views here.
from django.contrib import messages
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.utils.http import url_has_allowed_host_and_scheme

from .forms import RegisterForm, LoginForm

User = get_user_model()


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
            user = authenticate(
                request,
                username=form.cleaned_data['email'].strip().lower(),
                password=form.cleaned_data['password'],
            )
            if user is not None:
                login(request, user)
                next_url = request.GET.get('next')
                if next_url and url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                    return redirect(next_url)
                return redirect('home')
            # Mensaje genérico: no revela si falló el correo o la contraseña (CA-02.3)
            messages.error(request, 'Correo o contraseña incorrectos.')
    else:
        form = LoginForm()

    return render(request, 'loginRegister/login.html', {'form': form})


@login_required  # CA-02.6: sin sesión, redirige al login
def home_view(request):
    return render(request, 'loginRegister/home.html')