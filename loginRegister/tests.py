from datetime import timedelta
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.contrib.messages import get_messages
from django.core import mail
from django.conf import settings
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import LoginAttempt

User = get_user_model()


class RegisterTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_ca_01_registro_exitoso_y_hashing(self):
        response = self.client.post(reverse('register'), {
            'nombre': 'Carlos Perez',
            'email': 'carlos@example.com',
            'password': 'Password123',
            'password2': 'Password123',
        })
        self.assertRedirects(response, reverse('login'))
        user = User.objects.get(email='carlos@example.com')
        self.assertEqual(user.first_name, 'Carlos Perez')
        self.assertNotEqual(user.password, 'Password123')
        self.assertTrue(user.check_password('Password123'))


class LoginTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='carlos@example.com',
            email='carlos@example.com',
            first_name='Carlos',
            password='Password123',
        )

    def test_ca_02_login_exitoso_y_redireccion_privada(self):
        response = self.client.post(reverse('login'), {
            'email': 'carlos@example.com',
            'password': 'Password123',
        })
        self.assertRedirects(response, reverse('home'))

    def test_ca_02_credenciales_invalidas_mensaje_generico(self):
        response = self.client.post(reverse('login'), {
            'email': 'carlos@example.com',
            'password': 'WrongPassword123',
        })
        self.assertEqual(response.status_code, 200)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Correo o contraseña incorrectos' in str(m) for m in messages))

    def test_ca_02_6_visitante_no_autenticado_no_accede_a_privado(self):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('login')))


class LogoutTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='usuario@example.com',
            email='usuario@example.com',
            first_name='Juan',
            password='Password123',
        )

    def test_ca_04_1_opcion_cerrar_sesion_visible_para_usuario_autenticado(self):
        self.client.login(username='usuario@example.com', password='Password123')
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse('logout'))
        self.assertContains(response, 'Cerrar sesión')

    def test_ca_04_2_y_ca_04_3_logout_invalida_sesion_y_redirige_a_login(self):
        self.client.login(username='usuario@example.com', password='Password123')
        response = self.client.post(reverse('logout'))
        self.assertRedirects(response, reverse('login'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_ca_04_4_no_acceso_a_paginas_privadas_tras_cerrar_sesion(self):
        self.client.login(username='usuario@example.com', password='Password123')
        self.client.post(reverse('logout'))
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('login')))

    def test_ca_04_4_cabeceras_no_cache_en_pagina_privada(self):
        self.client.login(username='usuario@example.com', password='Password123')
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        cache_control = response.headers.get('Cache-Control', '')
        self.assertIn('no-cache', cache_control)
        self.assertIn('no-store', cache_control)


class PasswordResetTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='carlos@example.com',
            email='carlos@example.com',
            first_name='Carlos',
            password='OldPassword123',
        )

    def test_ca_03_1_y_ca_03_2_solicitud_muestra_mensaje_generico(self):
        # Con correo registrado
        res1 = self.client.post(reverse('password_reset_request'), {'email': 'carlos@example.com'})
        self.assertRedirects(res1, reverse('login'))
        msgs1 = [str(m) for m in get_messages(res1.wsgi_request)]
        self.assertTrue(any('Si el correo está registrado' in m for m in msgs1))

        # Con correo no registrado
        res2 = self.client.post(reverse('password_reset_request'), {'email': 'noexiste@example.com'})
        self.assertRedirects(res2, reverse('login'))
        msgs2 = [str(m) for m in get_messages(res2.wsgi_request)]
        self.assertEqual(msgs1, msgs2)

    def test_ca_03_3_envio_correo_con_enlace_solo_si_existe(self):
        mail.outbox = []
        self.client.post(reverse('password_reset_request'), {'email': 'carlos@example.com'})
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('restablecer-password', mail.outbox[0].body)
        self.assertEqual(mail.outbox[0].to, ['carlos@example.com'])

        mail.outbox = []
        self.client.post(reverse('password_reset_request'), {'email': 'noexiste@example.com'})
        self.assertEqual(len(mail.outbox), 0)

    def test_ca_03_4_configuracion_timeout_30_minutos(self):
        self.assertEqual(settings.PASSWORD_RESET_TIMEOUT, 1800)

    def test_ca_03_5_validacion_seguridad_nueva_contrasena(self):
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        url = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})

        # Contraseña debil (sin mayuscula ni digito)
        res = self.client.post(url, {'password': 'password', 'password2': 'password'})
        self.assertEqual(res.status_code, 200)
        self.assertFormError(res.context['form'], 'password', 'La contraseña debe tener una mayúscula, un número.')

        # Contraseñas no coinciden
        res = self.client.post(url, {'password': 'NewPassword123', 'password2': 'Diferente123'})
        self.assertEqual(res.status_code, 200)
        self.assertFormError(res.context['form'], 'password2', 'Las contraseñas no coinciden.')

    def test_ca_03_6_y_ca_03_7_reset_exitoso_invalida_token_y_cambia_password(self):
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        url = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})

        # Cambio exitoso
        res = self.client.post(url, {
            'password': 'NewPassword123',
            'password2': 'NewPassword123',
        })
        self.assertRedirects(res, reverse('login'))

        # CA-03.6: El token queda invalidado
        self.user.refresh_from_db()
        self.assertFalse(default_token_generator.check_token(self.user, token))

        # Reusar el mismo enlace falla
        res_reuso = self.client.get(url)
        self.assertRedirects(res_reuso, reverse('password_reset_request'))

        # CA-03.7: Contraseña anterior no funciona y nueva sí funciona
        user_old = authenticate(username='carlos@example.com', password='OldPassword123')
        self.assertIsNone(user_old)

        user_new = authenticate(username='carlos@example.com', password='NewPassword123')
        self.assertIsNotNone(user_new)


class RateLimitLoginTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='bloqueo@example.com',
            email='bloqueo@example.com',
            first_name='Carlos',
            password='Password123',
        )
        self.login_url = reverse('login')
        self.ip = '192.168.1.10'

    def _login_fallido(self, ip='192.168.1.10', email='bloqueo@example.com'):
        return self.client.post(
            self.login_url,
            {'email': email, 'password': 'WrongPassword'},
            REMOTE_ADDR=ip,
        )

    def test_ca_05_1_y_ca_05_2_bloqueo_al_quinto_intento_fallido(self):
        # Primeros 4 intentos fallidos: error de credenciales
        for _ in range(4):
            res = self._login_fallido()
            self.assertEqual(res.status_code, 200)
            msgs = [str(m) for m in get_messages(res.wsgi_request)]
            self.assertTrue(any('Correo o contraseña incorrectos' in m for m in msgs))

        # Intento 5: activa el bloqueo
        res5 = self._login_fallido()
        self.assertEqual(res5.status_code, 200)
        msgs5 = [str(m) for m in get_messages(res5.wsgi_request)]
        self.assertTrue(any('temporalmente bloqueada' in m for m in msgs5))

        # Registro en BD
        attempt = LoginAttempt.objects.get(email='bloqueo@example.com', ip_address=self.ip)
        self.assertEqual(attempt.failed_attempts, 5)
        self.assertIsNotNone(attempt.blocked_until)
        self.assertGreater(attempt.blocked_until, timezone.now())

        # Intento 6 (incluso con contraseña correcta): permanece bloqueado
        res6 = self.client.post(
            self.login_url,
            {'email': 'bloqueo@example.com', 'password': 'Password123'},
            REMOTE_ADDR=self.ip,
        )
        self.assertEqual(res6.status_code, 200)
        msgs6 = [str(m) for m in get_messages(res6.wsgi_request)]
        self.assertTrue(any('temporalmente bloqueada' in m for m in msgs6))

    def test_ca_05_1_combinacion_cuenta_e_ip_independientes(self):
        # 5 intentos fallidos desde IP 1
        for _ in range(5):
            self._login_fallido(ip='192.168.1.10')

        # Desde otra IP, el usuario aún puede intentar autenticarse con éxito
        res_otra_ip = self.client.post(
            self.login_url,
            {'email': 'bloqueo@example.com', 'password': 'Password123'},
            REMOTE_ADDR='192.168.1.20',
        )
        self.assertRedirects(res_otra_ip, reverse('home'))

    def test_ca_05_4_desbloqueo_despues_de_15_minutos(self):
        # Simular registro con bloqueo expirado (hace más de 15 minutos)
        LoginAttempt.objects.create(
            email='bloqueo@example.com',
            ip_address=self.ip,
            failed_attempts=5,
            blocked_until=timezone.now() - timedelta(minutes=1),
        )

        # Puede volver a intentar con credenciales correctas
        res = self.client.post(
            self.login_url,
            {'email': 'bloqueo@example.com', 'password': 'Password123'},
            REMOTE_ADDR=self.ip,
        )
        self.assertRedirects(res, reverse('home'))

    def test_ca_05_5_login_exitoso_reinicia_contador(self):
        # 3 intentos fallidos
        for _ in range(3):
            self._login_fallido()

        attempt = LoginAttempt.objects.get(email='bloqueo@example.com', ip_address=self.ip)
        self.assertEqual(attempt.failed_attempts, 3)

        # Login exitoso
        res = self.client.post(
            self.login_url,
            {'email': 'bloqueo@example.com', 'password': 'Password123'},
            REMOTE_ADDR=self.ip,
        )
        self.assertRedirects(res, reverse('home'))

        # Contador reiniciado (registro eliminado o puesto en 0)
        self.assertFalse(
            LoginAttempt.objects.filter(email='bloqueo@example.com', ip_address=self.ip).exists()
        )


