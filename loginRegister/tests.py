from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.contrib.messages import get_messages
from django.core import mail
from django.conf import settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

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


