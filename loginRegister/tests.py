from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages

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


