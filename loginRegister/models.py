from django.db import models


class LoginAttempt(models.Model):
    email = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    failed_attempts = models.PositiveIntegerField(default=0)
    last_attempt = models.DateTimeField(auto_now=True)
    blocked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('email', 'ip_address')

