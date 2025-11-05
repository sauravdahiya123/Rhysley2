from celery import shared_task
from .cron import send_pending_reminders

@shared_task
def send_reminders_task():
    send_pending_reminders()
