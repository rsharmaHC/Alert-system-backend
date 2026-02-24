from celery import Celery
from app.config import settings

celery_app = Celery(
    "tm_alert",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="America/New_York",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "process-scheduled-notifications": {
            "task": "app.tasks.process_scheduled_notifications",
            "schedule": 60.0,  # every 60 seconds
        },
    },
)
