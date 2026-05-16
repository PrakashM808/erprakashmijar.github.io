"""
scheduler.py — Automatic scheduled scans using APScheduler
Runs scans on a cron schedule and sends email alerts
"""
import json
import logging
from datetime import datetime
from typing import Callable
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

# In-memory schedule store (upgrade to DB for production)
_schedules: dict = {}   # schedule_id -> schedule config
_scheduler = AsyncIOScheduler()

# ── SCHEDULE MANAGEMENT ──────────────────────────────────────────

def add_schedule(
    schedule_id: str,
    device_config: dict,
    cron_expression: str,
    alert_email: str,
    scan_fn: Callable,
    alert_fn: Callable
) -> dict:
    """
    Add a scheduled scan job.
    cron_expression: e.g. "0 9 * * *" = daily at 9am
                         "0 */6 * * *" = every 6 hours
                         "0 9 * * 1" = every Monday at 9am
    """
    # Parse cron
    parts = cron_expression.strip().split()
    if len(parts) != 5:
        return {"ok": False, "error": "Invalid cron expression. Format: minute hour day month weekday (e.g. '0 9 * * *')"}

    minute, hour, day, month, day_of_week = parts

    async def job():
        logger.info(f"Running scheduled scan for {device_config.get('host','localhost')}")
        try:
            if device_config.get("type") == "local":
                from scanner import local_scan
                result = local_scan()
            else:
                from scanner import remote_scan
                result = remote_scan(**{k:v for k,v in device_config.items() if k != "type"})

            _schedules[schedule_id]["last_run"] = datetime.now().isoformat()
            _schedules[schedule_id]["last_score"] = result.get("security_score", 0)
            _schedules[schedule_id]["run_count"] = _schedules[schedule_id].get("run_count", 0) + 1

            # Send alert if issues found
            if alert_email and result.get("issues"):
                critical = [i for i in result["issues"] if i.get("severity") == "critical"]
                high     = [i for i in result["issues"] if i.get("severity") == "high"]
                if critical or high:
                    alert_fn(alert_email, result)
                    logger.info(f"Alert sent to {alert_email} for {device_config.get('host')}")
        except Exception as e:
            logger.error(f"Scheduled scan failed: {e}")
            _schedules[schedule_id]["last_error"] = str(e)

    try:
        trigger = CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)
        _scheduler.add_job(job, trigger, id=schedule_id, replace_existing=True, name=f"scan-{device_config.get('host','local')}")
        _schedules[schedule_id] = {
            "id": schedule_id,
            "device": device_config,
            "cron": cron_expression,
            "alert_email": alert_email,
            "created_at": datetime.now().isoformat(),
            "last_run": None,
            "last_score": None,
            "run_count": 0,
            "active": True,
            "next_run": str(_scheduler.get_job(schedule_id).next_run_time) if _scheduler.get_job(schedule_id) else None
        }
        return {"ok": True, "schedule_id": schedule_id, "next_run": _schedules[schedule_id]["next_run"]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def remove_schedule(schedule_id: str) -> bool:
    try:
        _scheduler.remove_job(schedule_id)
        _schedules.pop(schedule_id, None)
        return True
    except:
        return False

def pause_schedule(schedule_id: str) -> bool:
    try:
        _scheduler.pause_job(schedule_id)
        if schedule_id in _schedules:
            _schedules[schedule_id]["active"] = False
        return True
    except:
        return False

def resume_schedule(schedule_id: str) -> bool:
    try:
        _scheduler.resume_job(schedule_id)
        if schedule_id in _schedules:
            _schedules[schedule_id]["active"] = True
        return True
    except:
        return False

def get_all_schedules() -> list:
    result = []
    for sid, s in _schedules.items():
        job = _scheduler.get_job(sid)
        s_copy = s.copy()
        s_copy["next_run"] = str(job.next_run_time) if job and job.next_run_time else None
        result.append(s_copy)
    return result

def get_schedule(schedule_id: str) -> dict:
    return _schedules.get(schedule_id)

# ── CRON PRESETS ─────────────────────────────────────────────────
CRON_PRESETS = {
    "every_hour":    {"cron": "0 * * * *",      "label": "Every hour"},
    "every_6h":      {"cron": "0 */6 * * *",    "label": "Every 6 hours"},
    "every_12h":     {"cron": "0 */12 * * *",   "label": "Every 12 hours"},
    "daily_9am":     {"cron": "0 9 * * *",      "label": "Daily at 9:00 AM"},
    "daily_midnight":{"cron": "0 0 * * *",      "label": "Daily at midnight"},
    "weekly_monday": {"cron": "0 9 * * 1",      "label": "Every Monday at 9:00 AM"},
    "weekly_friday": {"cron": "0 17 * * 5",     "label": "Every Friday at 5:00 PM"},
    "monthly":       {"cron": "0 9 1 * *",      "label": "Monthly (1st of month)"},
}

# ── LIFECYCLE ────────────────────────────────────────────────────
def start_scheduler():
    if not _scheduler.running:
        _scheduler.start()
        logger.info("APScheduler started")

def stop_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")
