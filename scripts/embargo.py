#!/usr/bin/env python3
"""Exact two-UTC-calendar-month embargo calculations."""

from __future__ import annotations

import calendar
import datetime as dt

UTC_MILLISECONDS = "%Y-%m-%dT%H:%M:%S.%fZ"


def parse_utc_milliseconds(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.strptime(value, UTC_MILLISECONDS).replace(tzinfo=dt.UTC)
    except ValueError as error:
        raise ValueError("timestamp must be canonical UTC with milliseconds") from error
    if format_utc_milliseconds(parsed) != value:
        raise ValueError("timestamp must be canonical UTC with milliseconds")
    return parsed


def format_utc_milliseconds(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
        raise ValueError("timestamp must be UTC-aware")
    return value.strftime(UTC_MILLISECONDS)[:-4] + "Z"


def add_calendar_months(value: dt.datetime, months: int) -> dt.datetime:
    if months < 0:
        raise ValueError("months must be nonnegative")
    month_index = value.year * 12 + value.month - 1 + months
    year, zero_based_month = divmod(month_index, 12)
    month = zero_based_month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def eligible_at(accepted_at: str) -> str:
    return format_utc_milliseconds(add_calendar_months(parse_utc_milliseconds(accepted_at), 2))


def is_eligible(accepted_at: str, as_of: str) -> bool:
    return parse_utc_milliseconds(as_of) >= parse_utc_milliseconds(eligible_at(accepted_at))
