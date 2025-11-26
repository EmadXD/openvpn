#!/usr/bin/env bash

BIN="$1"

# اگر فایل نیست → false
[[ -f "$BIN" ]] || { echo false; exit; }

# اگر اجراپذیر نیست → false
[[ -x "$BIN" ]] || { echo false; exit; }

# تست اجرای کمک
if "$BIN" --help >/dev/null 2>&1 || "$BIN" --version >/dev/null 2>&1; then
    echo true
else
    echo false
fi
