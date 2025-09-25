#!/usr/bin/env bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --timeout 120 --access-logfile - --error-logfile -
