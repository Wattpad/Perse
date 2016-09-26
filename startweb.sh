#!/bin/bash

sleep 5  # sleep because the db might not be running yet
python manage.py collectstatic --noinput
python manage.py makemigrations
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
