# home24 Test Task for Software Engineer

## Task
Create a small REST API having several endpoints:
1. /token - an endpoint that will be used to create an authorisation token using email
and password.
2. /entities - an endpoint having CRUD functionality (use any entity structure you like).
3. /account - an endpoint returning account information identified by authorisation token.

## Instructions
$ python -m venv env
$ source flask-jwt-auth/env/Scripts/activate
$ pip install -r flask-jwt-auth/requirements.txt