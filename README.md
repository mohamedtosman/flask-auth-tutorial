# home24 Test Task for Software Engineer

## Task
Create a small REST API having several endpoints:
1. /token - an endpoint that will be used to create an authorisation token using email
and password.
2. /entities - an endpoint having CRUD functionality (use any entity structure you like).
3. /account - an endpoint returning account information identified by authorisation token.

## Prerequisites
Python3.x
Psql

## Instructions
Clone the repo
'$ git clone https://github.com/mohamedtosman/home24.git'
Activate a virtual environment
'''
$ cd flask-jwt-auth/
$ python -m venv env
$ source env/Scripts/activate
'''

Install dependencies
'(env)$ pip install -r requirements.txt'

Create databases (You need to have psql installed)
'''
(env)$ psql
# create database flask_jwt_auth;
CREATE DATABASE
# create database flask_jwt_auth_test;
CREATE DATABASE
# \q
'''

Set environment variables in terminal:
'(env)$ export APP_SETTINGS="project.server.config.DevelopmentConfig"'

Confirm you see the following in psql
'''
postgres=# \c flask_jwt_auth
WARNING: Console code page (437) differs from Windows code page (1252)
         8-bit characters might not work correctly. See psql reference
         page "Notes for Windows users" for details.
You are now connected to database "flask_jwt_auth" as user "postgres".
flask_jwt_auth=# \d
                   List of relations
 Schema |          Name           |   Type   |  Owner
--------+-------------------------+----------+----------
 public | alembic_version         | table    | postgres
 public | blacklist_tokens        | table    | postgres
 public | blacklist_tokens_id_seq | sequence | postgres
 public | products                | table    | postgres
 public | products_id_seq         | sequence | postgres
 public | users                   | table    | postgres
 public | users_id_seq            | sequence | postgres
(7 rows)
'''

In a python shell, generate a random key
'''
>>> import os
>>> os.urandom(24)
b"C~\xf8\xb2\x9e\xf7=3\xfb\x85\xc3=-\xa8Y}+[Rx)\xbb9\x0c"
'''

In a shell, set they key as a secret key environment variable
'(env)$ export SECRET_KEY="C~\xf8\xb2\x9e\xf7=3\xfb\x85\xc3=-\xa8Y}+[Rx)\xbb9\x0c"'

Run the following command to execute the unit tests found in flask-jwt-auth\project\tests\test_auth.py
'(env)$ python manage.py test'

## Running the Application
'(env) $ python manage.py runserver'

## Testing
'''
(env)$ python manage.py test
test_app_is_development (project.tests.test__config.TestDevelopmentConfig) ... ok
test_app_is_production (project.tests.test__config.TestProductionConfig) ... ok
test_app_is_testing (project.tests.test__config.TestTestingConfig) ... ok
test_add_product (project.tests.test_auth.TestAuthBlueprint)
Test for adding product ... ok
test_adding_already_added_product (project.tests.test_auth.TestAuthBlueprint)
Test adding a product code that already exists ... ok
test_decode_auth_token (project.tests.test_auth.TestAuthBlueprint)
Test for decoding authentication token ... ok
test_delete_product (project.tests.test_auth.TestAuthBlueprint)
Test delete product with specific code ... ok
test_delete_product_failed (project.tests.test_auth.TestAuthBlueprint)
Test deleting product with code that does not exist ... ok
test_edit_product (project.tests.test_auth.TestAuthBlueprint)
Test editing product code ... ok
test_edit_product_not_exist (project.tests.test_auth.TestAuthBlueprint)
Test editing product code that does not exist ... ok
test_getting_all_product (project.tests.test_auth.TestAuthBlueprint)
Test getting all products matching specific type ... ok
test_getting_product (project.tests.test_auth.TestAuthBlueprint)
Test getting product with specific code ... ok
test_getting_product_not_exist (project.tests.test_auth.TestAuthBlueprint)
Test getting product code that does not exist ... ok
test_invalid_logout (project.tests.test_auth.TestAuthBlueprint)
Testing logout after the token expires ... ok
test_non_registered_user_login (project.tests.test_auth.TestAuthBlueprint)
Test for login of non-registered user ... ok
test_registered_user_login (project.tests.test_auth.TestAuthBlueprint)
Test for login of registered-user login ... ok
test_registered_with_already_registered_user (project.tests.test_auth.TestAuthBlueprint)
Test registration with already registered email ... ok
test_registration (project.tests.test_auth.TestAuthBlueprint)
Test for user registration ... ok
test_user_status (project.tests.test_auth.TestAuthBlueprint)
Test for user status ... ok
test_user_status_malformed_bearer_token (project.tests.test_auth.TestAuthBlueprint)
Test for user status with malformed bearer token ... ok
test_valid_blacklisted_token_logout (project.tests.test_auth.TestAuthBlueprint)
Test for logout after a valid token gets blacklisted ... ok
test_valid_blacklisted_token_user (project.tests.test_auth.TestAuthBlueprint)
Test for user status with a blacklisted valid token ... ok
test_valid_logout (project.tests.test_auth.TestAuthBlueprint)
Test for logout before token expires ... ok
test_decode_auth_token (project.tests.test_user_model.TestUserModel) ... ok
test_encode_auth_token (project.tests.test_user_model.TestUserModel) ... ok

----------------------------------------------------------------------
Ran 25 tests in 18.614s

OK
'''

## API Documentations
**POST: /auth/register**
Register a new user using email and password

Parameters:
'''
email
password
'''

**POST: /auth/login**
Login using email and password

Parameters:
'''
email - string
password - string
'''

**GET: /auth/account**
Get status of the currently logged in user

**POST: /auth/logout**
Logout from current session

Parameters:
'''
email - string
password - string
'''

**POST: /auth/products**
Add new product to product database using code, type, and quantity

Parameters:
'''
code - string
type - string
quantity - integer
'''

**GET: /auth/inventory**
Get single product by passing in it's code or multiple product types by passing in a type

Header:
'''
code - string
'''

OR

Headers:
'''
type - string
'''

**PUT: /auth/inventory**
Edit product in the inventory

Headers:
'''
code - string
newcode - string
'''

**DELETE: /auth/inventory**
Delete product in inventory

Headers:
'''
code - string
newcode - string
'''

## Questions
1. Please explain your choice of technologies.
To be honest, I have never done something like this before. I was learning while working on this task. As I am a huge fan of Python, I chose to develop using Python. Using my bestfriend google, I was able to understand as much as possible about REST, JWT, PSQL, tokens and much more in less than 2 days.

2. What is the difference between PUT and POST methods?
PUT puts data to a specific URI. If there is already data there, then PUT replaces that data with the data in the request. If there is not data in the URI, then PUT creates one.

POST sends data to a specific URI for it to handle the request

Ultimately, PUT is used as an edit for most cases, while POST is used to send data.

3. What approaches would you apply to make your API responding fast?
I could try using multiprocessing. Python has a multiprocessing module that could be useful for that.

4. How would you monitor your API?
I would monitor my API by always enhancing my test cases and finding new technologies that allows a faster response time, etc. With a simple google search, I also found out that there are tons of API monitoring tools that could be useful for that.

5. Which endpoints from the task could by publically cached?
/auth/inventory endpoint can be cached to to allow for faster results when searching for the same product again.