# project/tests/test_auth.py

import unittest
import json
import time


from project.server import db
from project.server.models import User, BlacklistToken, Products
from project.tests.base import BaseTestCase

def register_user(self, email, password):
    return self.client.post(
        '/auth/register',
        data=json.dumps(dict(
            email=email,
            password=password
        )),
        content_type='application/json',
    )


class TestAuthBlueprint(BaseTestCase):

    def test_registration(self):
	    """ Test for user registration """
	    with self.client:
	        response = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
	        data = json.loads(response.data.decode())
	        self.assertTrue(data['status'] == 'success')
	        self.assertTrue(data['message'] == 'Successfully registered.')
	        self.assertTrue(data['auth_token'])
	        self.assertTrue(response.content_type == 'application/json')
	        self.assertEqual(response.status_code, 201)

    def test_registered_with_already_registered_user(self):
    	""" Test registration with already registered email """
    	user = User(
    	    email='mohamedtosman@cmail.carleton.ca',
    	    password='test'
    	)
    	db.session.add(user)
    	db.session.commit()
    	with self.client:
    	    response = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
    	    data = json.loads(response.data.decode())
    	    self.assertTrue(data['status'] == 'fail')
    	    self.assertTrue(
    	        data['message'] == 'User already exists. Please Log in.')
    	    self.assertTrue(response.content_type == 'application/json')
    	    self.assertEqual(response.status_code, 202)

    def test_registered_user_login(self):
        """ Test for login of registered-user login """
        with self.client:
            # user registration
            resp_register = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.'
            )
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # registered user login
            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='mohamedtosman@cmail.carleton.ca',
                    password='123456'
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged in.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_non_registered_user_login(self):
        """ Test for login of non-registered user """
        with self.client:
            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='mohamedtosman@cmail.carleton.ca',
                    password='123456'
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'User does not exist.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)

    def test_user_status(self):
        """ Test for user status """
        with self.client:
            resp_register = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
            response = self.client.get(
                '/auth/account',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_register.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['data'] is not None)
            self.assertTrue(data['data']['email'] == 'mohamedtosman@cmail.carleton.ca')
            self.assertTrue(data['data']['admin'] is 'true' or 'false')
            self.assertEqual(response.status_code, 200)

    def test_valid_logout(self):
        """ Test for logout before token expires """
        with self.client:
            # user registration
            resp_register = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # user login
            resp_login = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='mohamedtosman@cmail.carleton.ca',
                    password='123456'
                )),
                content_type='application/json'
            )
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, 200)
            # valid token logout
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully logged out.')
            self.assertEqual(response.status_code, 200)

    def test_invalid_logout(self):
        """ Testing logout after the token expires """
        with self.client:
            # user registration
            resp_register = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # user login
            resp_login = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='mohamedtosman@cmail.carleton.ca',
                    password='123456'
                )),
                content_type='application/json'
            )
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, 200)
            # invalid token logout
            time.sleep(6)
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Signature expired. Please log in again.')
            self.assertEqual(response.status_code, 401)


    def test_valid_blacklisted_token_logout(self):
        """ Test for logout after a valid token gets blacklisted """
        with self.client:
            # user registration
            resp_register = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['status'] == 'success')
            self.assertTrue(
                data_register['message'] == 'Successfully registered.')
            self.assertTrue(data_register['auth_token'])
            self.assertTrue(resp_register.content_type == 'application/json')
            self.assertEqual(resp_register.status_code, 201)
            # user login
            resp_login = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='mohamedtosman@cmail.carleton.ca',
                    password='123456'
                )),
                content_type='application/json'
            )
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['status'] == 'success')
            self.assertTrue(data_login['message'] == 'Successfully logged in.')
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(resp_login.content_type == 'application/json')
            self.assertEqual(resp_login.status_code, 200)
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(resp_login.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            # blacklisted valid token logout
            response = self.client.post(
                '/auth/logout',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_login.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token blacklisted. Please log in again.')
            self.assertEqual(response.status_code, 401)

    def test_decode_auth_token(self):
        """ Test for decoding authentication token """
        user = User(
            email='test@test.com',
            password='test'
        )
        db.session.add(user)
        db.session.commit()
        auth_token = user.encode_auth_token(user.id)
        self.assertTrue(isinstance(auth_token, bytes))
        self.assertTrue(User.decode_auth_token(
            auth_token.decode("utf-8") ) == 1)

    def test_valid_blacklisted_token_user(self):
        """ Test for user status with a blacklisted valid token """
        with self.client:
            resp_register = self.client.post(
                '/auth/register',
                data=json.dumps(dict(
                    email='mohamedtosman@cmail.carleton.ca',
                    password='123456'
                )),
                content_type='application/json'
            )
            # blacklist a valid token
            blacklist_token = BlacklistToken(
                token=json.loads(resp_register.data.decode())['auth_token'])
            db.session.add(blacklist_token)
            db.session.commit()
            response = self.client.get(
                '/auth/account',
                headers=dict(
                    Authorization='Bearer ' + json.loads(
                        resp_register.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Token blacklisted. Please log in again.')
            self.assertEqual(response.status_code, 401)

    def test_user_status_malformed_bearer_token(self):
        """ Test for user status with malformed bearer token """
        with self.client:
            resp_register = register_user(self, 'mohamedtosman@cmail.carleton.ca', '123456')
            response = self.client.get(
                '/auth/account',
                headers=dict(
                    Authorization='Bearer' + json.loads(
                        resp_register.data.decode()
                    )['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(data['message'] == 'Bearer token malformed.')
            self.assertEqual(response.status_code, 401)

    def test_add_product(self):
        """ Test for adding product """
        with self.client:
            response = self.client.post(
                '/auth/products',
                data=json.dumps(dict(
                    code="123xx",
                    type='chair',
                    quantity=1
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(data['message'] == 'Successfully added.')
            self.assertTrue(data['auth_token'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 201)

    def test_adding_already_added_product(self):
        """ Test adding a product code that already exists """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.post(
                '/auth/products',
                data=json.dumps(dict(
                    code="123xx",
                    type='chair',
                    quantity=1
                )),
                content_type='application/json'
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Product already exists. Please try with another product.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)

    def test_getting_product(self):
        """ Test getting product with specific code """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.get(
                '/auth/inventory',
                headers=dict(
                    code="123xx"
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(
                data['message'] == 'Product found in inventory.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_getting_all_product(self):
        """ Test getting all products matching specific type """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        product2 = Products(
            code="123yy",
            type='chair',
            quantity=2
        )
        db.session.add(product2)
        db.session.commit()
        with self.client:
            response = self.client.get(
                '/auth/inventory',
                headers=dict(
                    type='chair'
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(
                data['message'] == 'Products retrieved successfully.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_getting_product_not_exist(self):
        """ Test getting product code that does not exist """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.get(
                '/auth/inventory',
                headers=dict(
                    code="xxxx"
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Product does not exist in inventory.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)


    def test_edit_product(self):
        """ Test editing product code """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.put(
                '/auth/inventory',
                headers=dict(
                    code="123xx",
                    newcode="123yy"
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(
                data['message'] == 'Product edited successfully.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_edit_product_not_exist(self):
        """ Test editing product code that does not exist """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.put(
                '/auth/inventory',
                headers=dict(
                    code="123yy",
                    newcode="123zz"
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Product does not exist in inventory.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)

    def test_delete_product(self):
        """ Test delete product with specific code """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.delete(
                '/auth/inventory',
                headers=dict(
                    code="123xx"
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'success')
            self.assertTrue(
                data['message'] == 'Product deleted successfully.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_delete_product_failed(self):
        """ Test deleting product with code that does not exist """
        product = Products(
            code="123xx",
            type='chair',
            quantity=1
        )
        db.session.add(product)
        db.session.commit()
        with self.client:
            response = self.client.delete(
                '/auth/inventory',
                headers=dict(
                    code="123yy"
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['status'] == 'fail')
            self.assertTrue(
                data['message'] == 'Product delete failed. Product does not exist in inventory.')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()