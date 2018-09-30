# project/server/auth/views.py

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User, BlacklistToken, Products

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    def post(self):
        # Needed to add this check due to change in request type.
        # When running unit tests, requests come in as a dict
        # However, in server mode, requests come in as ImmutableMultiDict
        if type(request.get_json()) is dict:
            post_data = request.get_json()
            user = User.query.filter_by(email=post_data.get('email')).first()
            email=post_data.get('email')
            password=post_data.get('password')

        else:
            # get the post data
            post_data = (request.get_json() or request.form).to_dict(flat=False)
            # check if user already exists
            user = User.query.filter_by(email=post_data.get('email')[0]).first()
            email=post_data.get('email')[0],
            password=post_data.get('password')[0]
        
        if not user:
            try:
                user = User(
                    email=email,
                    password=password
                )

                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                auth_token = user.encode_auth_token(user.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(responseObject)), 202

class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # Needed to add this check due to change in request type.
        # When running unit tests, requests come in as a dict
        # However, in server mode, requests come in as ImmutableMultiDict
        if type(request.get_json()) is dict:
            post_data = request.get_json()
            user = User.query.filter_by(email=post_data.get('email')).first()
            email=post_data.get('email')
            password=post_data.get('password')

        else:
            # get the post data
            post_data = (request.get_json() or request.form).to_dict(flat=False)
            # check if user already exists
            user = User.query.filter_by(email=post_data.get('email')[0]).first()
            email=post_data.get('email')[0],
            password=post_data.get('password')[0]

        try:
            # fetch the user data
            user = User.query.filter_by(
                email=email
            ).first()
            if user and bcrypt.check_password_hash(
                user.password, password
            ):
                auth_token = user.encode_auth_token(user.id)
                if auth_token:
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'auth_token': auth_token.decode()
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(responseObject)), 404
        except Exception as e:
            print(e)
            responseObject = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(responseObject)), 500

class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                responseObject = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                responseObject = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(responseObject)), 200
            responseObject = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 401

class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)
                try:
                    # insert the token
                    db.session.add(blacklist_token)
                    db.session.commit()
                    responseObject = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(responseObject)), 200
                except Exception as e:
                    responseObject = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(responseObject)), 403


class ProductAPI(MethodView):
    """
    Product Resource
    """
    def post(self):
        # Needed to add this check due to change in request type.
        # When running unit tests, requests come in as a dict
        # However, in server mode, requests come in as ImmutableMultiDict
        if type(request.get_json()) is dict:
            post_data = request.get_json()
            product = Products.query.filter_by(code=post_data.get('code')).first()
            code=post_data.get('code')
            ProductType=post_data.get('type')
            quantity=post_data.get('quantity')

        else:
            # get the post data
            post_data = (request.get_json() or request.form).to_dict(flat=False)
            # check if user already exists
            product = Products.query.filter_by(code=post_data.get('code')[0]).first()
            code=post_data.get('code')[0]
            ProductType=post_data.get('type')[0],
            quantity=post_data.get('quantity')[0]

        if not product:
            try:
                product = Products(
                	code = code,
                    type= ProductType,
                    quantity= quantity
                )

                # insert the product
                db.session.add(product)
                db.session.commit()
                # generate the auth token
                auth_token = product.encode_auth_token(product.id)
                responseObject = {
                    'status': 'success',
                    'message': 'Successfully added.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(responseObject)), 201
            except Exception as e:
                responseObject = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(responseObject)), 401
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Product already exists. Please try with another product.',
            }
            return make_response(jsonify(responseObject)), 404


class InventoryAPI(MethodView):
    """
    Inventory Resource
    """
    def get(self):
        if request.headers.get("code"):
            code = request.headers.get("code")
            #check if product already exists
            product = Products.query.filter_by(code=code).first()
            if product:
                responseObject = {
                    'status': 'success',
                    'data': {
                        'code': product.code,
                    },
                    'message': 'Product found in inventory.'
                }
                return make_response(jsonify(responseObject)), 200
            else:
                responseObject = {
                    'status': 'fail',
                    'message': 'Product does not exist in inventory.',
                }
                return make_response(jsonify(responseObject)), 404
        else:
            type =  request.headers.get("type")
            #check if product already exists
            product = Products.query.filter_by(type=type).all()
            if len(product) == 2:
                responseObject = {
                    'status': 'success',
                    'message': 'Products retrieved successfully.'
                }
                return make_response(jsonify(responseObject)), 200

    def put(self):
        code = request.headers.get("code")
        newcode = request.headers.get("newcode")
        #check if product already exists
        product = Products.query.filter_by(code=code).first()
        if product:
            product.code = newcode
            db.session.add(product)
            db.session.commit()
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Product does not exist in inventory.',
            }
            return make_response(jsonify(responseObject)), 404

        newproduct = Products.query.filter_by(code=newcode).first()
        if newproduct:
            responseObject = {
                'status': 'success',
                'data': {
                    'code': product.code,
                },
                'message': 'Product edited successfully.'
            }
            return make_response(jsonify(responseObject)), 200

    def delete(self):
        code = request.headers.get("code")
        #check if product already exists
        product = Products.query.filter_by(code=code).first()
        if product:
            Products.query.filter_by(code=code).delete()
            db.session.commit()
        else:
            responseObject = {
                'status': 'fail',
                'message': 'Product delete failed. Product does not exist in inventory.'
            }
            return make_response(jsonify(responseObject)), 404

        product = Products.query.filter_by(code=code).first()
        if product is None:
            responseObject = {
                'status': 'success',
                'message': 'Product deleted successfully.'
            }
            return make_response(jsonify(responseObject)), 200



# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')
product_view = ProductAPI.as_view('product_api')
inventory_view = InventoryAPI.as_view('inventory_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/account',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/products',
    view_func=product_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/auth/inventory',
    view_func=inventory_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/auth/inventory',
    view_func=inventory_view,
    methods=['PUT']
)
auth_blueprint.add_url_rule(
    '/auth/inventory',
    view_func=inventory_view,
    methods=['DELETE']
)