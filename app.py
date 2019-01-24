import json
import flask
from flask import abort, Response, request, jsonify, send_from_directory,render_template, make_response,send_file
import traceback
from flask_swagger import swagger
import os
from flask_cors import CORS
import sigstore
import io

from flask_jwt_simple import (
    JWTManager, jwt_required, get_jwt
)

app = flask.Flask(__name__, static_url_path='')

CORS(app, resources=r'/*')


jwt_cert = os.getenv('JWT_CERT_FILE', None)
if jwt_cert is None:
    print('must specify JWT_CERT_FILE env variable, exiting')
    exit(1)


def get_file(file):

    try:
        f = open(file, 'r')
        contents = f.read()
        return contents
    except:
        print("\nCouldn't open file " + file)
        exit(1)


# The public key needed for asymmetric based signing algorithms, such as RS* or ES*. PEM format expected.
app.config['JWT_PUBLIC_KEY'] = get_file(jwt_cert)
app.config['JWT_ALGORITHM'] = 'RS256'
jwt = JWTManager(app)


@app.route("/")
def index():
    return 'This is sigstore app.  Please see postman docs at <a href="/swagger-ui/index.html">swagger-ui</a>'


@app.route("/secure")
@jwt_required
def secure_test():
    return "JWT validated!"


@app.route("/spec")
def spec():
    swag = swagger(app)
    swag['info']['version'] = "1.0"
    swag['info']['title'] = "rhc-api-keys"
    resp = flask.Response(response=json.dumps(swag), status=200)
    resp.headers.add('Access-Control-Allow-Origin', '*')
    return resp


@app.route('/swagger-ui/<path:path>')
def send_swagger_ui(path):
    return send_from_directory('swagger-ui', path)


@app.route('/store_signature', methods=['POST'])
@jwt_required
def store_signature():
    """
    store a container signature in the database.

    ---
    security:
        - bearer: []
    parameters:
       - in: body
         name: post payload
         schema:
           type: object
           required:
             - created_by
           optional:
             - description
           properties:
             description:
               type: string
               example: api key used in prod

    responses:
       '201':
         description: signature created
       '200':
         description: Request successful but key not created, see message for reason.
       '401':
         description: unauthorized, jwt verification failed.
        """

    post_dict = request.get_json(force=True, silent=False, cache=True)

    try:
        result, code = sigstore.store_signature(post_dict['full_reg_path'],
                                            post_dict['signature'],
                                            post_dict['pub_key']
                                            )
    except KeyError:
        result = {"message" : "Not all required values were provided in the request."}
        code = 200
        return make_response(json.dumps(result), code)


    return make_response(json.dumps(result), code)


@app.route('/sigstore/<path:path>')
def get_sig(path):
    """
    Get a signature by filesystem layout path
    ---
    security:
        - basicAuth: []
    responses:
       '200':
         description: request successful
       '404':
         description: not found
        """

    signature, index, code = sigstore.get_signature(path)

    return send_file(
    io.BytesIO(signature),
    mimetype = 'document',
    as_attachment = True,
    attachment_filename = 'signature-' + str(index))



# I think deleting signatures is a bad idea...
#
# @app.route('/jwt_delete_key/<key_id>', methods=['DELETE'])
# @jwt_required
# def jwt_delete_key(key_id):
#     """
#     Delete an API key by primary key id.
#     ---
#     security:
#         - basicAuth:[]
#     parameters:
#        - in: path
#          name: key_id
#          schema:
#            type: object
#            required:
#              - key_id
#            properties:
#              key_id:
#                type: string
#                example: 4
#                description: the 'id' column of the api key row to delete
#     responses:
#        '200':
#          description: request successful
#
#         """
#
#     result, code = rhc_api_auth.jwt_delete_api_key(int(key_id), int(get_jwt()['company_nid']))
#     return make_response(json.dumps(result), code)
#
#




if __name__ == '__main__':
    ssl_context = ('/tls/tls.crt',
                   '/tls/tls.key')

    app.run(debug=False, port=8443, host='0.0.0.0', ssl_context=ssl_context)






#
# for a container repo at
# docker pull example.com/ns1/ns2/ns3/repo@sha256:digestvalue
#
# the sig url would be:
# https://example.com/sigstore/ns1/ns2/ns3/repo@sha256=digestvalue/signature-1
