# sigstore_server
serve 'simple signing' container signatures from a database and emulate the sigstore file layout

Calling store_signature requires a JWT token.  For test purposes only, you can generate one using the gen_jwt.py file.
This will use the RSA keypair in this repo, which should NEVER be used for any other use than demo / poc.

In order to run the app, set the following environment variables to appropriate values.

* MARIABDB_TABLE_NAME=sigstore
* MARIADB_USER=root
* MARIADB_HOST=127.0.0.1
* JWT_CERT_FILE=DONOTUSETHISKEY.pub
* DB_NAME=my_database
* MARIADB_SECRET=/secrets/maria-db-pwd


implemented paths:
/store_signature: insert a neew signature into the DB
/sigstore/[path]: emulates the sigstore file tree from database.
/find?repository=[repository] returns JSON formatted result of all signatures for that repository, their docker-manifest-digest and docker-refeerence values.

See the postman API reference for other usage instructions at /swagger-ui/index.html
