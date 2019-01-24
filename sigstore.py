import os
from sqlalchemy import create_engine, UniqueConstraint, select, func, ForeignKey
from sqlalchemy import Column, Integer, String, Text, asc
from sqlalchemy.orm import sessionmaker, column_property
from sqlalchemy.ext.declarative import declarative_base
import gnupg
import base64
import json
from collections import OrderedDict


class SigstoreDb:

    def __init__(self, db_name):
        self.db_name = db_name

        self.mariadb_user = os.environ.get('MARIADB_USER', 'root')
        self.mariadb_host = os.environ.get('MARIADB_HOST', '127.0.0.1')
        file = os.environ.get('MARIADB_SECRET')
        print('got mariadb secret filename from env: ' + file)
        f = open(file, 'r')

        self.mariadb_secret = f.read().strip()

        conn_string = ("mysql+pymysql://" +
                       self.mariadb_user +
                       ":" +
                       self.mariadb_secret + "@" +
                       self.mariadb_host + "/" +
                       db_name
                       )

        if self.mariadb_host != '127.0.0.1':
            conn_string += "?ssl_ca=" + os.getenv('DB_CA_CERT', None)

        # don't enable this unless you want the pwd output in cleartext
        #print("using connection string:")
        #print(conn_string)

        self.engine = create_engine(conn_string,
                                    echo=True,
                                    connect_args={'ssl':{'check_hostname': False}},
                                    pool_pre_ping=True,
                                    pool_size=20, max_overflow=0)

        self.Session = sessionmaker(bind=self.engine)
        self.Base = declarative_base()


db_name = os.getenv('DB_NAME', None)
if db_name is None:
    print("no db name specified, exiting")
    exit(1)


sigstore_db = SigstoreDb(db_name)


class TableSigstore(sigstore_db.Base):
    __tablename__ = 'sigstore'

    id = Column(Integer, primary_key=True, nullable=False)
    full_reg_path = Column(String(255), nullable=False, index=True, unique=False)
    repository = Column(String(128), nullable=False, index=True, unique=False)
    signature = Column(Text, nullable=False, unique=False)
    docker_manifest_digest = Column(String(72), nullable=False, unique=False)
    docker_reference = Column(String(128), nullable=False, index=True, unique=False)
    repository = Column(String(128), nullable=False, index=True, unique=False)

    # todo: composite unique requirement to prevent storing the same sig / ref over and over?

    def asdict(self, *, stringify=False):
        result = OrderedDict()
        for key in self.__mapper__.c.keys():
            if getattr(self, key) is not None:
                if stringify:
                    result[key] = str(getattr(self, key))
                else:
                    result[key] = getattr(self, key)
            else:
                # result[key] = getattr(self, key)
                result[key] = None

        return result

sigstore_db.Base.metadata.create_all(sigstore_db.engine)


def store_signature(full_reg_path, signature):

    # decrypt signature
    sig_dict= json.loads(decrypt_data(signature))

    docker_image_digest = sig_dict['critical']['image']['docker-manifest-digest']
    docker_reference = sig_dict['critical']['identity']['docker-reference']
    repository = get_repository(full_reg_path)

    session = sigstore_db.Session()

    # todo: composite unique requirement to prevent storing the same sig / ref over and over
    row = TableSigstore(full_reg_path=full_reg_path,
                        signature=signature,
                        docker_manifest_digest=docker_image_digest,
                        docker_reference=docker_reference,
                        repository=repository)


    session.add(row)
    session.commit()
    # session.remove()
    return {"message": 'success'}, 201


def decrypt_data(b64encrypted):
    # this patch is needed to make decrypt work in python3
    # https://github.com/isislovecruft/python-gnupg/issues/102#issuecomment-325979273

    gpg = gnupg.GPG(binary="/usr/local/bin/gpg", homedir="Users/bcook/.gnupg")

    decrypted_data = gpg.decrypt(base64.b64decode(b64encrypted))
    print(decrypted_data.ok)
    print(decrypted_data.stderr)
    print(str(decrypted_data))
    return str(decrypted_data)



def get_signature(full_sig_path):
    session = sigstore_db.Session()

    split = full_sig_path.split('/')
    full_reg_path = "/".join(split[:-1])

    index = split[-1].split('-')[-1]

    query_result = session.query(TableSigstore).filter_by(full_reg_path=full_reg_path).order_by(asc(TableSigstore.id)).all()

    if len(query_result) == 0:
        return "signature not found.", 404

    bin_sig = base64.b64decode(query_result[int(index)-1].signature)

    return bin_sig, index, 200


def query_by_repo(repository):
    session = sigstore_db.Session()
    query_result = session.query(TableSigstore).filter_by(repository=repository).all()

    return to_dict(query_result, stringify=True)


def get_repository(full_sig_path):

    # is this a reference to a digest?
    if "sha256" in full_sig_path.lower():
        parts = full_sig_path.split('@')
        return parts[0]

    else: # it was by tag
        parts = full_sig_path.split(':')
        return parts[0]


def to_dict(rows,*, stringify=False):
    v = [ row.asdict(stringify=stringify) for row in rows ]
    return v