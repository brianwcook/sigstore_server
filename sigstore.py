import os
from sqlalchemy import create_engine, UniqueConstraint, select, func, ForeignKey
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker, column_property
from sqlalchemy.ext.declarative import declarative_base


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
    signature = Column(Text, nullable=False, unique=False)
    index = Column(Integer, nullable=False, unique=False)

    # todo: composite unique constraint of full_reg_path + index


sigstore_db.Base.metadata.create_all(sigstore_db.engine)


def store_signature(full_reg_path, signature):

    # todo: calculate index as number of existing sigs for reg_path + 1
    session = sigstore_db.Session()
    row = TableSigstore(full_reg_path=full_reg_path,
                        signature=signature,
                        index=next_index(full_reg_path))

    session.add(row)
    session.commit()
    # session.remove()
    return {"message": 'success'}, 201


def next_index(full_reg_path):
    # calculate the next index for inserting a signature

    session = sigstore_db.Session()
    query_result = session.query(TableSigstore).filter_by(full_reg_path=full_reg_path).all()
    return len(query_result) + 1


def get_signature(full_sig_path):
    session = sigstore_db.Session()

    split = full_sig_path.split('/')
    full_reg_path = "/".join(split[:-1])

    index = split[-1].split('-')[-1]

    query_result = session.query(TableSigstore).filter_by(full_reg_path=full_reg_path, index=index).all()
    # todo: calidate only one row is returned.
    if len(query_result) == 0:
        return "signature not found.", 404

    return query_result[0].signature, 200



