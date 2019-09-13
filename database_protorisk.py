from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.dialects.mysql import TIMESTAMP
from sshtunnel import SSHTunnelForwarder
from atexit import register
from sqlalchemy import *


REMOTE_PROTORISK_HOST = ('protorisk.p1sec.com', 47478)

ssh_tunnel_forwarder = SSHTunnelForwarder(REMOTE_PROTORISK_HOST, ssh_username = 'p1sec', remote_bind_address = ('127.0.0.1', 3306))

ssh_tunnel_forwarder.start()

register(ssh_tunnel_forwarder.stop)


engine_protorisk = create_engine('mysql://%s@%s:%d/%s' % ('p1sec', 'localhost', ssh_tunnel_forwarder.local_bind_port, 'web_3gpp'))
# Append the ", echo = True" keyword argument to print sql requests to stdout

metadata_protorisk = MetaData(bind = engine_protorisk)
BaseProtorisk = declarative_base(metadata = metadata_protorisk)

SessionProtorisk = sessionmaker()
SessionProtorisk.configure(bind = engine_protorisk)


class Spec(BaseProtorisk):
    __tablename__ = 'specs'
    
    type = Column(String(8)) # "TS", "TR", "GSM"...
    code = Column(String(16), primary_key = True, nullable = False) # "27.323"
    code_first_number = Column(Integer) # "Subject of specification series" in http://www.3gpp.org/specifications/specification-numbering
    name = Column(String(2048))
    url_3gpp = Column(String(512), nullable = False)
    html_ok = Column(Boolean, nullable = False)
    date_regen = Column(TIMESTAMP)
    latest_release = Column(Integer)
    latest_version = Column(String(16))
    
    withdrawn = Column(Boolean)
    internal = Column(Boolean)
    draft = Column(Boolean)
    
    is_2g = Column(Boolean)
    is_3g = Column(Boolean)
    is_4g = Column(Boolean)
    is_5g = Column(Boolean)
    is_other = Column(Boolean)
    


def obtain_spec_from_code(spec_code) -> Spec:
    
    sql_session = SessionProtorisk()
    
    spec = sql_session.query(Spec).filter_by(code = spec_code).first()
    
    return spec
