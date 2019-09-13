#!/usr/bin/python3
#-*- encoding: Utf-8 -*-




from sqlalchemy import *
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from enum import IntEnum

from config import WEBAPP_PATH

"""
    CCF = Command Code Format = Diameter's custom ABNF,
    defined in https://tools.ietf.org/html/rfc6733#section-3.2
"""

engine = create_engine(f'sqlite:///' + WEBAPP_PATH + '/database.sqlite3')
# Append the ", echo = True" keyword argument to print sql requests to stdout

metadata = MetaData(bind = engine)
Base = declarative_base(metadata = metadata)




Session = sessionmaker()
Session.configure(bind = engine)






class DiameterDataSource(IntEnum):
    wireshark_database = 1
    iana_database = 2
    tgpp_specifications = 3
    ietf_specifications = 4
    diafuzzer_database = 5

class VersionedDiameterObject(Base):
    __tablename__ = 'versioned_diameter_object'
    
    object_id = Column(String, primary_key = True)
    
    custom_html_notes = Column(String, nullable = True)
    
    object_type = Column(String, index = True)
    
    spec_url = Column(String, index = True)
    short_spec_name = Column(String, index = True) # "TS 29.272"
    long_spec_name_prefix = Column(String, index = True) # "3GPP TS 28.272", "IETF RFC 3877"...
    long_spec_name_suffix = Column(String, index = True) # "Interface between MME and SGSN..."
    alternate_spec_url = Column(String, index = True)
    
    updates = relationship('DiameterObjectUpdate', uselist = True, backref = 'diameter_object')
    
    __mapper_args__ = {'polymorphic_on': object_type}
    
class DiameterObjectUpdate(Base):
    __tablename__ = 'diameter_object_update'
    
    update_id = Column(Integer, primary_key = True) # Will auto-increment

    object_id = Column(String, ForeignKey('versioned_diameter_object.object_id'), nullable = False)

    source = Column(Enum(DiameterDataSource), index = True, nullable = False)
    source_url = Column(String, nullable = False)
    source_information_html_excerpts = Column(String) # Optional: used if context from the 3GPP specification is available
    source_update_date = Column(DateTime, index = True, nullable = True)
    
    insertion_date = Column(DateTime, index = True, nullable = False)


class DiameterApplication(VersionedDiameterObject):
    __tablename__ = 'diameter_application'
    
    object_id = Column(String, primary_key = True) # "app_<application_id>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    application_id = Column(Integer, nullable = False, index = True)
    application_name = Column(String, nullable = False, index = True)
    
class DiameterVendor(VersionedDiameterObject):
    __tablename__ = 'diameter_vendor'
    
    object_id = Column(String, primary_key = True) # "vendor_<vendor_id>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    vendor_id = Column(Integer, nullable = False, index = True)
    vendor_name = Column(String, nullable = False, index = True)

class DiameterCommand(VersionedDiameterObject):
    __tablename__ = 'diameter_command'
    
    object_id = Column(String, primary_key = True) # "cmd_<command_code>_<request_flag_1_or_0>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}


    vendor_id = Column(Integer, ForeignKey('diameter_vendor.vendor_id'), index = True, nullable = True)
    
    command_code = Column(Integer, index = True, nullable = False)
    
    command_name = Column(String, nullable = False, index = True)
    command_three_char_abbreviation = Column(String, index = True)
    
    req_bit = Column(Boolean, index = True, nullable = True)
    pxy_bit = Column(Boolean, index = True, nullable = True)
    err_bit = Column(Boolean, index = True, nullable = True)
    
    applications = relationship('DiameterApplication', uselist = True, secondary = 'diameter_command_avp_occurrence', backref = 'commands')
    vendor = relationship('DiameterVendor', uselist = False, backref = 'commands')
    avp_occurrences = relationship('DiameterCommandAVPOccurrence', uselist = True)

class DiameterCommandApplicationOccurence(VersionedDiameterObject):
    __tablename__ = 'diameter_command_application_occurrence'
    
    object_id = Column(String, primary_key = True) # "cmd_app_<command_code>_<request_flag_0_or_1>_<application_id>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    command_code = Column(String, ForeignKey('diameter_command.command_code'), index = True, nullable = False)
    
    application_id = Column(Integer, ForeignKey('diameter_application.application_id'), index = True, nullable = False)

class DiameterAVPRequirement(IntEnum):
    
    fixed = 0
    required = 1
    optional = 2

class DiameterCommandAVPOccurrence(VersionedDiameterObject):
    __tablename__ = 'diameter_command_avp_occurrence'
    
    object_id = Column(String, primary_key = True) # "cmd_avp_<command_code>_<request_flag_0_or_1>_<avp_code>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    command_code = Column(String, ForeignKey('diameter_command.command_code'), index = True)
    
    avp_index_within_command = Column(Integer, index = True, nullable = True)
    
    #avp_name = Column(String, ForeignKey('index = True, nullable = False)
    avp_code = Column(Integer, ForeignKey('diameter_avp_definition.avp_code'), index = True)
    
    min_occurrences = Column(Integer, index = True, nullable = True)
    max_occurrences = Column(Integer, index = True, nullable = True)
    
    avp_requirement = Column(Enum(DiameterAVPRequirement), index = True)

class DiameterAVPTypeDefinition(VersionedDiameterObject):
    __tablename__ = 'diameter_avp_type_definition'
    
    object_id = Column(String, primary_key = True) # "avp_type_<diameter_type_name>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    diameter_type_name = Column(String, index = True, nullable = False)
    parent_type_name = Column(String, ForeignKey('diameter_avp_type_definition.diameter_type_name'), nullable = True)

    format_regex = Column(String, index = True, nullable = True)

    fixed_size = Column(Integer, index = True, nullable = True)

class DiameterAVPDefinition(VersionedDiameterObject):
    __tablename__ = 'diameter_avp_definition'
    
    object_id = Column(String, primary_key = True) # "avp_<avp_code>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    application_id = Column(Integer, ForeignKey('diameter_application.application_id'), index = True)
    vendor_id = Column(Integer, ForeignKey('diameter_vendor.vendor_id'), index = True)
    
    mandatory_flag = Column(Boolean, index = True)
    protected_flag = Column(Boolean, index = True)
    vendor_specific_flag = Column(Boolean, index = True)
    may_encrypt = Column(Boolean, index = True)
    
    avp_code = Column(Integer, index = True, nullable = False)
    
    avp_name = Column(String, index = True, nullable = False)
    
    avp_type = Column(String, ForeignKey('diameter_avp_type_definition.diameter_type_name'), index = True)
    
    vendor = relationship('DiameterVendor', uselist = False, backref = 'avps')
    application = relationship('DiameterApplication', uselist = False, backref = 'avps')
    type_definition = relationship('DiameterAVPTypeDefinition', uselist = False, backref = 'avps')
    enum_values = relationship('DiameterAVPEnumValue', uselist = True, backref = 'avp')

    avp_occurrences = relationship('DiameterCommandAVPOccurrence', uselist = True, backref = 'avp')

class DiameterAVPEnumValue(VersionedDiameterObject):
    __tablename__ = 'diameter_avp_enum_value'
    
    object_id = Column(String, primary_key = True) # "avp_enum_<avp_code>_<enum_value_integer>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    avp_code = Column(Integer, ForeignKey('diameter_avp_definition.avp_code'), index = True)
    
    enum_name_string = Column(String, index = True, nullable = False)
    
    enum_value_integer = Column(Integer, index = True, nullable = False)
    






if __name__ == '__main__':
    
    metadata.create_all()



