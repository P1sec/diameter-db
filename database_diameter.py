#!/usr/bin/python3
#-*- encoding: Utf-8 -*-




from os.path import dirname, realpath, exists
from sqlalchemy import *
from sqlalchemy.orm import relationship, sessionmaker, backref
from sqlalchemy.ext.declarative import declarative_base
from enum import IntEnum, Enum as PythonEnum
from html import escape
from typing import Sequence, List, Dict, Set, Tuple, Union

DIAMETER_DB_DIR = dirname(realpath(__file__))

"""
    CCF = Command Code Format = Diameter's custom ABNF,
    defined in https://tools.ietf.org/html/rfc6733#section-3.2
"""

engine = create_engine(f'sqlite:///' + DIAMETER_DB_DIR + '/database.sqlite3')
# Append the ", echo = True" keyword argument to print sql requests to stdout

metadata = MetaData(bind = engine)
Base = declarative_base(metadata = metadata)




Session = sessionmaker()
Session.configure(bind = engine)






class DiameterDataSource(PythonEnum):
    wireshark_database = 'Wireshark'
    iana_database = 'IANA'
    tgpp_specifications = '3GPP'
    ietf_specifications = 'IETF'
    diafuzzer_database = 'Diafuzzer'

class VersionedDiameterObject(Base):
    __tablename__ = 'versioned_diameter_object'
    
    object_id = Column(String, primary_key = True)
    
    custom_html_notes = Column(String, nullable = True)
    
    object_type = Column(String, index = True)
    
    spec_url = Column(String, index = True)
    short_spec_name = Column(String(collation  = 'NOCASE'), index = True) # "TS 29.272"
    long_spec_name_prefix = Column(String(collation  = 'NOCASE'), index = True) # "3GPP TS 28.272", "IETF RFC 3877"...
    long_spec_name_suffix = Column(String(collation  = 'NOCASE'), index = True) # "Interface between MME and SGSN..."
    alternate_spec_url = Column(String, index = True)
    
    updates = relationship('DiameterObjectUpdate', uselist = True, backref = 'diameter_object')
    
    __mapper_args__ = {'polymorphic_on': object_type}
    
    def to_html_tree_entry(self, current_page_object_id_arborescence :   Union[None, List[str]]  = None,  this_object__parent_object_id_arborescence  : List[str]  = None) -> str:
        
        css_class, declared_object_id, entry_name = self.obtain_css_class_and_name_of_tree_entry()
        
        this_object__parent_object_id_arborescence = list(this_object__parent_object_id_arborescence or [])
        
        current_page_object_id_arborescence = list(current_page_object_id_arborescence or [])
        
        extra_classes  : str = ''
        if declared_object_id in current_page_object_id_arborescence:
            extra_classes  += ' tree-item-expanded'
        
        returned_html  = '<div class="tree-%s tree-item%s"><span class="tree-action-icon"></span><a href="/%s/%s%s" target="_blank">%s</a>' % (
            css_class,
            extra_classes,
            css_class,
            declared_object_id,
            ('?object-id-arborescence=' +  ','.join(this_object__parent_object_id_arborescence)  ) if this_object__parent_object_id_arborescence  else  '',
            escape(entry_name))
        
        this_object__parent_object_id_arborescence.append(declared_object_id)

        if current_page_object_id_arborescence  and declared_object_id == current_page_object_id_arborescence[0]:
            returned_html  += '<div class="tree_view_indentation">'
            for child_object in self.obtain_child_objects():
                returned_html  += child_object.to_html_tree_entry(current_page_object_id_arborescence[1:], this_object__parent_object_id_arborescence)
            
            returned_html += '</div>'
        
        returned_html  += '</div>'
        
        
        
        return  returned_html
        
    
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
    application_name = Column(String(collation  = 'NOCASE'), nullable = False, index = True)
    
    def obtain_child_objects(self) -> Sequence[Union['DiameterCommand', 'DiameterAVPDefinition']]:
        return [
            *self.commands,
            *self.avps
        ]
    
    def obtain_css_class_and_name_of_tree_entry(self) -> Tuple[str, str, str]:
        return ['application', self.object_id, self.application_name]
        
    
class DiameterVendor(VersionedDiameterObject):
    __tablename__ = 'diameter_vendor'
    
    object_id = Column(String, primary_key = True) # "vendor_<vendor_id>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    vendor_id = Column(Integer, nullable = False, index = True)
    vendor_name = Column(String(collation  = 'NOCASE'), nullable = False, index = True)

class DiameterCommand(VersionedDiameterObject):
    __tablename__ = 'diameter_command'
    
    object_id = Column(String, primary_key = True) # "cmd_<command_code>_<request_flag_1_or_0>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}


    vendor_id = Column(Integer, ForeignKey('diameter_vendor.vendor_id'), index = True, nullable = True)
    
    command_code = Column(Integer, index = True, nullable = False)
    
    command_name = Column(String(collation  = 'NOCASE'), nullable = False, index = True)
    command_three_char_abbreviation = Column(String(collation  = 'NOCASE'), index = True)
    
    req_bit = Column(Boolean, index = True, nullable = True)
    pxy_bit = Column(Boolean, index = True, nullable = True)
    err_bit = Column(Boolean, index = True, nullable = True)
    
    applications = relationship('DiameterApplication', uselist = True, secondary = 'diameter_command_application_occurrence', backref = 'commands')
    vendor = relationship('DiameterVendor', uselist = False, backref = 'commands')
    avp_occurrences = relationship('DiameterCommandAVPOccurrence', uselist = True, order_by = 'DiameterCommandAVPOccurrence.avp_index_within_command', backref='command', primaryjoin = 'and_(DiameterCommandAVPOccurrence.command_code == DiameterCommand.command_code, DiameterCommandAVPOccurrence.req_bit == DiameterCommand.req_bit)')
    
    def obtain_child_objects(self) -> Sequence[Union['DiameterAVPDefinition']]:
        return [
            *self.avp_occurrences
        ]
    
    def obtain_css_class_and_name_of_tree_entry(self) -> Tuple[str, str, str]:
        return ['command-code', self.object_id, self.command_name]

class DiameterCommandApplicationOccurrence(VersionedDiameterObject):
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
    
    object_id = Column(String, primary_key = True) # "cmd_avp_<command_code>_<request_flag_0_or_1>_<avp_code>_<vendor_id_or_0>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    command_code = Column(Integer, ForeignKey('diameter_command.command_code'), index = True)
    
    req_bit = Column(Boolean, index = True, nullable = True)

    avp_index_within_command = Column(Integer, index = True, nullable = True)
    
    #avp_name = Column(String, ForeignKey('index = True, nullable = False)
    avp_code = Column(Integer, ForeignKey('diameter_avp_definition.avp_code'), index = True)
    avp_vendor_id = Column(Integer, index = True)
    avp_object_id = Column(Integer, ForeignKey('diameter_avp_definition.object_id'), index = True)
    
    min_occurrences = Column(Integer, index = True, nullable = True)
    max_occurrences = Column(Integer, index = True, nullable = True)
    
    avp_requirement = Column(Enum(DiameterAVPRequirement), index = True)
    
    def obtain_child_objects(self) -> Sequence[Union['DiameterAVPDefinition']]:
        return [
            # *self.nested_avps
        ]
    
    def obtain_css_class_and_name_of_tree_entry(self) -> Tuple[str, str, str]:
        return ['avp', self.avp.object_id, self.avp.avp_name]

class DiameterNestedAVPOccurrence(VersionedDiameterObject):
    __tablename__ = 'diameter_nested_avp_occurrence'
    
    object_id = Column(String, primary_key = True) # "nested_avp_<parent_avp_code>_<nested_avp_code>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    parent_avp_code = Column(Integer, ForeignKey('diameter_avp_definition.avp_code'), index = True)
    parent_avp_object_id = Column(String, ForeignKey('diameter_avp_definition.object_id'), index = True)
    
    avp_index_within_grouped_avp = Column(Integer, index = True, nullable = True)
    
    #avp_name = Column(String, ForeignKey('index = True, nullable = False)
    nested_avp_code = Column(Integer, ForeignKey('diameter_avp_definition.avp_code'), index = True)
    nested_avp_object_id = Column(String, ForeignKey('diameter_avp_definition.object_id'), index = True)
    
    min_occurrences = Column(Integer, index = True, nullable = True)
    max_occurrences = Column(Integer, index = True, nullable = True)
    
    avp_requirement = Column(Enum(DiameterAVPRequirement), index = True)
    
    nested_avp = relationship('DiameterAVPDefinition', foreign_keys = [nested_avp_object_id], primaryjoin = 'DiameterAVPDefinition.object_id == DiameterNestedAVPOccurrence.nested_avp_object_id', uselist = False, backref = backref('grouped_avps', uselist = True))

class DiameterAVPTypeDefinition(VersionedDiameterObject):
    __tablename__ = 'diameter_avp_type_definition'
    
    object_id = Column(String, primary_key = True) # "avp_type_<diameter_type_name>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    diameter_type_name = Column(String(collation  = 'NOCASE'), index = True, nullable = False)
    parent_type_name = Column(String(collation  = 'NOCASE'), ForeignKey('diameter_avp_type_definition.diameter_type_name'), nullable = True)

    format_regex = Column(String, index = True, nullable = True)

    fixed_size = Column(Integer, index = True, nullable = True)

class DiameterAVPDefinition(VersionedDiameterObject):
    __tablename__ = 'diameter_avp_definition'
    
    object_id = Column(String, primary_key = True) # "avp_<avp_code>_<vendor_id_or_0>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    application_id = Column(Integer, ForeignKey('diameter_application.application_id'), index = True)
    vendor_id = Column(Integer, ForeignKey('diameter_vendor.vendor_id'), index = True)
    
    mandatory_flag = Column(Boolean, index = True)
    protected_flag = Column(Boolean, index = True)
    vendor_specific_flag = Column(Boolean, index = True)
    may_encrypt = Column(Boolean, index = True)
    
    avp_code = Column(Integer, index = True, nullable = False)
    
    avp_name = Column(String(collation  = 'NOCASE'), index = True, nullable = False)
    
    avp_type = Column(String, ForeignKey('diameter_avp_type_definition.diameter_type_name'), index = True)
    
    is_grouped = Column(Boolean, index = True)
    
    vendor = relationship('DiameterVendor', uselist = False, backref = 'avps')
    application = relationship('DiameterApplication', uselist = False, backref = 'avps')
    type_definition = relationship('DiameterAVPTypeDefinition', uselist = False, backref = 'avps')
    enum_values = relationship('DiameterAVPEnumValue', foreign_keys = [object_id], primaryjoin = 'DiameterAVPDefinition.object_id == DiameterAVPEnumValue.avp_object_id', uselist = True, backref = backref('avp', uselist = False))

    nested_avps = relationship('DiameterNestedAVPOccurrence', foreign_keys = [object_id], primaryjoin = 'DiameterAVPDefinition.object_id == DiameterNestedAVPOccurrence.parent_avp_object_id', uselist = True, backref = backref('parent_avp', uselist = False))

    avp_occurrences = relationship('DiameterCommandAVPOccurrence', foreign_keys = [object_id], primaryjoin = 'DiameterAVPDefinition.object_id == DiameterCommandAVPOccurrence.avp_object_id', uselist = True, backref = backref('avp', uselist = False))

    
    def obtain_child_objects(self) -> Sequence[Union['DiameterAVPDefinition']]:
        return [
            # *self.nested_avps
        ]
    
    def obtain_css_class_and_name_of_tree_entry(self) -> Tuple[str, str, str]:
        return ['avp', self.object_id, self.avp_name]

class DiameterAVPEnumValue(VersionedDiameterObject):
    __tablename__ = 'diameter_avp_enum_value'
    
    object_id = Column(String, primary_key = True) # "avp_enum_<avp_code>_<vendor_id_or_0>_<enum_value_integer>"
    __mapper_args__ = {'polymorphic_identity': __tablename__, 'inherit_condition': (object_id == VersionedDiameterObject.object_id)}
    
    avp_code = Column(Integer, ForeignKey('diameter_avp_definition.avp_code'), index = True)
    avp_vendor_id = Column(Integer, index = True)
    avp_object_id = Column(Integer, ForeignKey('diameter_avp_definition.object_id'), index = True)
    
    enum_name_string = Column(String, index = True, nullable = False)
    
    enum_value_integer = Column(Integer, index = True, nullable = False)
    






if __name__ == '__main__':
    
    metadata.create_all()



