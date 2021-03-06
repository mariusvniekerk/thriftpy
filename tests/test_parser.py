# -*- coding: utf-8 -*-

import pytest
from thriftpy.thrift import TType
from thriftpy.parser import load
from thriftpy.parser.exc import ThriftParserError, ThriftGrammerError


def test_comments():
    load('parser-cases/comments.thrift')


def test_constants():
    thrift = load('parser-cases/constants.thrift')
    assert thrift.int16 == 3
    assert thrift.int32 == 800
    assert thrift.int64 == 123456789
    assert thrift.tstr == 'hello world'
    assert thrift.integer32 == 900
    assert thrift.tdouble == 1.3
    assert thrift.tlist == [1, 2, 3]
    assert thrift.tset == set([1, 2, 3])
    assert thrift.tmap1 == {'key': 'val'}
    assert thrift.tmap2 == {'key': 32}
    assert thrift.my_country == 4
    assert thrift.tom == thrift.Person(name='tom')
    assert thrift.country_map == {1: 'US', 2: 'UK', 3: 'CA', 4: 'CN'}


def test_include():
    thrift = load('parser-cases/include.thrift', include_dirs=[
        './parser-cases'])
    assert thrift.datetime == 1422009523


def test_tutorial():
    thrift = load('parser-cases/tutorial.thrift', include_dirs=[
        './parser-cases'])
    assert thrift.INT32CONSTANT == 9853
    assert thrift.MAPCONSTANT == {'hello': 'world', 'goodnight': 'moon'}
    assert thrift.Operation.ADD == 1 and thrift.Operation.SUBTRACT == 2 \
        and thrift.Operation.MULTIPLY == 3 and thrift.Operation.DIVIDE == 4
    work = thrift.Work()
    assert work.num1 == 0 and work.num2 is None and work.op is None \
        and work.comment is None
    assert set(thrift.Calculator.thrift_services) == set([
        'ping', 'add', 'calculate', 'zip', 'getStruct'])


def test_e_type_error():
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_type_error_0.thrift')
    assert 'Type error' in str(excinfo.value)

    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_type_error_1.thrift')
    assert 'Type error' in str(excinfo.value)

    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_type_error_2.thrift')
    assert 'Type error' in str(excinfo.value)


def test_value_ref():
    thrift = load('parser-cases/value_ref.thrift')
    assert thrift.container == {'key': [1, 2, 3]}
    assert thrift.lst == [39, 899, 123]


def test_type_ref():
    thrift = load('parser-cases/type_ref.thrift')
    assert thrift.jerry == thrift.type_ref_shared.Writer(
        name='jerry', age=26, country=thrift.type_ref_shared.Country.US)
    assert thrift.book == thrift.type_ref_shared.Book(name='Hello World',
                                                      writer=thrift.jerry)


def test_e_value_ref():
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_value_ref_0.thrift')
    assert excinfo.value

    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_value_ref_1.thrift')
    assert str(excinfo.value) == ('Couldn\'t find a named value in enum Lang '
                                  'for value 3')
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_value_ref_2.thrift')
    assert str(excinfo.value) == \
        'No enum value or constant found named \'Cookbook\''


def test_enums():
    thrift = load('parser-cases/enums.thrift')
    assert thrift.Lang.C == 0
    assert thrift.Lang.Go == 1
    assert thrift.Lang.Java == 2
    assert thrift.Lang.Javascript == 3
    assert thrift.Lang.PHP == 4
    assert thrift.Lang.Python == 5
    assert thrift.Lang.Ruby == 6
    assert thrift.Country.US == 1
    assert thrift.Country.UK == 2
    assert thrift.Country.CN == 3
    assert thrift.OS.OSX == 0
    assert thrift.OS.Win == 3
    assert thrift.OS.Linux == 4


def test_structs():
    thrift = load('parser-cases/structs.thrift')
    assert thrift.Person.thrift_spec == {
        1: (TType.STRING, 'name', False),
        2: (TType.STRING, 'address', False)
    }
    assert thrift.Person.default_spec == [
        ('name', None), ('address', None)
    ]
    assert thrift.Email.thrift_spec == {
        1: (TType.STRING, 'subject', False),
        2: (TType.STRING, 'content', False),
        3: (TType.STRUCT, 'sender', thrift.Person, False),
        4: (TType.STRUCT, 'recver', thrift.Person, True),
    }
    assert thrift.Email.default_spec == [
        ('subject', 'Subject'), ('content', None),
        ('sender', None), ('recver', None)
    ]
    assert thrift.email == thrift.Email(
        subject='Hello',
        content='Long time no see',
        sender=thrift.Person(name='jack', address='jack@gmail.com'),
        recver=thrift.Person(name='chao', address='chao@gmail.com')
    )


def test_e_structs():
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_structs_0.thrift')
    assert str(excinfo.value) == \
        'Field \'name\' was required to create constant for type \'User\''

    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_structs_1.thrift')
    assert str(excinfo.value) == \
        'No field named \'avatar\' was found in struct of type \'User\''


def test_service():
    thrift = load('parser-cases/service.thrift')
    assert thrift.EmailService.thrift_services == ['ping', 'send']
    assert thrift.EmailService.ping_args.thrift_spec == {}
    assert thrift.EmailService.ping_args.default_spec == []
    assert thrift.EmailService.ping_result.thrift_spec == {
        1: (TType.STRUCT, 'network_error', thrift.NetworkError, False)
    }
    assert thrift.EmailService.ping_result.default_spec == [
        ('network_error', None)
    ]
    assert thrift.EmailService.send_args.thrift_spec == {
        1: (TType.STRUCT, 'recver', thrift.User, False),
        2: (TType.STRUCT, 'sender', thrift.User, False),
        3: (TType.STRUCT, 'email', thrift.Email, False),
    }
    assert thrift.EmailService.send_args.default_spec == [
        ('recver', None), ('sender', None), ('email', None)
    ]
    assert thrift.EmailService.send_result.thrift_spec == {
        0: (TType.BOOL, 'success', False),
        1: (TType.STRUCT, 'network_error', thrift.NetworkError, False)
    }
    assert thrift.EmailService.send_result.default_spec == [
        ('success', None), ('network_error', None)
    ]


def test_service_extends():
    thrift = load('parser-cases/service_extends.thrift')
    assert thrift.PingService.thrift_services == ['ping', 'getStruct']


def test_e_service_extends():
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_service_extends_0.thrift')
    assert 'Can\'t find service' in str(excinfo.value)


def test_e_dead_include():
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_dead_include_0.thrift')
    assert 'Dead including' in str(excinfo.value)


def test_e_grammer_error_at_eof():
    with pytest.raises(ThriftGrammerError) as excinfo:
        load('parser-cases/e_grammer_error_at_eof.thrift')
    assert str(excinfo.value) == 'Grammer error at EOF'


def test_e_use_thrift_reserved_keywords():
    with pytest.raises(ThriftParserError) as excinfo:
        load('parser-cases/e_use_thrift_reserved_keywords.thrift')
    assert 'Cannot use reserved language keyword' in str(excinfo.value)


def test_e_duplicate_field_id_or_name():
    with pytest.raises(ThriftGrammerError) as excinfo:
        load('parser-cases/e_duplicate_field_id.thrift')
    assert 'field identifier/name has already been used' in str(excinfo.value)
    with pytest.raises(ThriftGrammerError) as excinfo:
        load('parser-cases/e_duplicate_field_name.thrift')
    assert 'field identifier/name has already been used' in str(excinfo.value)


def test_thrift_meta():
    thrift = load('parser-cases/tutorial.thrift')
    meta = thrift.__thrift_meta__
    assert meta['consts'] == [thrift.INT32CONSTANT, thrift.MAPCONSTANT]
    assert meta['enums'] == [thrift.Operation]
    assert meta['structs'] == [thrift.Work]
    assert meta['exceptions'] == [thrift.InvalidOperation]
    assert meta['services'] == [thrift.Calculator]
    assert meta['includes'] == [thrift.shared]
