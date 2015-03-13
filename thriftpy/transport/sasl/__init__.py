from __future__ import print_function, absolute_import

__author__ = 'mniekerk'


from thriftpy._compat import CYTHON

if CYTHON:
    from .cysasl import TCySaslTransport, TCySaslTransportFactory