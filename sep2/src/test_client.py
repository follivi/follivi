from http.client import HTTPSConnection,HTTPConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import time
import sys
import ssl
import os

# pem_data = open('certfile.pem','rb').read()
# crt = x509.load_pem_x509_certificate(pem_data,)
# x509.CertificateBuilder()
sae_dir = 'config/sae3072_xmls'
print()

def run_interactive(conn:HTTPSConnection):
    while True:
        s = input()
        try:
            if s.startswith('put') or s.startswith('post'):
                meth,path,f = s.split(' ')
                _xml = open(f'{sae_dir}/{f}','rb').read()
                r=conn.request(meth.upper(),path,_xml)
                r = conn.getresponse()
                print(r.fp.read().decode('utf-8'))                    
            elif s == 'clear': os.system('cls')
            elif s == 'stop': sys.exit()
            else:
                conn.request('GET',s)
                r = conn.getresponse()
                print(r.fp.read().decode('utf-8'))
                # print(r._content.decode('utf-8'))
        except Exception as e: print(e)


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations(cafile= u'tls/certs/ca.pem')
ctx.load_cert_chain( u'tls/certs/dev1.pem', u'tls/private/dev1.pem',)
ctx.verify_mode = ssl.CERT_REQUIRED
conn = HTTPSConnection(host='127.0.0.1',port = 7000 ,context=ctx,check_hostname=False)
conn.connect()
run_interactive(conn=conn)
conn.request('GET','dcap')
r = conn.getresponse()
print(r.fp.read().decode('utf-8'))
print(r.__dict__)
sys.exit()

host = '127.0.0.1'
port = 7000

conn =  HTTPConnection(host=host,port=port)

t0 = time.time()
conn.request('GET','dcap')
print(time.time() - t0)
r = conn.getresponse()
print(time.time() - t0)
print(r.__dict__)
print(r.msg.as_string())
print(r.fp.read().decode('utf-8'))

t0 = time.time()
conn.request('GET','dcap')
print(time.time() - t0)
r = conn.getresponse()
print(time.time() - t0)
print(r.__dict__)
print(r.msg.as_string())
print(r.fp.read().decode('utf-8'))