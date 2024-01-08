from flask import request, Response  as _Response, Flask
from sep import *
import sep as m
from constants import *
from enums import *
from types_ import *
from utils import *
import time
from datetime import datetime , timedelta , timezone
import yaml
import xmltodict
import pytz
import tzlocal
import ssl
import logging
import sys , os , json
from threading import Thread
from cryptography.hazmat.primitives import hashes , serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from  ipaddress import IPv4Address

logger = logging.getLogger(__name__)
logging.basicConfig(level="DEBUG", format='%(asctime)s  - [%(levelname)s] %(message)s', filemode='w')
with open('config/config.yml','r') as f: cfg = yaml.safe_load(f)
print(cfg)
server_info = cfg.get('server').get('info')
cafile , keyfile , certfile = server_info.get('certificates').get('cafile') , server_info.get('certificates').get('keyfile') , server_info.get('certificates').get('certfile')
encript = server_info.get('certificates').get('encript',False)
sep2_wadl_xml = cfg.get('sep2_wadl').get('path')
addr , http_port , https_port = server_info.get('ip','127.0.0.1') , server_info.get('port', 7000) ,  server_info.get('httpsPort', 8443)

with open(sep2_wadl_xml,'r') as f: data_dict = xmltodict.parse(f.read())

_now = datetime.now
# tzlocal = pytz.timezone('America/Montreal')
SEP_XML =  "application/sep+xml"
_headers = {'Content-Type': SEP_XML}
method_map  = {}
resource_map  = {}

# while True: time.sleep(0.)
# DERSettings()
# DERCapability()
DERControl()
# DeviceCategoryType()
# DefaultDERControl()
# DERCurve()
# cfg = None

class MyCertificate(x509.Certificate):
    def set_value(self,attr,value):
        setattr(self,attr,value)
        return
    def extensions(self, ext):
        self.ext = ext
        return
    def issuer(self,issuer):
        self.issuer = issuer
        return
    def not_valid_after(self,d):
        self.not_valid_after = d
        return
    def not_valid_before(self,d):
        self.not_valid_before
        return
    def serial_number(self,n):
        self.serial_number=n
        return
    def signature(self,s):
        self.signature=s
        return
    def signature_algorithm_oid(self):
        return
    def signature_hash_algorithm(self):
        return
    def tbs_certificate_bytes(self):
        return
    def subject(self):
        return
    def version(self):
        return
    def fingerprint(self):
        return self.fingerprint
    def public_bytes(self, encoding):
        return
    def public_key(self):
        return
    def __eq__(self, __other: object):
        return
    def __ne__(self, __other: object):
        return

def _allowed_meths(resource):
    for res in data_dict.get('application').get('resources').get('resource'):
        if res.get('@id') == resource:
            methods = [meth.get('@name') for meth in res.get('method') if meth.get('@wx:mode') in ['M','O']]
            break
    return methods

def _supported_query_strings(resource):
    t0 = time.time()
    s = []
    for res in data_dict.get('application').get('resources').get('resource'):
        if res.get('@id') == resource:
            for meth in res.get('method'):
                if meth.get('@name') == 'GET':
                    req = meth.get('request')
                    # print(req.get('param'))
                    if req is not None:
                        # print(req)
                        for p in req.get('param'):
                            if p['@style'] == 'query':
                                s.append(p['@name'])
                        break
    # print(time.time() -t0)
    # print(s)
    return s

def diff_between_obj(obj1,obj2):
    if not isinstance(obj1,obj2.__class__): return
    diffs = []
    for attr in obj1.__dict__:
        if getattr(obj1,attr) != getattr(obj2,attr): diffs.append(attr)
    return diffs

def frp_event_converter(event_schedules: FlowReservationRequestList = None):
    return

def build_context(cafile=cafile,certfile=certfile,keyfile=keyfile, verify = True):
    _ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER,purpose = 'CLIENT_AUTH')
    _ssl_context.check_hostname = False
    if verify: _ssl_context.verify_mode = ssl.CERT_REQUIRED  #  ssl.CERT_REQUIRED
    else: _ssl_context.verify_mode = ssl.CERT_OPTIONAL  #  ssl.CERT_REQUIRED
    _ssl_context.load_verify_locations(cafile=cafile)

    # Loads client information from the passed cert and key files. For
    # client side validation.
    _ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return _ssl_context

def clbck(conn:ssl.SSLSocket, direction, version=ssl.PROTOCOL_TLSv1_2, content_type=ssl._TLSContentType.HANDSHAKE, msg_type=ssl._TLSMessageType.CLIENT_HELLO, data=None):
    logger.debug(msg=f'New callback message registered')
    # print('Peer name: ',conn)
    print('***'*5,'direction: ', direction)
    print('***'*5,'version: ', version)
    print('***'*5,'Content type: ', content_type)
    print('***'*5,'msg type: ', msg_type)
    # print('Data: ',data)
    return

def compute_lfdi(certfile=certfile):
    pem_data = open(certfile,'rb').read()
    cert = x509.load_pem_x509_certificate(pem_data,default_backend())
    fp = cert.fingerprint(hashes.SHA256())
    lfdi = fp.hex()[:40]
    print(lfdi)
    return lfdi

def generate_cert():

    def create_cert(issuer, subject , subject_public_key , issuer_private_key, fname, ext = None):
        cert = x509.CertificateBuilder().subject_name(subject)\
                                        .issuer_name(issuer)\
                                        .public_key(subject_public_key)\
                                        .serial_number(x509.random_serial_number())\
                                        .not_valid_before(datetime.now(timezone.utc))\
                                        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=100))
        if ext is not None: cert = cert.add_extension(ext,False)
        # print(cert.fingerprint(hashes.SHA256()).hex(), cert.serial_number,cert.signature_hash_algorithm)
        cert = cert.sign(issuer_private_key, hashes.SHA256())
        pkey_serialized = cert.public_bytes(serialization.Encoding.PEM)
        with open(fname, "wb") as f: f.write(pkey_serialized)
        for line in pkey_serialized.splitlines(): print(line)
        return cert

    issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SunSpec Alliance"),
    x509.NameAttribute(NameOID.COMMON_NAME, f"Test IEEE 2030.5 Root/serialNumber=1"),
    ])

    subject_server = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    # x509.SubjectAlternativeName([x509.IPAddress(IPv4Address(addr))]),
    ])

    subject_client = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    ])

    key_ca = ec.generate_private_key(curve=ec.SECP256R1())
    key_server = ec.generate_private_key(curve=ec.SECP256R1())
    key_client = ec.generate_private_key(curve=ec.SECP256R1())

    create_cert(issuer,issuer,key_ca.public_key(),key_ca,'ca_cert.pem',ext=x509.BasicConstraints(ca=True,path_length=1))
    server_cert = create_cert(issuer,subject_server,key_server.public_key(),key_ca,'server_cert.pem',ext=x509.SubjectAlternativeName([x509.IPAddress(IPv4Address('142.127.36.126'))]))
    create_cert(issuer,subject_client,key_client.public_key(),key_ca,'client_cert.pem')

    print('lfdi', server_cert.fingerprint(hashes.SHA256()).hex()[:40])

    for fname,key in zip(['server_key.pem','client_key.pem'],[key_server,key_client]):
        key_serialized = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
        with open(fname, "wb") as f: f.write(key_serialized)
    return

def add_extension(cert_file):
    cert = x509.load_pem_x509_certificate(open(cert_file,'rb').read())
    print(cert.signature.hex())
    print(cert.public_bytes(serialization.Encoding.PEM))
    print(cert.extensions)
    new_cert = MyCertificate()
    for attr in ['issuer','subject','not_valid_after','not_valid_before','fingerprint','public_bytes','public_key',
                 'signature_algorithm_oid','signature_hash_algorithm','tbs_certificate_bytes','version']: setattr(new_cert,attr,getattr(cert,attr))
    new_cert.set_value('extensions',x509.SubjectAlternativeName([x509.IPAddress(IPv4Address('142.127.36.126'))]))
    new_cert.signature(cert.signature)
    print(new_cert.signature.hex())
    print(new_cert.public_bytes(serialization.Encoding.PEM))
    print(new_cert.extensions)
    print(new_cert.issuer,new_cert.subject)
    cert_serialized = new_cert.public_bytes(serialization.Encoding.PEM)
    for line in cert_serialized.splitlines(): print(line)
    with open('_certfile.pem', "wb") as f: f.write(cert_serialized)
    print('lfdi: ', new_cert.fingerprint(hashes.SHA256()).hex()[:40])
    # print(cert.issuer,cert.subject,cert.extensions,cert.extensions)
    # print(cert.fingerprint(hashes.SHA256()).hex(), cert.serial_number,cert.signature_hash_algorithm)
    # print(cert.issuer,cert.subject,cert.extensions,cert.extensions)
    return

# add_extension('..\IEEE-2030.5-Client\certs\csep_root.pem')
# generate_cert()
# sys.exit()
class FunctionSet():
    def __init__(self, name = '',) -> None:
        self.resources:Resource = {}
        pass
    def sort_list(self):
        return
    def register_links(self,flask_app):
        raise('Not implemented')

class CommAgent():
    def __init__(self,_class = None,_class_kwargs = {}) -> None:
        self.agent = _class(**_class_kwargs)
    def connect(self,host,port,**kwargs):
        self.agent.connect(host,port)
    def subscribe(self,topics):
        self.agent.subscribe(topics)
        return

class IEEE_2030_5_server:

    def __init__(self, name:str='mysep2server',**kwargs) -> None:
        self.name = name
        self.flask_app = Flask(name, template_folder='templates')
        self.resources={}

    def init_server(self,server):
        """
        Register server from server configuration
        param server: dict
        """
        logger.debug("Register server programs from configuration dictionnary")
        # dcap initialization
        self._add_resource(
            DeviceCapability(
                href='/dcap',
                TimeLink=TimeLink(href='/tm'),
                EndDeviceListLink=EndDeviceListLink(href='/edev'),
                ResponseSetListLink=ResponseSetListLink(href='/rsps'),
                UsagePointListLink=UsagePointListLink(href='/upt'),
                MirrorUsagePointListLink=MirrorUsagePointListLink(href='/mup'),
                pollRate=900
            ))
        
        self._add_resource(Time(href='/tm'))
        self._add_resource(EndDeviceList(href='/edev',all=0,pollRate=900))
        self._add_resource(ResponseSetList(href='/rsps',all=0,pollRate=900))
        self._add_resource(UsagePointList(href='/upt',all=0,pollRate=900))
        self._add_resource(MirrorUsagePointList(href='/mup',all=0,pollRate=900))
        # Add program resources if any
        topo_prog = server['programs']['topology']
        # topology system program
        for descr, prog_id in zip(['SYS','SUBTX','SUBST','FEED','SEG','TX','SP'],['system','substransmission','substation','feeder','segment','transformer','service']):
            _progs = topo_prog[prog_id]['tag']
            primacy  = topo_prog[prog_id]['primacy']
            if _progs is not None: 
                if not isinstance(_progs,list): _progs = [_progs]
                for _prog in _progs:
                    # add to server database a resource representing the current derprogram object with links to the various controls
                    self._add_resource(
                        DERProgram(
                            href=f"/{_prog}/derp/1",
                            mRID=uuid_2030_5(),
                            description=f"{descr}-{_prog} program",
                            ActiveDERControlListLink=ActiveDERControlListLink(href=f"{_prog}/derp/1/actderc",all=0),
                            DefaultDERControlLink=DefaultDERControlLink(href=f"{_prog}/derp/1/dderc"),
                            DERControlListLink=DERControlListLink(href=f"{_prog}/derp/1/derc",all=0),
                            DERCurveListLink=DERCurveListLink(href=f"{_prog}/derp/1/dc",all=0),
                            primacy=primacy))
                    # add to server database control resources mapped to links contained in the current derprogram 
                    self._add_resource(DefaultDERControl(href = f"/{_prog}/derp/1/dderc",mRID=uuid_2030_5()))
                    self._add_resource(DERControlList(href = f"/{_prog}/derp/1/derc",all=0))
                    self._add_resource(DERCurveList(href = f"/{_prog}/derp/1/dc",all=0))
        # custom programs
        custom_progs = server['programs']['custom']['tag']
        custom_progs_primacy = server['programs']['custom']['primacy']
        if custom_progs is not None: 
            if not isinstance(custom_progs,list): custom_progs=[custom_progs]
            for _prog in custom_progs:
                # add to server database a resource representing the current derprogram object with links to the various controls
                self._add_resource(
                    DERProgram(
                        href=f"/{_prog}/derp/1",
                        mRID=uuid_2030_5(),
                        description=f"Group-{_prog} program",
                        ActiveDERControlListLink=ActiveDERControlListLink(href=f"{_prog}/derp/1/actderc",all=0),
                        DefaultDERControlLink=DefaultDERControlLink(href=f"{_prog}/derp/1/dderc"),
                        DERControlListLink=DERControlListLink(href=f"{_prog}/derp/1/derc",all=0),
                        DERCurveListLink=DERCurveListLink(href=f"{_prog}/derp/1/dc",all=0),
                        primacy=custom_progs_primacy))            
                # add to server database control resources mapped to links contained in the current derprogram 
                self._add_resource(DefaultDERControl(href = f"/{_prog}/derp/1/dderc",mRID=uuid_2030_5()))
                self._add_resource(DERControlList(href = f"/{_prog}/derp/1/derc",all=0))
                self._add_resource(DERCurveList(href = f"/{_prog}/derp/1/dc",all=0))
        return

    def register_devices(self,devices:dict):
        """ Register IEEE 2030.5 end devices.

        :param devices: End devices from agent config file.
        :type devices: dictionnary

        :return: Dictionary of EndDevice objects keyed by ID.
        """
        logger.debug("Loading Devices: {}".format(self.__class__.__name__))
        # add to server database a resource for empty end device list
        self._add_resource(EndDeviceList(href='/edev',all = 0 , results=0 , pollRate= 900))
        for dev_id,device in devices.items():
            edev_uri = f'/edev/{dev_id}'
            # add end device object resource 
            self._add_resource(
                EndDevice(
                href= edev_uri,
                lFDI= device['info']['lfdi'].encode('utf-8').hex(),
                sFDI= int(device['info']['sfdi']),
                PowerStatusLink = PowerStatusLink(href=f'{edev_uri}/ps'),
                RegistrationLink= RegistrationLink(f'{edev_uri}/rg'),
                DERListLink=DERListLink(href=f'{edev_uri}/der',all=1),
                DeviceInformationLink= DeviceInformationLink(href=f'{edev_uri}/di'),
                DeviceStatusLink= DeviceStatusLink(href=f'{edev_uri}/dstat'),
                ))
            # append edev to edev_list
            self.resources['/edev'].EndDevice.append(self.resources[edev_uri])
            # add edev subordinate resources
            self._add_resource(PowerStatus(href=f'{edev_uri}/ps',))
            self._add_resource(
                Registration(
                    href=f'{edev_uri}/rg',
                    dateTimeRegistered=datetime.utcnow().timestamp().__ceil__(),
                    pIN=device['info']['pin'],
                    pollRate=900)
                    )
            self._add_resource(DeviceInformation(href=f'{edev_uri}/di'))
            self._add_resource(DeviceStatus(href=f'{edev_uri}/dstat'))
            ## der and subordinate resources
            self._add_resource(
                DERList(href=f'{edev_uri}/der',
                        pollRate=900,
                        DER=[
                            DER( 
                                href=f'{edev_uri}/der/1',
                                DERAvailabilityLink=DERAvailabilityLink(href=f'{edev_uri}/der/1/dera'),
                                DERCapabilityLink=DERCapabilityLink(href=f'{edev_uri}/der/1/dercap'),
                                DERSettingsLink=DERSettingsLink(href=f'{edev_uri}/der/1/ders'),
                                DERStatusLink=DERStatusLink(href=f'{edev_uri}/der/1/derstat')
                        )]))
            for der in self.resources[f'{edev_uri}/der'].DER: self._add_resource(der)
            self._add_resource(DERAvailability(href=f'{edev_uri}/der/1/dera'))
            self._add_resource(DERCapability(href=f'{edev_uri}/der/1/dercap'))
            self._add_resource(DERSettings(href=f'{edev_uri}/der/1/ders'))
            self._add_resource(DERStatus(href=f'{edev_uri}/der/1/derstat'))
            # check wether flow reservation or dercontrol
            if device['flow_reservation']: 
                # add FlowReservationRequestListLink to end device object
                self.resources[edev_uri].FlowReservationRequestListLink = FlowReservationRequestListLink(f'{edev_uri}/frq',all=0)
                # add FlowReservationRequestList and FlowReservationResponseList resources to server database
                self._add_resource(FlowReservationRequestList(href=f'{edev_uri}/frq',all = 0,results=0,pollRate=15))
                self._add_resource(FlowReservationResponseList(href=f'{edev_uri}/frp',all = 0,results=0,pollRate=15))
            else:
                function_set_assignments = device['function_set_assignments']
                if 'programs' in function_set_assignments:
                    fsa_uri = f'{edev_uri}/fsa'
                    topo_prog_uri = f'{edev_uri}/derpF1'
                    # initialize function set assignments list link to en device resource
                    self.resources[edev_uri].FunctionSetAssignmentsListLink = FunctionSetAssignmentsListLink(href=fsa_uri)
                    # add fsa list resource to server database
                    self._add_resource(FunctionSetAssignmentsList(href=fsa_uri,all=0,pollRate=900))
                    # create fsa object 
                    _fsa = FunctionSetAssignments(
                            href=f'{fsa_uri}/1',
                            TimeLink=TimeLink('/tm'),
                            DERProgramListLink = DERProgramListLink(href=topo_prog_uri))
                    # add fsa resource to srver database
                    self._add_resource(_fsa)
                    # Append fsa object to fsa list object
                    self.resources[fsa_uri].FunctionSetAssignments.append(_fsa)
                    # iterate through fsa programs
                    # TODO verifiy config yml and prog list structure
                    # create derprogramlist object and add resource
                    self._add_resource(DERProgramList(topo_prog_uri,all=0))
                    for program_id in function_set_assignments['programs']:
                        # add program to progrsm list object
                        self.resources[topo_prog_uri].DERProgram.append(self.resources[f"/{program_id}/derp/1"])            
        return

    def update_dderc(self, url, key_val:dict):
        if url not in self.resources:
            logger.exception(f'{url} not in server resources ; check again and try later on')
            return
        else: obj:DefaultDERControl = self.resources[url]
        for key,val in key_val.items():
            try: setattr(obj,key,val) 
            except: setattr(obj.DERControlBase,key,val)
        return
    
    def add_derc(self,prog_name='' , key_val:dict = {}):
        """
        Add new der control event to existing der program (prog_name). 

        Params:
            prog_name:str name of derprogram to which derc has to be added:: Make sure prog_name exists otherwhise will throw key error
            key_val: dict key, value pair of  control attributes. Keys must be a attribute of DERControl object
            keys: deviceCategory:str The category of devices that should consider the given control. It is very important to mention this parameter , otherwhise will be ignored
                  start:int event start date. This parameter must be present otherwhise will throw key error
                  duration:int duration of the control event. This parameter must be present otherwhise will throw key error

        """
        current_time = _now().timestamp().__ceil__()
        derc_list_uri = f"/{prog_name}/derp/1/derc"
        derc_idx = self.resources[derc_list_uri].DERControl.__len__()+1
        # update other derc eventstatus
        for idx,_derc in enumerate(self.resources[derc_list_uri].DERControl):
            end_time = _derc.interval.start + _derc.interval.duration
            if end_time < current_time: 
                self.resources[derc_list_uri].DERControl.pop(idx)
                self.resources.pop(_derc.href)
            elif _derc.interval.start < key_val['start']: 
                if _derc.deviceCategory == key_val['deviceCategory']: 
                    _derc.EventStatus.currentStatus = 4
                    _derc.EventStatus.potentiallySuperseded = True
                    _derc.EventStatus.potentiallySupersededTime = key_val['start']
        # TODO: check if program exists
        derc = DERControl(
            href=f"{derc_list_uri}/{derc_idx}",
            mRID=uuid_2030_5(),
            creationTime=current_time,
            description= f'new derc {derc_idx}',
            EventStatus=EventStatus(
                currentStatus=0,
                dateTime=time.time().__ceil__()),
            interval=DateTimeInterval(start= key_val.pop('start'), duration=key_val.pop('duration')))
        # update event status
        if derc.interval.start <= current_time: derc.EventStatus.currentStatus = 1
        # update control parameters
        for key,val in key_val.items():
            try: setattr(derc,key,val) 
            except: setattr(derc.DERControlBase,key,val)
        self.resources[f'{derc_list_uri}'].DERControl.append(derc)
        # register derc url to server database
        self._add_resource(derc)
        return
    
    def add_dc(self,prog_name='' , key_val:dict = {}):
        dc_list_uri = f"{prog_name}/derp/1/dc"
        dc_idx = self.resources[dc_list_uri].DERControl.__len__()+1
        dc = DERCurve(
            href= f'{dc_list_uri}/1',
            mRID=uuid_2030_5(),
            description='curve',
            creationTime=time.time().__ceil__(),
            curveType= getattr(CurveType,key_val.pop('curveType')),
            CurveData=[CurveData(xvalue=dic['xvalue'] , yvalue=dic['yvalue']) for dic in key_val['curveData']]
        )
        self.resources['dc_list_uri'].DERCurve = [dc]
        return
    
    def update_settings(self, idx=1, key_val:dict = {}):
        obj = self.resources[f'/edev/{idx}/der/1/derg']
        for key, val in key_val.items():
            print(key,val)
            if key == 'modesEnabled': setattr(obj,key,hex(val))
            elif key == 'setMaxA':  setattr(obj,key,CurrentRMS(multiplier=0,value=val))
            elif key == 'setMaxAh':  setattr(obj,key,AmpereHour(multiplier=0,value=val))
            elif key == 'setMaxChargeRateVA':  setattr(obj,key,ApparentPower(multiplier=0,value=val))
            elif key == 'setMaxDischargeRateW':  setattr(obj,key,ActivePower(multiplier=0,value=val))
            elif key == 'setMaxW':  setattr(obj,key,ActivePower(multiplier=0,value=val))
            else: setattr(obj, key, val)
        return

    def add_frp(self,):
        
        return
    
    def _build_ssl_context(self,server_key_file,server_cert_file,ca_cert_file,purpose='CLIENT_AUTH',verify_mode = 'CERT_OPTIONAL'):
        # # to establish an SSL socket we need the private key and certificate that
        # # we want to serve to users.
        # server_key_file = str(tlsrepo.server_key_file)
        # server_cert_file = str(tlsrepo.server_cert_file)

        # # in order to verify client certificates we need the certificate of the
        # # CA that issued the client's certificate. In this example I have a
        # # single certificate, but this could also be a bundle file.
        # ca_cert = str(tlsrepo.ca_cert_file)

        # create_default_context establishes a new SSLContext object that
        # aligns with the purpose we provide as an argument. Here we provide
        # Purpose.CLIENT_AUTH, so the SSLContext is set up to handle validation
        # of client certificates.
        # print(str(ca_cert_file))
        self.ssl_context = ssl.create_default_context(purpose=getattr(ssl.Purpose,purpose), cafile=str(ca_cert_file))

        # # load in the certificate and private key for our server to provide to clients.
        # # force the client to provide a certificate.
        self.ssl_context.load_cert_chain(
            certfile=server_cert_file,
            keyfile=server_key_file,
        # password=app_key_password
        )
        # change this to ssl.CERT_REQUIRED during deployment.
        # TODO if required we have to have one all the time on the server.
        self.ssl_context.verify_mode = getattr(ssl,verify_mode)    # ssl.CERT_REQUIRED
        return

    def _add_resource(self,obj:Resource):
        if obj.href in self.resources: add_rule = False
        else: add_rule = True
        self.resources[obj.href] = obj
        if add_rule:
            method_map[obj.href] = {}
            name = obj.__class__.__name__
            methods = _allowed_meths(name)
            query_str = _supported_query_strings(name)
            resource_map[obj.href] = query_str
            for meth in methods:
                _meth = f"{meth.lower()}_{name.lower()}"
                try: method_map[obj.href][meth] = getattr(self,_meth)
                except: method_map[obj.href][meth] = getattr(self,meth.lower())
            # TODO: Ensure replacement for flask
            self.flask_app.add_url_rule(rule = obj.href,view_func=self.handle_request, methods = methods)

    def handle_request(self,**kw):
        t0 = time.time()
        path = request.path
        method = request.method
        try: func = getattr(self,f"{method.lower()}_{self.resources[path].__class__.__name__.replace('List','').lower()}")
        except: func = getattr(self,request.method.lower())
        resp = func()
        print(time.time()-t0)
        return resp

    def get_point(self,path):
        return dataclass_to_xml(self.resources[path])

    def set_point(self,path,value):
        self.resources[path] = value #xml_to_dataclass(value)
        return

    def get_frq(self,path):
        frq_list = self.resources[path]
        arg_copy = frq_list.__dict__.copy()
        frq_list_copy = getattr(m,'FlowReservationRequestList')(**arg_copy)
        frq_list_copy.FlowReservationRequest = [frq for frq in frq_list_copy.FlowReservationRequest if frq.RequestStatus.requestStatus == 0]
        l = sorted(frq_list_copy.FlowReservationRequest,key=lambda x: x.intervalRequested.start,reverse=True)
        arr = [l[0]]
        last_tm = l[0].intervalRequested.start
        for item in l[1:]:
            if last_tm >= item.intervalRequested.start + item.intervalRequested.duration:
                last_tm = item.intervalRequested.start
                arr.append(item)
        # l = sorted(l,key=lambda x: x.creationTime,reverse=True)
        # l = sorted(l,key=lambda x: x.mRID,reverse=True)
        frq_list_copy.FlowReservationRequest = arr
        return  frq_list_copy
        dic = {}
        frq:FlowReservationRequest = self.resources[path]
        dic['request description'] = frq.description
        dic['duration requested (s)'] = frq.durationRequested
        dic['energyRequested (Wh)'] = frq.energyRequested.value*pow(10,frq.energyRequested.multiplier)
        dic['powerRequested (W)'] = frq.powerRequested.value*pow(10,frq.powerRequested.multiplier)
        dic['requiredStart'] = frq.intervalRequested.start
        dic['requiredDuration'] = frq.intervalRequested.duration
        dic['requestStatus'] = frq.RequestStatus
        return frq

    def set_frp(self,path,value):
        t0 = time.time()
        print('inside set frp')
        frp_list:FlowReservationResponseList = self.resources[path]
        # print('all ',frp_list.all)
        if frp_list.all > 0:
            # print('inside true condition')
            idx =[]
            high_idx = []
            for i in range(frp_list.all):
                _idx = int(frp_list.FlowReservationResponse[i].href.split('/')[-1])
                high_idx.append(_idx)
                _end = frp_list.FlowReservationResponse[i].interval.duration + frp_list.FlowReservationResponse[i].interval.start
                # print(_end,value['start'])
                if frp_list.FlowReservationResponse[i].EventStatus.potentiallySuperseded:
                    idx.append(i)
                elif (_end < value['start']) or (frp_list.FlowReservationResponse[i].interval.start < value['start'] < _end):
                    frp_list.FlowReservationResponse[i].EventStatus.potentiallySuperseded = True
                    frp_list.FlowReservationResponse[i].EventStatus.potentiallySupersededTime = _now().timestamp().__ceil__()

            for i in idx:
                print('inside loop 2 ',i)
                self.resources.pop(frp_list.FlowReservationResponse[i].href)
                frp_list.FlowReservationResponse.pop(i)
            new_path = f'{path}/{max(high_idx)+1}'
            frp_list.all = len(frp_list.FlowReservationResponse)
            # print('all ',frp_list.all)
            # frp_list.FlowReservationResponse = frp_list.FlowReservationResponse[idx]
        else:
            new_path = f'{path}/1'
        frp = FlowReservationResponse(href=new_path,
                                        EventStatus=EventStatus(0,
                                                                  value['start'],
                                                                  potentiallySuperseded=False),
                                        interval=DateTimeInterval(value['duration'],value['start']),
                                        energyAvailable=SignedRealEnergy(0,value['energyAvailable']),
                                        powerAvailable=ActivePower(0,value['powerAvailable']),
                                        subject=value['subject'])
        self.resources[new_path] = frp
        frp_list.FlowReservationResponse.append(frp)
        frp_list.all += 1
        print('frp set duration ' , time.time()-t0)
        # print(frp_list)
        return

    def get(self):
        # print(request.environ['REMOTE_ADDR'],request.environ['REMOTE_PORT'])
        # print(request.query_string)
        if request.path not in self.resources: return _Response(status=404,headers=_headers)
        obj = self.resources[request.path]
        #TODO check if user is authorized to access resource and filter resource accordingly
        #TODO handle query string
        #TODO handle list ordering
        query_str = request.query_string
        name = obj.__class__.__name__
        if query_str == b'':
            t0 = time.time()
            rsp = _Response(dataclass_to_xml(obj), headers=_headers)
            print('elapsed ', time.time() -t0)
            return rsp
        else:
            if not name.endswith('List'): return _Response(dataclass_to_xml(obj), headers=_headers)
            else:
                _name = name.removesuffix('List')
                query_arr = query_str.split(b'&')
                # check for supported query strings
                if resource_map[request.path] == ['s','l']:
                    if len(query_arr) == 1:
                        if query_arr[0].startswith(b's'): return Response(dataclass_to_xml(obj), headers=_headers)
                        elif query_arr[0].startswith(b'l'):
                            _start = 0
                            l = int(query_arr[0].split(b'=')[1])
                            dic = obj.__dict__.copy()
                            dic.update({'results':min(l,obj.all-_start),_name: getattr(obj,_name)[_start:_start+l]})
                            resp = _Response(dataclass_to_xml(getattr(m,name)(**dic)), headers=_headers)
                            del dic
                            return  resp
                    s,_start = query_arr[0].split(b'=')
                    _start = int(_start)

                    if _start > obj.all-1:
                        return Response(dataclass_to_xml(getattr(m,name)(href= obj.href,all=obj.all,results = 0)),headers=_headers)
                    else:
                        _,l = query_arr[1].split(b'=')
                        l = int(l)
                        dic = obj.__dict__.copy()
                        dic.update({'results':min(l,obj.all-_start),_name: getattr(obj,_name)[_start:_start+l]})
                        resp = _Response(dataclass_to_xml(getattr(m,name)(**dic)), headers=_headers)
                        del dic
                        return  resp

    def get_paths(self):
        return self.resources.keys()

    def head(self,uri,output = 'http_resp'):
        return self.get(self,uri,output = 'http_resp')

    def put(self):
        # retrieve request info
        data , path = request.data , request.path
        # convert xml to dataclass
        obj = xml_to_dataclass(data.decode('utf-8'))
        obj.href = path
        if path in self.resources: status = '204'
        else:
            status = '201'
            _path = path.removesuffix(f"/{path.split('/')[-1]}")
            if _path in self.resources and 'List' in self.resources[_path].__class__.__name__:
                try:
                    getattr(self.resources[_path] , obj.__class__.__name__).append(obj)
                except: pass
        self.resources[path] = obj
        return _Response(status=status, headers=_headers)

    def post(self):
        # retrieve request info
        data = request.data
        path = request.path
        # print(data,path)
        # convert xml to dataclass
        obj = xml_to_dataclass(data.decode('utf-8'))
        # check if obj is posted at the end of list
        name = self.resources[path].__class__.__name__
        status = None
        if 'List' in name:
            # print(f'posting new ob at {path} to the list {name}')
            # check if refenced obj is already referenced by mRID in the list
            if 'mRID' in obj.__dict__:
                found = False
                l = getattr(self.resources[path],name[:-4])
                for idx,item in enumerate(l):
                    if item.mRID == obj.mRID:
                        found = True
                        href = f"{path}/{idx+1}"
                        obj.href = href
                        l[idx] = obj
                        try: server.resources[href] = obj
                        except Exception: print(href,' not in server')
                        status = 204
                        break
                if not found:
                    # update obj href in the list
                    obj.href = f"{path}/{getattr(server.resources[path],name[:-4]).__len__()+1}"
                    server.resources[obj.href] = obj
                    # append object to list end
                    getattr(server.resources[path],name[:-4]).append(obj)
                    status = 201
            else:
                # update obj href in the list
                obj.href = f"{path}/{getattr(server.resources[path],name.removesuffix('List')).__len__()+1}"
                # add obj resource to server
                # print(obj.__dict__)
                server.resources[obj.href] = obj
                # append object to list end
                getattr(server.resources[path],name[:-4]).append(obj)
                status = 201
            tmp_header = _headers.copy()
            tmp_header.update({'Location':obj.href})
        return _Response(status=status , headers=tmp_header)

    def delete(self): return _Response(status='204' , headers=_headers)

    def get_time(self) -> Response:
        # TODO fix for new stuff.
        # local_tz = datetime.now().astimezone().tzinfo
        # now_local = datetime.now().replace(tzinfo=local_tz)

        now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
        # now_utc = pytz.utc.localize(datetime.utcnow())
        local_tz = pytz.timezone(tzlocal.get_localzone().zone)
        now_local = datetime.now().replace(tzinfo=local_tz)

        start_dst_utc, end_dst_utc = [
            dt for dt in local_tz._utc_transition_times if dt.year == now_local.year
        ]

        utc_offset = local_tz.utcoffset(start_dst_utc - timedelta(days=1))
        dst_offset = local_tz.utcoffset(start_dst_utc + timedelta(days=1)) - utc_offset
        local_but_utc = datetime.now().replace(tzinfo=pytz.utc)

        tm = Time(currentTime=format_time(now_utc),
                    dstEndTime=format_time(end_dst_utc.replace(tzinfo=pytz.utc)),
                    dstOffset=TimeOffsetType(int(dst_offset.total_seconds())),
                    localTime=format_time(local_but_utc),
                    quality=None,
                    tzOffset=TimeOffsetType(utc_offset.total_seconds()))
        return _Response(dataclass_to_xml(tm),headers=_headers)

    def put_flowreservationrequest(self):
        # retrieve request info
        data , path = request.data , request.path
        # convert xml to dataclass
        obj = xml_to_dataclass(data.decode('utf-8'))
        # get path to frq list
        _path = path.removesuffix(f"/{path.split('/')[-1]}")
        frq_list = self.resources[_path]
        if path in self.resources:
            status = '204'
            obj.href = path
            d = diff_between_obj(obj,self.resources[path])
            if d == ['RequestStatus']: self.resources[path] = obj
            else: return _Response(status=400,headers=_headers)
        else:
            status = '201'
            # check if a previous request has the same mRID
            for frq in frq_list.FlowReservationRequest:
                if frq.mRID == obj.mRID:
                    return Response(status=400,headers=_headers)
            # append frq to frq list
            frq_list.FlowReservationRequest.append(obj)
        return  _Response(status=status,headers=_headers)

    def interactive(self):
        while True:
            s = input('Write command\n')
            if s == 'clear': os.system('cls')
            elif s == 'stop': sys.exit()
            else:
                arr = s.split(' ')
                print(arr)
                try: 
                    if len(arr) == 1: 
                        r = getattr(self,arr[0])()
                        print(r)
                    else:
                        func =  arr[0]
                        if func == 'get_point': print(server.get_point(arr[1]))
                        elif func == 'add_dc': 
                            key_val = json.loads(arr[1])
                            print(server.add_dc(key_val=key_val))
                        elif func == 'update_settings': 
                            key_val = json.loads(arr[1])
                            print(key_val)
                            print(server.update_settings(key_val=key_val))
                except Exception as e: logger.exception('Got error')
        return
    
    def initialize():
        return

def test_init_server():
    myserver = IEEE_2030_5_server()
    myserver.init_server(server = cfg.get('server'))
    myserver.register_devices(devices = cfg.get('devices'))
    for k,v in myserver.resources.items():
        print(k)
        print(dataclass_to_xml(v))
        print()
    while True: time.sleep(2)
    sys.exit()
    return 
test_init_server()

def test():
    import sys
    server = IEEE_2030_5_server()
    value =  {'duration':10,'start':1200,'energyAvailable':10,
               'powerAvailable':1,'subject':b'al'}
    path = '/edev/1/frp'
    server.resources[path] = FlowReservationResponseList(href=path,all=0)
    server.set_frp(path=path,value= value)
    value['start'] = 1208
    server.set_frp(path=path,value= value)
    value['start'] = 1218
    server.set_frp(path=path,value= value)
    value['start'] = 1228
    server.set_frp(path=path,value= value)
    value['start'] = 1238
    server.set_frp(path=path,value= value)
    sys.exit()
# test()
if __name__ == '__main__':
    lfdi = compute_lfdi()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER,purpose = 'CLIENT_AUTH')
    ssl_ctx.load_verify_locations('tls/certs/ca.pem')
    ssl_ctx.load_cert_chain('tls/certs/01.pem','tls/private/0.0.0.0:7000.pem')
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    # ssl_ctx = build_context()
    # ssl_ctx._msg_callback = clbck
    server = IEEE_2030_5_server()
    server.flask_app.add_url_rule(rule = f'/derp',view_func=server.handle_request, methods = ['GET','PUT'])
    server.flask_app.add_url_rule(rule = f'/derp/<derp_id>',view_func=server.handle_request, methods = ['GET','PUT'])
    server.flask_app.add_url_rule(rule = f'/derp/1/<c_id>',view_func=server.handle_request, methods = ['GET','PUT'])

    # TODO add templace /edev/{}/frq/<> to flask
    server._add_resource(DeviceCapability(href='/dcap',
                                          EndDeviceListLink=EndDeviceListLink('/edev'),
                                          TimeLink=TimeLink('/tm'),
                                          UsagePointListLink=m.UsagePointListLink('/upt'),
                                          MirrorUsagePointListLink=MirrorUsagePointListLink('/mup'),
                                          DERProgramListLink = DERProgramListLink(f"/derp")))
    server._add_resource(EndDeviceList(href='/edev',all=0,results=0))
    server._add_resource(Time(href='/tm'))
    server._add_resource(MirrorUsagePointList(href='/mup',all=0,results=0))
    server._add_resource(DERProgramList(href='/derp',
                                        DERProgram=[
                                            DERProgram(href =f'/derp/1',
                                                       DefaultDERControlLink=f"/derp/1/dderc")
                                        ]))
    print(server.resources.keys())
    server._add_resource(server.resources['/derp'].DERProgram[0])
    server._add_resource(DefaultDERControl(href=f"/derp/1/dderc"))

    for i in range(1,2):
        edev = EndDevice(href=f'/edev/{i}', changedTime= time.time().__ceil__(),sFDI=12749470,
                           PowerStatusLink=PowerStatusLink(href=f'/edev/{i}/ps'),
                           DERListLink=DERListLink(f'/edev/{i}/der',all=1),
                           FunctionSetAssignmentsListLink=FunctionSetAssignmentsListLink(f'/edev/{i}/fsa'),
                           FlowReservationRequestListLink=FlowReservationRequestListLink(f'/edev/{i}/frq'),
                           FlowReservationResponseListLink=FlowReservationResponseListLink(f'/edev/{i}/frp'))
        server._add_resource(edev)
        server.resources['/edev'].EndDevice.append(edev)
        server.resources['/edev'].all +=1
        server.resources['/edev'].results +=1
        server._add_resource(PowerStatus(href=f'/edev/{i}/ps'))
        server._add_resource(ResponseList(href=f'/rsps/{i}/rsp'))
        server._add_resource(ResponseList(href=f'/rsps/{i}/rsp'))
        der_list = DERList(href=f'/edev/{i}/der',all=1,results=1)
        for j in range(1,2):
            der = DER(href=f'/edev/{i}/der/{j}',
                        DERAvailabilityLink=DERAvailabilityLink(href=f'/edev/{i}/der/{j}/dera'),
                        DERCapabilityLink=DERCapabilityLink(href=f'/edev/{i}/der/{j}/dercap'),
                        DERSettingsLink=DERSettingsLink(href=f'/edev/{i}/der/{j}/derg'),
                        DERStatusLink=DERStatusLink(href=f'/edev/{i}/der/{j}/ders'),
                        )
            server._add_resource(der)
            server._add_resource(DERAvailability(href=f'/edev/{i}/der/{j}/dera'))
            server._add_resource(DERCapability(href=f'/edev/{i}/der/{j}/dercap'))
            server._add_resource(DERSettings(href=f'/edev/{i}/der/{j}/derg'))
            server._add_resource(DERStatus(href=f'/edev/{i}/der/{j}/derstat'))
            der_list.DER.append(der)
        server._add_resource(der_list)
        server._add_resource(FlowReservationRequestList(href=f'/edev/{i}/frq',all=0,results=0))
        server._add_resource(FlowReservationResponseList(href=f'/edev/{i}/frp',all=0,results=0))
        server.flask_app.add_url_rule(rule = f'/edev/{i}/frq/<frq_id>',view_func=server.handle_request, methods = ['GET','PUT'])
        server.flask_app.add_url_rule(rule = f'/edev/{i}/frp/<frp_id>',view_func=server.handle_request, methods = ['GET','PUT'])
    # server.rpc_agent = PyRpc(name=f'{server.name}',tcpaddr=f'{addr_vpn}:{rpc_port}')
    # server.rpc_agent.publishService(server.set_point)
    # server.rpc_agent.publishService(server.get_point)
    # server.rpc_agent.publishService(server.get_frq)
    # server.rpc_agent.publishService(server.set_frp)
    # server.rpc_agent.start()
    
    if encript: Thread(target = server.flask_app.run, kwargs={'host':addr,'port':http_port,'ssl_context':ssl_ctx}).start()
    else: Thread(target = server.flask_app.run, kwargs={'host':addr,'port':http_port,'ssl_context':None}).start()
    # ssl_ctx.session_stats
    server.interactive()