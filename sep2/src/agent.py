import sep as xsd_models
import os, time , sys , ssl , logging , pytz , yaml , xmltodict , tzlocal
from flask import request, Response  as _Response, Flask
from constants import *
from enums import *
from types_ import *
from utils import *
from end_device import EndDevice 
from datetime import datetime , timedelta , timezone
from threading import Thread
from cryptography.hazmat.primitives import hashes , serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from  ipaddress import IPv4Address

# region get agent configuration
with open('config/config.yml','r') as f: cfg = yaml.safe_load(f)
sep2_wadl_xml = cfg.get('sep2_wadl').get('path')
with open(sep2_wadl_xml,'r') as f: data_dict = xmltodict.parse(f.read())
encript = cfg.get('server').get('encript',False)
ip_addr , port = cfg.get('server').get('ip','127.0.0.1') , cfg.get('server').get('port')
if encript: 
    cafile = cfg.get('server').get('certificates').get('cafile')
    keyfile = cfg.get('server').get('certificates').get('keyfile') 
    certfile = cfg.get('server').get('certificates').get('certfile')
#endregion

# region logging
_log = logging.getLogger(__name__)
logging.basicConfig(level="DEBUG", format='%(asctime)s  - [%(levelname)s] %(message)s', filemode='w')
#endregion

class IEEE2030_5Agent():
    """
    Agent that handles IEEE 2030.5 communication 
    """
    
    def __init__(self) -> None:

        self.devices = {}

    def register_devices(self, devices):
        """ Register IEEE 2030.5 end devices.

        :param devices: End devices from agent config file.
        :type devices: List

        :return: Dictionary of EndDevice objects keyed by ID.
        """
        _log.debug("Loading Devices: {}".format(self.__class__.__name__))
        for device in devices:
            # end device object
            edev = xsd_models.EndDevice(
            href= f'/edev/{self.id+1}',
            lFDI= self.lfdi.encode('utf-8').hex(),
            sFDI= int(self.sfdi.encode('utf-8')),
            PowerStatusLink = xsd_models.PowerStatusLink(href=f'/edev/{self.id+1}/ps'),
            FunctionSetAssignmentsListLink=xsd_models.FunctionSetAssignmentsListLink(href=f'/edev/{self.id+1}/fsa',all=1),
            RegistrationLink=xsd_models.RegistrationLink(f'/edev/{self.id+1}/rg'),
            DERListLink=xsd_models.DERListLink(href=f'/edev/{self.id+1}/der',all=1),
            DeviceInformationLink= xsd_models.DeviceInformationLink(href=f'/edev/{self.id+1}/dstat')
            )
        end_devices = self.devices
        for device in devices:
            if device['sfdi'] not in [k.sfdi for k in end_devices.values()]:
                d = EndDevice(sfdi=device["sfdi"],
                              lfdi=device["lfdi"],
                              load_shed_device_category=device["load_shed_device_category"],
                              pin_code=device["pin_code"])
                end_devices[d.id] = d
            else:
                d = self.get_end_device(sfdi=device['sfdi'])
                d.lfdi = device['lfdi']
                d.load_shed_device_category = device['device_category']
                d.pin_code = device['pin_code']
        old_indices = []
        for index, d in end_devices.items():
            if d.sfdi not in [device['sfdi'] for device in devices]:
                old_indices.append(index)
        for i in old_indices:
            end_devices.pop(i)
        return end_devices