import time
# import atexit
# import ssl
import sys , re
# import http.client as client
# from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
# from pprint import pprint
import argparse
import os , time , json
from typing import Dict, Optional
from threading import Thread,Timer
# import OpenSSL
import ieee_2030_5.models.constants as constants
from ieee_2030_5.client import IEEE2030_5_Client
from ieee_2030_5 import models as m
from ieee_2030_5.utils import dataclass_to_xml,xml_to_dataclass
import logging
from datetime import datetime
# import xml.etree.ElementTree as ET
from apscheduler.schedulers.background import BackgroundScheduler
# import xsdata
# import xml.dom.minidom
# from bs4 import BeautifulSoup
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
# from multiprocessing import Queue
import requests
from threading import Thread
from uuid import uuid1
import requests
import sunspec2.modbus.client as sunspec_client
import enum

Dir = 'sae3072_xmls'
# Dir ='Examples'
Dir = os.path.join(os.path.dirname(os.path.realpath(__file__)),Dir)
_now = datetime.now

logger = logging.getLogger(__name__)
logging.basicConfig(level="DEBUG", format='%(asctime)s  - [%(levelname)s] %(message)s', filemode='w')

# d = sunspec_client.SunSpecModbusClientDeviceTCP(slave_id=1, ipaddr='192.168.226.20', ipport=502)
# d.scan()

ActivePowerReadingType = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Reverse,
    kind=constants.KindType.Power,
    uom=constants.UomType.W)

ReactivePowerReadingType = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Reverse,
    kind=constants.KindType.Power,
    uom=constants.UomType.VAr)

VoltageReading = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Forward,
    phase=constants.PhaseCode.Phase_AB,
    uom=constants.UomType.Voltage)    

FrequencyReadingType = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Forward,
    uom=constants.UomType.Hz)


def populate_from_kwargs(obj,**kwargs):
    for key,val in kwargs.items():
        if key in obj.__dict__: 
            if isinstance(val,dict): 
                _field = obj.__dataclass_fields__.get(f"{key}")
                dclass = re.findall(r'\[.*?\]',_field.type)[0].replace('[','').replace(']','')
                setattr(obj,key,getattr(m,dclass)(**val))
            else: setattr(obj,key,val)   

def find_field_class(obj , key):
    _field = obj.__dataclass_fields__.get(f"{key}")
    _field_class = re.findall(r'\[.*?\]',_field.type)[0].replace('[','').replace(']','')    
    return _field_class

def parse_str_obj(str_obj):
    print(str_obj)
    idx = str_obj.find('(')
    obj_cls = str_obj[:idx]
    print(str_obj)
    params = str_obj[idx+1:]
    print(params)
    obj = getattr(m,obj_cls)()
    for f in obj.__dataclass_fields__: 
        idx = params.find(f)
        if idx == -1: continue
        f_class = find_field_class(obj,f)
        if f_class in m.__dict__:
            print(f_class)
            open_p_idx , closed_p_idx = params.find('(',idx) , params.find(')',idx)
            print(open_p_idx , closed_p_idx)
            print(params[open_p_idx:])
            f_params = params[open_p_idx+1:closed_p_idx]
            sub_field = getattr(m,f_class)()
            print(f_params)
            for key_val in f_params.split(','):
                print(key_val)
                key,val  = key_val.split('=')
                key_cls = find_field_class(sub_field,key)
                if key_cls == 'int': val = int(val)
                elif key_cls == 'bytes': val = bytes(val.encode())
                setattr(sub_field,key,val)
                # print(sub_field)
            setattr(obj,f,sub_field)
            # print(obj)
        else:
            cm_idx = params.find(',',idx)
            key_val = params[idx:cm_idx-1]
            key,val  = key_val.split('=')
            key_cls = find_field_class(obj,key)
            if key_cls == 'int': val = int(val)
            elif key_cls == 'bytes': val = bytes(val.encode())
            setattr(obj,key,val)    
            # print(obj)    
        
    return obj

def obj_from_xml_file(f='dercap.xml'):
    if '.xml' not in f: f = f'{f}.xml'
    with open(f"{Dir}/{f}",'r') as file:
        xml = file.read()
        return xml_to_dataclass(xml)

def read_xml(f='dercap'):
    if '.xml' not in f: f = f'{f}.xml'

    with open(f"{Dir}/{f}",'rb') as file:
        return file.read()

def _value(o):
    return o.value*pow(10,o.multiplier)

def start_mqtt(callbacks = {},
                host = 'localhost',
                port = 1883,
                **kwargs):
    client = mqtt.Client()
    client.connect(host=host,port=port,**kwargs)
    for k,v in callbacks.items():
        client.subscribe(k)
        client.message_callback_add(k,v)
    client.loop_start()    
    logger.debug('mqtt client launched')
    return client

def read_sunspec_modbus():
    t0 = time.time()
    d.inverter[0].read() , d.battery[0].read()
    d1 , d2 = d.inverter[0].get_dict(True) , d.battery[0].get_dict(True)
    dic={'i': d1.get('A'),'u':d1.get('PPVphAB'),'p':d1.get('W'),'f':d1.get('Hz'),'var': d1.get('VAr'),'t':d1.get('TmpCab'),'soc':d2.get('SoC')}
    print(time.time()-t0,dic)
    return dic 

ActivePowerReadingType = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Reverse,
    kind=constants.KindType.Power,
    uom=constants.UomType.W)

ReactivePowerReadingType = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Reverse,
    kind=constants.KindType.Power,
    uom=constants.UomType.VAr)

VoltageReading = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Forward,
    phase=constants.PhaseCode.Phase_AB,
    uom=constants.UomType.Voltage)    

FrequencyReadingType = m.ReadingType(
    accumulationBehaviour=constants.AccumlationBehaviourType.Instantaneous,
    commodity= constants.CommodityType.Electricity_secondary_metered,
    flowDirection=constants.FlowDirectionType.Forward,
    uom=constants.UomType.Hz)

class IEEE2030_5_Client_Ext():
    
    def der_list(self, edev_index: Optional[int] = 0) -> m.DERList:
        der_list = self.__get_request__(self.end_device(edev_index).DERListLink.href)
        self._derlist = der_list
        return der_list

    def update_status_on_server(self , info , obj):
        # call end device list if yet called
        if not self._end_devices : self.end_devices()
        # object link
        obj_link = f"{info}Link"
        # check if obj_link is in edev or der
        obj_link_inst = getattr(self._end_devices.EndDevice[0], obj_link,None)
        if obj_link_inst is None:
            # TODO cache links upon first retrieval
            self.der_list()
            obj_link_inst = getattr(self._derlist.DER[0],obj_link)
        # update href
        href = obj_link_inst.href
        obj.href = href
        # populate object
        # populate_from_kwargs(obj,**params)
        # send info to server
        r = self.__put__(href,dataclass_to_xml(obj))
        return r
    
    def derp_job(self,derp):
        for derProg in derp.DERProgram:
            prog_primacy = derProg.primacy
            ctrls = [key.removesuffix('Link') for key,val in derProg.__dict__.items() if 'Link' in key and val is not None]
            if 'DefaultDERControl' in ctrls:
                # client.poll_timer(client.request,derProg.DefaultDERControlLink.href)
                self.request(derProg.DefaultDERControlLink.href)
            if 'DERControlList' in ctrls:
                # client.poll_timer(client.request,derProg.DERControlListLink.href)
                self.request(derProg.DERControlListLink.href)
            if 'DERCurveList' in ctrls:
                # client.poll_timer(client.request,derProg.DERControlListLink.href)
                self.request(derProg.DERCurveListLink.href)

    def dcap_job(self):
        def job_func():
            # print('job execution')
            self.device_capability()
            # r = requests.get('https/dcap',timeout=30)
            # print(r.__dict__)
            # if r.status_code == 200:
            #TODO: check if dcap has changed and publish new instance via mqtt
        if not self._device_cap: self.device_capability()
        self.scheduler.add_job(job_func,'interval', seconds = self._device_cap.pollRate,id='dcap-job')
        
    def edev_job(self):
        if not self._end_devices: self.end_devices()
        self.scheduler.add_job(self.end_devices,'interval', seconds = self._end_devices.pollRate,id='edev-job')
        #TODO: check if edev has changed and publish new instance via mqtt

    def der_job(self):
        self.der_list()
        self.scheduler.add_job(self.der_list,'interval', seconds = self._derlist.pollRate,id='der-job')
        #TODO: check if edev has changed and publish new instance via mqtt

    def __get__(self, url: str, body=None, headers: dict = None, print_transaction = True):
        if headers is None:
            headers = {"Connection": "keep-alive", "keep-alive": "timeout=30, max=1000"}

        if print_transaction:
            print(f"----> GET REQUEST")
            print(f"url: {url} body: {body}")
        self.http_conn.request(method="GET", url=url, body=body, headers=headers)
        response = self._http_conn.getresponse()
        response_data = response.read().decode("utf-8")
        # print(response.headers)

        response_obj = None
        try:
            response_obj = xml_to_dataclass(response_data)
            resp_xml = xml.dom.minidom.parseString(response_data)
            if resp_xml and print_transaction:
                print(f"<---- GET RESPONSE")
                print(f"{response_data}")  # toprettyxml()}")

        except xsdata.exceptions.ParserError as ex:
            if self._debug:
                print(f"<---- GET RESPONSE")
                print(f"{response_data}")
            response_obj = response_data

        return response_obj    
    
    def __put__(self, url: str, data=None, headers: Optional[Dict[str, str]]=None,print_transaction = False):
        if not headers: headers = {'Content-Type': 'text/xml','Location':url}
        self.http_conn.request(method="PUT", headers=headers,url=url, body=data)
        response = self._http_conn.getresponse()
        if response and print_transaction:
            print(response.headers.as_string())
            print(response.read().decode("utf-8"))
        # response_data = response.read().decode("utf-8")
        return response

class SEP_2_Client():

    def __init__(self,
                 dev_id = 1,
                 cafile : Optional[str] = None,
                 certfile : Optional[str] = None,
                 keyfile : Optional[str] = None,
                 server_hostname: Optional[str] = '127.0.0.1',
                 server_port : Optional[int] = 8443,
                 debug: bool = True):   
        self.dev_id = dev_id
        self._server_hostname = server_hostname
        self._server_port = server_port
        self._key = keyfile
        self._cert = certfile
        self._ca = cafile    
        self._scheduler = BackgroundScheduler()    
        # process certificate
        self._ssl_context = None
        if False:
            # if ssl_context.__contains__('certfile') and ssl_context.__contains__('keyfile') and ssl_context.__contains__('cafile'):
            #     # load files from ssl_context argument
            #     cafile , keyfile , certfile = ssl_context.get('cafile') , ssl_context.get('keyfile') , ssl_context.get('certfile') 
                # cafile = cafile if isinstance(cafile, PathLike) else Path(cafile)
                # keyfile = keyfile if isinstance(keyfile, PathLike) else Path(keyfile)
                # certfile = certfile if isinstance(certfile, PathLike) else Path(certfile)
                # assign files to instance
                self._key = keyfile
                self._cert = certfile
                self._ca = cafile
                # manage __ssl_context param
                # self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                # self._ssl_context.check_hostname = False
                # self._ssl_context.verify_mode = ssl.CERT_OPTIONAL  #  ssl.CERT_REQUIRED
                # self._ssl_context.load_verify_locations(cafile=cafile)
                # # Loads client information from the passed cert and key files. For
                # # client side validation.
                # self._ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
                # # check if really files exist
                # assert cafile.exists(), f"cafile doesn't exist ({cafile})"
                # assert keyfile.exists(), f"keyfile doesn't exist ({keyfile})"
                # assert certfile.exists(), f"certfile doesn't exist ({certfile})"
        # Initialize attributes
        self._dcap: Optional[m.DeviceCapability] = None
        self._mup: Optional[m.MirrorUsagePointList] = None
        self._upt: Optional[m.UsagePointList] = None
        self._edev: Optional[m.EndDeviceList] = None
        self._sdev: Optional[m.SelfDevice] = None
        self._der: Optional[m.DERList] = None
        self._fsa: Optional[m.FunctionSetAssignmentsList] = None        
        self._derp: Optional[m.DERProgramList] = None        
        self._derc: Optional[m.DERControlList] = None        
        self._dderc: Optional[m.DefaultDERControl] = None        
        self._dc: Optional[m.DERCurveList] = None        

    def build_url(self,path,hostname = None , port = None,headers = None, encript = False,verify = True, cert = None):
        if hostname is None: host = self._server_hostname
        else: host = hostname
        if port is None: port = self._server_port
        else: port = port
        if encript: url = 'https'
        else: url = 'http'
        url = f"{url}://{host}:{port}/{path}"
        return url        
    
    def handle_attr_changes(self,attr):

        return
    
    def attr_changed(self,attr,other):
        attr_class = self.__getattribute__(attr).__class__
        if not isinstance(other,attr_class):
            raise(f'cant compare objet from class {attr_class} to objet from {other.__class__}')
        return self.__getattribute__(attr).__dict__ != other.__dict__
    
    def add_job(self,func,seconds,kwargs,id = None):
        func(**kwargs)
        self._scheduler.add_job(func,trigger='interval',seconds=seconds,id = id,kwargs=kwargs)
        #TODO publish new instance if changed , put topic in kwargs
        return

    def get_resource(self,resource = '',debug=False):
        """
        resources
            dcap = device capability \n
            edev = end device        \n
            sdev = self device       \n
            reg =  registration       \n
            frp =  flow reservation response\n
        """
        dic = {'dcap':'dcap'}

        return
    
    def device_capability(self,url='dcap',debug = False):
        self._dcap = self.__get__(url,debug=debug)
        return self._dcap

    def self_device(self,debug=False):
        if self._dcap is  None: self.device_capability(debug=debug)
        self._sdev = self.__get__(self._dcap.SelfDeviceLink.href)
        return self._sdev

    def end_device_list(self,debug = False):
        if self._dcap is None: self.device_capability(debug=debug)
        self._edev = self.__get__(self._dcap.EndDeviceListLink.href,debug=debug, encript= True)
        return self._edev

    def registration(self, debug = False):
        if self._edev is None: self.end_device_list(debug)
        self._reg = self.__get__(self._edev.EndDevice[0].RegistrationLink.href,debug=debug)
        return self._reg
    
    def der_list(self,debug = False):
        if self._edev is None: self.end_device_list(debug=debug)
        self._der = self.__get__(self._edev.EndDevice[0].DERListLink.href,debug=debug)
        return self._der

    def fsa_list(self,debug = False):
        if self._edev is None: self.end_device_list(debug=debug)
        self._fsa = self.__get__(self._edev.EndDevice[0].FunctionSetAssignmentsListLink.href,debug=debug)
        return self._fsa
    
    def derp_list(self,fsa_index = 0, debug = False):
        if self._fsa is None: self.fsa_list(debug=debug)
        self._derp = self.__get__(self._fsa.FunctionSetAssignments[fsa_index].DERProgramListLink.href,debug=debug)
        return self._derp

    def dderc(self,derp_index = 0,debug = False):
        if self._derp is None: self.derp_list(debug=debug)    
        self._dderc = self.__get__(path=self._derp.DERProgram[derp_index].DefaultDERControlLink.href, debug=debug)
        return self._dderc
    
    def derc(self,derp_index = 0, debug = False):
        if self._derp is None: self.derp_list(debug=debug)
        self._derc = self.__get__(path=self._derp.DERProgram[derp_index].DERControlListLink.href) 
        return self._derc     
    
    def dc(self, derp_index = False, debug = False):
        if self._derp is None: self.derp_list(debug=debug) 
        self._dc = self.__get__(path=self._derp.DERProgram[derp_index].DERCurveListLink.href,debug=debug)
        return self._dc

    def frp(self,debug=False):
        if self._edev is None: self.end_device_list(debug=debug)
        self._frp = self.__get__(self._edev.EndDevice[0].FlowReservationResponseListLink.href,debug=debug)
        obj = m.FlowReservationResponse(EventStatus=m.EventStatus(0,10,False),
                                        interval=m.DateTimeInterval(10,100),
                                        energyAvailable=m.SignedRealEnergy(3,12),
                                        powerAvailable=m.ActivePower(3,4))
        self._frp.FlowReservationResponse = [obj,obj,obj]
        data = []
        t0 = time.time()
        for _frp in self._frp.FlowReservationResponse:
            tmp = _frp.__dict__.copy()
            tmp['responseRequired'] = int.from_bytes(tmp['responseRequired'],byteorder='big')
            for item in ['EventStatus','interval']:
                if tmp[item] is not None: tmp[item] = tmp[item].__dict__
            for item in ['energyAvailable','powerAvailable']:
                if tmp[item] is not None: tmp[item] = _value(tmp[item])
            data.append(tmp)
        self.mqtt.publish('frp',payload=json.dumps(data,default=str))
        logger.debug(f"published {data} on topic frp within {time.time()-t0}")
        return

    def start_mqtt(self,
                   callbacks = {},
                   host = 'localhost',
                   port = 1883,
                   **kwargs):
        self.mqtt = mqtt.Client()
        self.mqtt.connect(host=host,port=port,**kwargs)
        for k,v in callbacks:
            self.mqtt.subscribe(k)
            self.mqtt.message_callback_add(k,v)
        self.mqtt.loop_start()
        return

    def __get__(self, path , 
                hostname = None , 
                port = None,
                headers = None, 
                encript = False,
                verify = None, 
                cert = None,
                debug = False, 
                _return = 'obj'):
        t0 = time.time()
        url = self.build_url(path,hostname = hostname , port = port,headers = headers, encript = encript,verify = verify, cert = cert)
        if encript: 
            if cert is None: cert = (self._cert,self._key)
            if verify: verify = self._ca        
        # print(url)
        if headers is None: headers = {"Connection": "keep-alive", "keep-alive": "timeout=0, max=10"}
        r = requests.get(url,verify=verify,headers= headers, cert=cert)
        d = time.time()-t0
        if d > 0.1: logger.debug(f"get request to path {path} took {round(d)} sec with status {r.status_code}")
        _xml = r._content.decode('utf-8')
        if _return == 'raw': ret = r
        else: ret = xml_to_dataclass(_xml)
        if r.status_code == 200: 
            if debug: 
                logger.debug(f"Got reply to GET {url} from the server")
                # print(f"HEADERS\n")
                for k,v in r.headers.items(): print(k,' : ',v)
                print()
                # print(f"BODY\n")
                print(r._content.decode('utf-8'))
        return ret

    def __put__(self, path , data, hostname = None , port = None,headers = None, encript = False,verify = True, cert = None):
        t0 = time.time()
        url = self.build_url(path,hostname = hostname , port = port,headers = headers, encript = encript,verify = verify, cert = cert)
        if encript: 
            if cert is None: cert = (self._cert,self._key)
            if verify: verify = self._ca             
        if headers is None: headers = {"Connection": "keep-alive", "keep-alive": "timeout=30, max=1000"}
        r = requests.put(url,data,verify=verify,headers= headers, cert=cert)
        d = time.time()-t0
        if r.status_code != 204 or d > 0.1: print(datetime.now(),path,d,r.status_code)
        return r

    def __post__(self, path , data, hostname = None , port = None,headers = None, encript = False,verify = True, cert = None):
        t0 = time.time()
        url = self.build_url(path,hostname = hostname , port = port,headers = headers, encript = encript,verify = verify, cert = cert)
        if encript: 
            if cert is None: cert = (self._cert,self._key)
            if verify: verify = self._ca             
        if headers is None: headers = {"Connection": "keep-alive", "keep-alive": "timeout=30, max=1000"}
        r = requests.post(url,data,verify=verify,headers= headers, cert=cert)
        d = time.time()-t0
        if r.status_code != 201 or d > 0.1: print(datetime.now(),path,d,r.status_code)
        return r

    def run_3072(self,server_hostname = None, server_port=None, encript = True,verify = True, cert = None):
        logger.debug('running sae j3072 client autonomously')
        # region discover resources
        t0=time.time()
        self.device_capability() # retrieve dcap
        self.self_device()       # retrieve sdev
        sdev_der:m.DER = xml_to_dataclass(self.__get__(self._sdev.DERListLink.href)._content.decode()).DER[0]  # retrieve sdev der
        self.end_device_list()   # retrieve edev
        self.fsa_list() # retrieve fsa
        self.der_list() # retrieve der
        logger.debug(f'Resources discovery finished within {round(time.time()-t0,5)}')
        # endregion
        
        # region initial information exchange
        ## get site limits
        sdev_set = xml_to_dataclass(self.__get__(sdev_der.DERSettingsLink.href)._content.decode())  # retrieve sdev settings
        logger.debug('got site limits info')
        ## process sdev settings here ....
        logger.debug('processed evse site limits info ; pev info pending')
        ## send config to evse
        t0 = time.time()
        # send settings to server
        self.__put__(self._der.DER[0].DERSettingsLink.href,read_xml('derg.xml'))
        # send di to server
        self.__put__(self._edev.EndDevice[0].DeviceInformationLink.href,read_xml('di.xml'))
        # send dera to server
        self.__put__(self._der.DER[0].DERAvailabilityLink.href,read_xml('dera.xml'))
        # send dercap to server
        self.__put__(self._der.DER[0].DERCapabilityLink.href,read_xml('dercap.xml'))
        # send ders to server
        self.__put__(self._der.DER[0].DERCapabilityLink.href,read_xml('ders.xml'))
        logger.debug(f'first steps exchange with evse terminated witin {time.time()-t0}')
        # endregion

        # region get manage information derc , dderc , dc
        self.derp_list()   # retrieve management data
        ## send event received and event started response before being authorized to discharge 
        # check if authorization is granted
        self.disch_auth = self._dderc.DERControlBase.opModEnergize
        print(datetime.now(), 'authorization to discharge: ' ,self.disch_auth)
        # endregion

        # region continuoius periodic operation monitoiring
        # controls
        self.add_job(self.derp_list,1,kwargs={},id = 'derp-job') # TODO: Handle authorization inside main job communicate with real system
        # TODO: Add monitoring jobs with specific postrate: 
        # TODO: create main watcher
        # self.add_job(self.device_capability,1,kwargs={'url':'dcap'},id = 'dcap-job')
        # self.add_job(self.end_device_list,1,kwargs={'url':self._dcap.EndDeviceListLink.href},id ='edev-job')
        # self.add_job(self.der_list,1,kwargs={'url':self._edev.EndDevice[0].DERListLink.href}, id= 'der-job')
        # self.add_job(self.fsa_list,1,kwargs={'url':self._edev.EndDevice[0].FunctionSetAssignmentsListLink.href},id = 'fsa-job')
        # start the client scheduler 
        self._scheduler.start() 
        time.sleep(1) 
        # endregion

        while True:
            # track attr changes ; and update job freq
            # send responses to ctrl
            # post monitoring data mup
            # track device and der state (read db for example); and post it to server
            # post di
            self.__put__(self._edev.EndDevice[0].DeviceInformationLink.href,data=read_xml('di'))
            # post ps
            self.__put__(self._edev.EndDevice[0].PowerStatusLink.href,data=read_xml('ps'))
            # post dercap
            self.__put__(self._der.DER[0].DERCapabilityLink.href,data=read_xml('dercap'))
            # post derg
            self.__put__(self._der.DER[0].DERSettingsLink.href,data=read_xml('derg'))
            # post dera
            self.__put__(self._der.DER[0].DERAvailabilityLink.href,data=read_xml('dera'))
            # post ders
            self.__put__(self._der.DER[0].DERStatusLink.href,data=read_xml('ders'))
            time.sleep(1)
        return

    def run_interactive(self):
        while True:
            s = input()
            try:
                if s.startswith('put') or s.startswith('post'):
                    meth,path,f = s.split(' ')
                    _xml = read_xml(f)
                    if meth == 'put': r=self.__put__(path,_xml)
                    else:  r = self.__post__(path,_xml)
                    print(r.status_code,r.__getattribute__('headers'))
                elif s == 'clear': os.system('cls')
                elif s == 'stop': sys.exit()
                else: 
                    r = self.__get__(s,debug=True,_return ='raw')
                    # print(r._content.decode('utf-8'))
            except Exception as e: print(e)

    def run_frq(self):
        logger.debug('running sep2 client autonomously')

        # region start mqtt client
        self.start_mqtt()
        # endregion
        
        # region discover resource
        t0=time.time()
        self.der_list(True)
        while True: 
            self.frp(True)
            time.sleep(1)
        logger.debug(f'Resources discovery finished within {round(time.time()-t0,5)}')
        # endregion
        
        return
        capa = 23760
        init_soc = 0.65
        rate = 6500
        evse_rate = 7000
        tcin = _now().timestamp().__ceil__() + 16000
        soc =init_soc
        frp = m.FlowReservationResponse()
        p_allowed = 0
        tresp = _now().timestamp().__ceil__()

        ereq =  3600 * (init_soc - 0.2) * 0.9
        durationRequested = int(3600 * ereq / rate)
        now_s = _now().timestamp().__ceil__()
        # create and send a flow reservation request
        frq = m.FlowReservationRequest(mRID=uuid1().hex,description='test frq',
                                       creationTime=now_s,
                                       durationRequested=durationRequested,
                                       energyRequested = m.SignedRealEnergy(0, ereq),
                                       intervalRequested=m.DateTimeInterval(duration=16000,start=now_s + 10),
                                       powerRequested= m.ActivePower(0,rate),
                                       RequestStatus= m.RequestStatus(dateTime=now_s,requestStatus= 0)
                                       )
        self.__post__(path = f'/edev/{self.dev_id}/frq',data = dataclass_to_xml(frq))
        
        while True:
            new_frp = self.__get__(path = f'/edev/{self.dev_id}/frp',_return = 'object').FlowReservationResponse
            # print(new_frp)
            soc = soc - p_allowed * 0.9 * (_now().timestamp().__ceil__() - tresp) / 3600 / capa
            if len(new_frp) > 0:
                new_frp = new_frp[-1]
                if frp != new_frp: 
                    tresp = _now().timestamp().__ceil__()
                    frp = new_frp
                p_allowed = _value(frp.powerAvailable)
            erem = int(soc*capa)
            ps = m.PowerStatus(href=f'/edev/{self.dev_id}/ps',batteryStatus=4,
                            changedTime=_now().timestamp().__ceil__(),
                            currentPowerSource=1,
                            estimatedChargeRemaining=int(soc*100),
                            PEVInfo=m.PEVInfo(chargingPowerNow=m.ActivePower(0,p_allowed),
                                                energyRequestNow=m.RealEnergy(0,erem),
                                                maxForwardPower=m.ActivePower(0,rate),
                                                minimumChargingDuration= int(erem/rate*3600),
                                                targetStateOfCharge=100,
                                                timeChargeIsNeeded=tcin,
                                                timeChargingStatusPEV=_now().timestamp().__ceil__()))
            self.__put__(path=f'/edev/{self.dev_id}/ps',data=dataclass_to_xml(ps))
            time.sleep(1)
        return

mup = m.MirrorUsagePoint(deviceLFDI=0,
                   roleFlags=constants.RoleFlagsType.IsSubmeter,
                   serviceCategoryKind=constants.ServiceKind.Electricity,
                   MirrorMeterReading=m.MirrorMeterReading(
                       ReadingType= ActivePowerReadingType,
                       Reading= m.Reading(
                               qualityFlags=constants.QualityFlagsType.Valid,
                               localID=1,
                               value= 10)
                                                          ),
                   postRate=15)

print(dataclass_to_xml(mup))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("--cert", default='tls\\certs\\dev1.pem',required=False,
                        help="Certificate file to use to connect to the 2030.5 server")
    parser.add_argument("--key", default='tls\\private\\dev1.pem',required=False,
                        help="Key file to use to connect to the 2030.5 server")
    parser.add_argument("--cacert", default='tls\\certs\\ca.pem', required=False,
                        help="CA Certificate file to use to connect to the 2030.5 server")
    parser.add_argument("--server", default='127.0.0.1',required=False,
                        help="The 2030.5 server to connect to")
    parser.add_argument("--port", default=7000, type=int,
                        help="The port to connect to the 2030.5 server on. (Default 443)")
    parser.add_argument("--pin", required=False, type=int,
                        help="PIN to validate that the client is registered with the server.")

    # cafile = "tls/certs/ca.pem"
    # certfile = "tls/certs/dev1.pem"
    # keyfile = "tls/private/dev1.pem"
    # server_hostname = '127.0.0.1'
    # server_port = 8443
    
    opts = parser.parse_args()
    curdir = os.path.dirname(os.path.realpath(__file__))

    for p in ["cert", "key", "cacert"]: setattr(opts, p, str(os.path.join(curdir,getattr(opts, p))))

    print(opts.cacert,opts.cert,opts.key,opts.server,opts.port)

    client = SEP_2_Client(cafile = opts.cacert,
                          certfile=opts.cert,
                          keyfile=opts.key,
                          server_hostname=opts.server,
                          server_port=opts.port)
    
    client.end_device_list(True)

    dic = read_sunspec_modbus()

    for item, descr in [('p','Active power') , ('f','Frequency') , ('u','Voltage') , ('var','Reactive power')]:
        mup = m.MirrorUsagePoint(
                    mRID= uuid1().hex,
                    description=f'{descr} mirror usage point',
                    deviceLFDI=client._edev.EndDevice[0].lFDI,
                    roleFlags=constants.RoleFlagsType.IsSubmeter,
                    serviceCategoryKind=constants.ServiceKind.Electricity,
                    status=1,
                    MirrorMeterReading=m.MirrorMeterReading(
                        mRID=uuid1().hex,
                        description=f'{descr} mirror meter reading',
                        ReadingType= ActivePowerReadingType,
                        Reading= m.Reading(
                                qualityFlags=constants.QualityFlagsType.Valid,
                                localID=1,
                                value= int(dic[item]))
                                                            ),
                    postRate=15) 
        m.UsagePoint()

        r = client.__post__(client._dcap.MirrorUsagePointListLink.href,data=dataclass_to_xml(mup), encript=True)
        print(r.headers)

    r = client.__get__('upt', encript=False)
    print(r.__dict__)

    
    # client.run_interactive()
    # print('starting new thread')
    # mqtt_client = start_mqtt(callbacks={'frp':lambda udata,a,message: logger.debug(f"Message payload from topic frp: {json.loads(message.payload)}")})
        
    # client.run_frq()
    # Thread(target = client.run_frq).start()
    # while True: time.sleep(1)
    # t = Thread(target = client.run_3072)
    # t.start()
    # t.join()
requests.get
#     hostname = "gridappsd_dev_2004"
#     dic = {}
#     #hostname = "google.com"
#     port = 7443

    
#     keys = "cert", "key", "cacert" # "server" , "port" , "pin"

#     for k in keys:
#         # path that is going to be expanded and resolved
#         test_path = getattr(opts, k)
#         test_path= dic[k]
#         print()
#         setattr(opts, k, str(os.path.join(os.path.curdir,test_path)))

#     x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,open(opts.cert, "rb").read())

#     # print(open(opts.cert, "rb").read())

#     print(f"Connecting to: {opts.server}:{opts.port} using subject: {x509.get_subject().CN}")

#     client = IEEE2030_5_Client_Ext(cafile=opts.cacert,
#                                server_hostname=opts.server,
#                                keyfile=opts.key,
#                                certfile=opts.cert,
#                                server_ssl_port=int(opts.port))
#     #disable debug
#     client._debug = False
#     # create scheduler
#     client.scheduler = BackgroundScheduler()
#     # add dcap job
#     client.dcap_job()
#     # add edev job
#     client.edev_job()
#     # handle der job
#     client.der_job()
#     # start scheduler 
#     client.scheduler.start()
#     # post di to server
#     client.__put__(client._end_devices.EndDevice[0].DeviceInformationLink.href,data=read_xml('di'))
#     while True:
#         # print(client._end_devices.EndDevice[0].PowerStatusLink.href)
#         try: client.__put__(client._end_devices.EndDevice[0].PowerStatusLink.href,data=read_xml('ps'))
#         except Exception as e: print(e)
#         time.sleep(0.1)
#     # There should be only a single device, unless this is an aggregator, which this
#     # would give the first response in the list.
#     end_device = client.end_device()
#     # get der instance
#     der = client.der_list().DER[0]
#     # post device information to server
#     client.__put__(end_device.DeviceInformationLink.href,data=read_xml('di'))
#     # post nameplate to server
#     client.__put__(der.DERCapabilityLink.href,data=read_xml('dercap'))
#     # post power status to server
#     client.__get__(end_device.PowerStatusLink.href)
#     client.__put__(end_device.PowerStatusLink.href,data=read_xml('ps'))
#     client.__get__(end_device.PowerStatusLink.href)
#     # post adjusted settings
#     client.__get__(der.DERSettingsLink.href)
#     client.__put__(der.DERSettingsLink.href,data=read_xml('derg'))
#     client.__get__(der.DERSettingsLink.href)
#     # post der availability
#     client.__get__(der.DERAvailabilityLink.href)
#     client.__put__(der.DERAvailabilityLink.href,data=read_xml('dera'))
#     client.__get__(der.DERAvailabilityLink.href)
#     # post der status
#     client.__get__(der.DERStatusLink.href)
#     client.__put__(der.DERStatusLink.href,data=read_xml('ders'))
#     client.__get__(der.DERStatusLink.href)
#     # get fsa list
#     fsa_list = client.function_set_assignment_list()
#     #iterate through fsa list
    
#     sys.exit()
#     # Check the first end device in the list to see if it is the same as the pin
#     # passed to the client script.  If not then exit the program with a note to
#     # check the pin.
#     if not client.is_end_device_registered(end_device, opts.pin):
#         print(f"End device ({x509.get_subject().CN}) not registered on server.  Check pin.")
#         sys.exit(0)
#     # retireve function sets assignment list
#     fsa_list = client.function_set_assignment_list()
#     # iterate through function sets assignments
#     for fsa in fsa_list.FunctionSetAssignments:
#         fs = [key.removesuffix('Link') for key,val in fsa.__dict__.items() if 'Link' in key and val is not None]
    
#         if 'Time' in fs: client.time()

#         if 'DERProgramList' in fs:
#             derp = client.der_program_list()
#             derp_rate = int(derp.pollRate)
#             job_id = f'DERProgramList-job-{fsa.mRID}'
#             derp_job = client.scheduler.get_job(job_id)
#             if derp_job is None: 
#                 derp_job = client.scheduler.add_job(client.derp_job,'interval', seconds = 5, kwargs = {'derp':derp},id=job_id)
#                 client.scheduler.start()
#                 client.scheduler._thread.join()
#     sys.exit()
#     while True:
#         s = input()
#         while False:
#             try: client.request(s)
#             except Exception as e: print(e)
#             time.sleep(1)       
#         if s == 'clear': os.system('cls')
#         elif s == 'stop': sys.exit()
#         elif s.split(' ')[0].upper().startswith('GET'):
#             cmds = s.split(' ')
#             if len(cmds) >= 2: client.request(cmds[1])
#         elif s.split(' ')[0].upper().startswith('P'):
#             cmds = s.split(' ')
#             print(cmds[0])
#             if len(cmds) >= 3: 
#                 uri = cmds[1]
#                 str_obj = cmds[2]
#                 print(str_obj)
#                 obj = parse_str_obj(str_obj)
#                 print(obj)
#                 if cmds[0] == 'POST': r = client.request(uri,body = dataclass_to_xml(obj),method=cmds[0])
#                 else: r = client.__put__(uri,data = dataclass_to_xml(obj))
#                 print(r.__dict__)
#         elif s.startswith('/'):
#             try: 
#                 b = client.request(s)
#                 if 'replyTo' in b.__dict__:
#                     if b.replyTo is not None:
#                         rsp_obj = m.Response(createdDateTime=time.time().__ceil__(),endDeviceLFDI=bytes(b'hhyydddssdfgg'),status=6)
#                         xml = dataclass_to_xml(rsp_obj)
#                         r = client.request(b.replyTo,body = xml,method='POST')
#                         print(r.headers.__dict__)
#             except Exception as e: print(e)
#         else:
#             args = s.split(' ')
#             print(args)
#             if args[0] == 'update_status_on_server':
#                 if len(args) > 1:
#                     info = args[1]
#                     if info == 'DERCapability': client.update_status_on_server(info,obj_from_xml_file('dercap.xml'))
#                     elif info == 'PowerStatus': client.update_status_on_server(info,obj_from_xml_file('ps.xml'))
#                     elif info == 'DeviceInformation': client.update_status_on_server(info,obj_from_xml_file('di.xml'))
#                     elif info == 'DERSettings': client.update_status_on_server(info,obj_from_xml_file('derg.xml'))
#                     elif info == 'DERAvailability': client.update_status_on_server(info,obj_from_xml_file('dera.xml'))
#                     elif info == 'DERStatus': client.update_status_on_server(info,obj_from_xml_file('ders.xml'))
#                     elif info == 'DERStatus': client.update_status_on_server(info,obj_from_xml_file('ders.xml'))
#             else:
#                 getattr(client,args[0])()

#     # OpenSSL.crypto.
#     # x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, x509_binary)
#     #         environ['ieee_2030_5_peercert'] = x509
#     #         environ['ieee_2030_5_subject'] = x509.get_subject().CN

# # cafile = "/home/gridappsd/tls/certs/ca.crt"
# # certfile = "/home/gridappsd/tls/certs/dev1.crt"
# # keyfile = "/home/gridappsd/tls/private/dev1.pem"
# # hostname = "gridappsd_dev_2004"
# # #hostname = "google.com"
# # port = 8443
# #
# # context = ssl.SSLContext(ssl.PROTOCOL_TLS)
# # context.verify_mode = ssl.CERT_OPTIONAL
# # context.load_verify_locations(cafile=cafile)
# #
# # # Loads client information from the passed cert and key files. For
# # # client side validation.
# # context.load_cert_chain(certfile=certfile, keyfile=keyfile)
# #
# # conn = HTTPSConnection(host=hostname,
# #                        port=port,
# #                        context=context)
# #
# # conn.set_debuglevel(5)
# # conn.connect()
# # print(id(conn.sock))
# # headers = {"Connection": "keep-alive"}
# # conn.request("GET", "/admin/index.html", headers=headers) # /admin/index.html", headers=headers)
# # resp = conn.getresponse()
# # print(resp.read())
# # pprint(resp.headers.items())
# #
# # print(id(conn.sock))
# # conn.request("GET", "/", headers=headers)
# # print(id(conn.sock))
# # resp = conn.getresponse()
# # print(resp.read())
# # pprint(resp.headers.items())
# # conn.close()
