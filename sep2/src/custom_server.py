from http.server import ThreadingHTTPServer , BaseHTTPRequestHandler
# from ieee_2030_5.server
import ssl
import re
import time
import os
import pandas as pd
import logging
import threading
from io import BytesIO
import sep
from utils import *
import yaml
import xmltodict
import sys
from pathlib import Path

one_min_dir = os.path.join(Path.home(),"Downloads", "PartnerApiClientExample","Python","1mindata")
f = os.path.join(one_min_dir,'2023-11-16.parquet')
print(f)
# df = pd.read_parquet(f)

# print(df)

data = open(f,'rb').read()

# print(data)

# sys.exit()
_resources = {}
_resources_map = {}


dcap = sep.DeviceCapability(href='/dcap', 
                        TimeLink=sep.TimeLink('/tm'),
                        EndDeviceListLink= sep.EndDeviceListLink('/edev'),
                        MirrorUsagePointListLink=sep.MirrorUsagePointListLink('/mup'))

def split_path(path):
    try:
        i = path.index( "?" )
        base_path , query_string = path[:i] , path[i+1:]
    except: base_path , query_string = path, ''
    return base_path , query_string

class EndPoints():

    def get(_path):
        # print(request.environ['REMOTE_ADDR'],request.environ['REMOTE_PORT'])
        # print(request.query_string)
        path,query_str = split_path(_path)
        if path not in _resources: return {"code": 404}
        obj = _resources[path]
        #TODO check if user is authorized to access resource and filter resource accordingly
        #TODO handle query string 
        #TODO handle list ordering
        name = obj.__class__.__name__
        if query_str == b'': 
            # t0 = time.time()
            data = dataclass_to_xml(obj).encode()
            # print('elapsed ', time.time() -t0)
            return {"code": 200 ,"data": data}
        else:
            if not name.endswith('List'): return {"code": 200 ,"data": data}
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
    
    # def delete(self): return _Response(status='204' , headers=_headers)

    # def get_time(self) -> Response:
    #     # TODO fix for new stuff.
    #     # local_tz = datetime.now().astimezone().tzinfo
    #     # now_local = datetime.now().replace(tzinfo=local_tz)

    #     now_utc = datetime.utcnow().replace(tzinfo=pytz.utc)
    #     # now_utc = pytz.utc.localize(datetime.utcnow())
    #     local_tz = pytz.timezone(tzlocal.get_localzone().zone)
    #     now_local = datetime.now().replace(tzinfo=local_tz)

    #     start_dst_utc, end_dst_utc = [
    #         dt for dt in local_tz._utc_transition_times if dt.year == now_local.year
    #     ]

    #     utc_offset = local_tz.utcoffset(start_dst_utc - timedelta(days=1))
    #     dst_offset = local_tz.utcoffset(start_dst_utc + timedelta(days=1)) - utc_offset
    #     local_but_utc = datetime.now().replace(tzinfo=pytz.utc)

    #     tm = Time(currentTime=format_time(now_utc),
    #                 dstEndTime=format_time(end_dst_utc.replace(tzinfo=pytz.utc)),
    #                 dstOffset=TimeOffsetType(int(dst_offset.total_seconds())),
    #                 localTime=format_time(local_but_utc),
    #                 quality=None,
    #                 tzOffset=TimeOffsetType(utc_offset.total_seconds()))
    #     return _Response(dataclass_to_xml(tm),headers=_headers)     

    # def put_flowreservationrequest(self): 
    #     # retrieve request info
    #     data , path = request.data , request.path 
    #     # convert xml to dataclass  
    #     obj = xml_to_dataclass(data.decode('utf-8'))
    #     # get path to frq list
    #     _path = path.removesuffix(f"/{path.split('/')[-1]}")
    #     frq_list = self.resources[_path]
    #     if path in self.resources:
    #         status = '204'
    #         obj.href = path
    #         d = diff_between_obj(obj,self.resources[path])
    #         if d == ['RequestStatus']: self.resources[path] = obj
    #         else: return _Response(status=400,headers=_headers)
    #     else:
    #         status = '201'
    #         # check if a previous request has the same mRID
    #         for frq in frq_list.FlowReservationRequest:
    #             if frq.mRID == obj.mRID:
    #                 return Response(status=400,headers=_headers)
    #         # append frq to frq list
    #         frq_list.FlowReservationRequest.append(obj) 
    #     return  _Response(status=status,headers=_headers)

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        return
    
    def do_GET(self):
        print(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)
        # self.wfile.write(dataclass_to_xml(dcap).encode())
        return
    
    def do_PUT(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        print(body)        
        self.send_response(204)
        self.send_header('Location','dcap/1')
        self.end_headers()
        data = BytesIO()
        data.write(b'i am your angel')
        self.wfile.write(b'Got put')
        self.wfile.write(data.getvalue())
        return

server = ThreadingHTTPServer(('0.0.0.0',7000),HTTPRequestHandler)

server.serve_forever()