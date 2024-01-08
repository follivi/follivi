# }}}

from datetime import datetime, timedelta
import IEEE2030_5
import calendar
import logging
import pytz
import io
import time
import sep as xsd_models
from volttron.platform.agent import utils

utils.setup_logging()
_log = logging.getLogger(__name__)
_now = datetime.now

class EndDevice:
    """ Object representing an End Device in IEEE 2030.5

    End Devices talk with the IEEE 2030.5 Agent over HTTP using XML formatting. This End Device representation stores
    configuration information about the End Device and exports that information as XSD Objects when various
    endpoint urls are queried.
    """
    enddevice_id = 0

    def __init__(self, info, function_set_assignments , flow_reservation):
        """Representation of End Device object.

        :param sfdi: Short Form Device Identifier
        :param lfdi: Long Form Device Identifier
        :param device_category: Load Shed Device Category
        :param pin_code: Pin Code
        """

        # Basic Device Configurations
        self.sfdi = info['sfdi']
        self.lfdi = info['lfdi']
        self.deviceCategory = info['device_category']
        self.pinCode = info['pin_code']
        self.registeredOn = datetime.utcnow().replace(tzinfo=pytz.utc)

        # Global Device ID. Updates as End Devices are registered.
        self.id = EndDevice.enddevice_id
        EndDevice.enddevice_id += 1

        self.mappings = {}

        # IEEE 2030.5 Resource Initialization
        # TODO: configurate resources according to input in config file
        self._end_device = xsd_models.EndDevice(
            href= f'/edev/{self.id+1}',
            lFDI= self.lfdi.encode('utf-8').hex(),
            sFDI= int(self.sfdi.encode('utf-8')),
            PowerStatusLink = xsd_models.PowerStatusLink(href=f'/edev/{self.id+1}/ps'),
            FunctionSetAssignmentsListLink=xsd_models.FunctionSetAssignmentsListLink(href=f'/edev/{self.id+1}/fsa',all=1),
            RegistrationLink=xsd_models.RegistrationLink(f'/edev/{self.id+1}/rg'),
            DERListLink=xsd_models.DERListLink(href=f'/edev/{self.id+1}/der',all=1),
            DeviceInformationLink= xsd_models.DeviceInformationLink(href=f'/edev/{self.id+1}/dstat')
            )

        if flow_reservation: 
            self._end_device.FlowReservationRequestListLink = xsd_models.FlowReservationRequestListLink(f'/edev/{self.id+1}/frq',all=0)
            self._frq = xsd_models.FlowReservationRequestList(
                href=self._end_device.FlowReservationRequestListLink.href,
                all = 0,
                results=0,
                pollRate=15)

            self._end_device.FlowReservationResponseListLink = xsd_models.FlowReservationResponseListLink(f'/edev/{self.id+1}/frp',all=0)
            self._frp = xsd_models.FlowReservationResponseList(
                href=self._end_device.FlowReservationResponseListLink.href,
                pollRate=15
            )

        else:
            if 'programs' in function_set_assignments:
                fsa_uri = f'/edev/{self.id+1}/fsa'
                base_prog_uri = f'{self.id+1}/derp'
                # initialize function set resource
                self._end_device.FunctionSetAssignmentsListLink = xsd_models.FunctionSetAssignmentsListLink(href=fsa_uri)
                self._fsa = xsd_models.FunctionSetAssignmentsList(href=fsa_uri,pollRate=900)
                # iterate through fsa programs
                for idx,program_id in enumerate(function_set_assignments['programs']):
                    prog_uri = f"{base_prog_uri}/1/derpF{idx+1}"
                    self._fsa.FunctionSetAssignments.append(xsd_models.FunctionSetAssignments(
                        href=f'{fsa_uri}/{idx+1}',
                        TimeLink=xsd_models.TimeLink('/tm'),
                        DERProgramListLink=xsd_models.DERProgramListLink(href= prog_uri)))
                    self._derp
                
            function_set_assignments
        
        self._device_information = xsd_models.DeviceInformation(href = self._end_device.DeviceInformationLink.href)
        self._device_status = xsd_models.DeviceStatus(href = self._end_device.DeviceStatusLink.href)
        self._power_status = xsd_models.PowerStatus(href= self._end_device.PowerStatusLink.href)

        self._fsa = xsd_models.FunctionSetAssignmentsList(
            href=self._end_device.FunctionSetAssignmentsListLink.href,
            all = 1,
            results=1,
            FunctionSetAssignments= [xsd_models.FunctionSetAssignments()]
            pollRate= 900
        )
        self._function_set_assignments = xsd_models.FunctionSetAssignments(
            subscribable='0',
            mRID=xsd_models.mRIDType(valueOf_=mrid_helper(self.id, IEEE2030_5.MRID_SUFFIX_FUNCTION_SET_ASSIGNMENT)),
            description="FSA",
        )
        self._function_set_assignments.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS["fsa"].url.format(self.id))
        self._function_set_assignments.DERProgramListLink = xsd_models.DERProgramListLink()
        self._function_set_assignments.DERProgramListLink.\
            set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS["derp-list"].url.format(self.id))
        self._function_set_assignments.DERProgramListLink.set_all(1)
        self._function_set_assignments.TimeLink = xsd_models.TimeLink()
        self._function_set_assignments.TimeLink.set_href(IEEE2030_5.IEEE2030_5_ENDPOINTS["tm"].url)

        self._registration = xsd_models.Registration(
            dateTimeRegistered=IEEE2030_5Time(self.registeredOn),
            pIN=xsd_models.PINType(valueOf_=int(self.pinCode)))
        self._registration.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['reg'].url.format(self.id))

        self._der = xsd_models.DER(
            AssociatedDERProgramListLink=xsd_models.AssociatedDERProgramListLink(),
            CurrentDERProgramLink=xsd_models.CurrentDERProgramLink(),
            DERAvailabilityLink=xsd_models.DERAvailabilityLink(),
            DERCapabilityLink=xsd_models.DERCapabilityLink(),
            DERSettingsLink=xsd_models.DERSettingsLink(),
            DERStatusLink=xsd_models.DERStatusLink()
        )
        self._der.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['der'].url.format(self.id))
        self._der.AssociatedDERProgramListLink.set_href(
            IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derp-list'].url.format(self.id))
        self._der.AssociatedDERProgramListLink.set_all(1)
        self._der.CurrentDERProgramLink.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derp'].url.format(self.id))
        self._der.DERAvailabilityLink.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['dera'].url.format(self.id))
        self._der.DERCapabilityLink.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['dercap'].url.format(self.id))
        self._der.DERSettingsLink.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derg'].url.format(self.id))
        self._der.DERStatusLink.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['ders'].url.format(self.id))

        self._der_program = xsd_models.DERProgram(
            DERControlListLink=xsd_models.DERControlListLink(),
            primacy=xsd_models.PrimacyType(valueOf_=1)
        )
        self._der_program.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derp'].url.format(self.id))
        self._der_program.set_mRID(
            xsd_models.mRIDType(valueOf_=mrid_helper(self.id, IEEE2030_5.MRID_SUFFIX_DER_PROGRAM)))
        self._der_program.set_version(xsd_models.VersionType(valueOf_='0'))
        self._der_program.set_description("DER Program")
        self._der_program.DERControlListLink.set_href(
            IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derc-list'].url.format(self.id))
        self._der_program.DERControlListLink.set_all(1)

        self._der_settings = xsd_models.DERSettings()
        self._der_capability = xsd_models.DERCapability()
        self._der_status = xsd_models.DERStatus()
        self._der_availability = xsd_models.DERAvailability()

        self._der_control = xsd_models.DERControl(DERControlBase=xsd_models.DERControlBase())
        self._der_control.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derc'].url.format(self.id))
        self._der_control.set_description("DER Control")

        self._mup = None

    def meter_reading_helper(self, attr_name):
        """ Helper method for attributes that use meter readings

        :param attr_name: Name of SunSpec attribute
        :return: Value of IEEE 2030.5 Meter Reading correlated with SunSpec attribute
        """
        if self.mup is not None:
            for reading in self.mup.mup_xsd.get_MirrorMeterReading():
                if reading.get_description() == attr_name:
                    power_of_ten = reading.get_ReadingType()
                    value = reading.get_Reading().get_value()
                    return float(value) * pow(10, int(power_of_ten.get_powerOfTenMultiplier().get_valueOf_())) \
                        if power_of_ten is not None else float(value)
        return None

    #####################################################################
    # Currently WChaMax is the only SunSpec register we support         #
    # writing to. Because of the way IEEE 2030.5 is set up, we can read #
    # any register by giving it a proper IEEE 2030.5 resource and field #
    # but writing to registers will require special agent config        #
    #####################################################################
    xsd_models.FunctionSetAssignments()
    
    def add_control(self,prog_list_uri,ctrl_type, derp_id=1,**kwargs):
        # derprogram uri
        prog_uri = f"{prog_list_uri}/{derp_id}"
        # check if endpoint prog_list_uri exist , otherwhise create
        if not prog_list_uri in self.resources:
            self.add_resource('DERProgramList',uri = prog_list_uri, subscribable=1,rule=prog_list_uri, http_methods = ['GET','POST'],**kwargs)
            # # add derprogram listlink is in fsa
            xsd_models.DERProgram()
            xsd_models.DeviceCapability()
            xsd_models.FunctionSetAssignments()
            xsd_models.DERControlBase()
            setattr(self.resources['/dcap'].resource,'DERProgramListLink',m.DERProgramListLink(prog_list_uri))
        # check if endpoint for derprogr exists otherwhise create it
        if not prog_uri in self.resources:
            # derp_MRID = uuid.uuid1().hex[:6] + self.resources[prog_list_uri].resource.mRID[6:] #TODO better structure derp mRID vs derp list mRID
            derp_mRID = '0'*6 + uuid.uuid1().hex[6:] # generate uuid for derprogram
            derp_primacy = kwargs.pop('primacy',89)
            description = kwargs.pop('program_description',f"der program {derp_id}")
            self.add_resource('DERProgram',uri = prog_uri,subscribable = 0,mRID= derp_mRID,primacy = derp_primacy,description =description,
                              rule=prog_uri, http_methods = ['GET','POST'],**kwargs)
            # update derprogramlist instance attribute derprogram
            getattr(self.resources[prog_list_uri].resource,'DERProgram').append(self.resources[prog_uri].resource)
        if ctrl_type == 'curve':
            # build uris
            dc_uri = f"{prog_uri}/dc"
            # Check if a dercurvelist resource is registered in the server resources , otherwhise create new one
            if not dc_uri in self.resources:
                self.add_resource('DERCurveList',uri = dc_uri,rule=dc_uri, http_methods = ['GET','POST'],**kwargs)
                # update derprogram instance
                self.update_resource(prog_uri,DERCurveListLink=m.DERCurveListLink(dc_uri))
            # retrieve dercuvelist instance attr dercurve
            dercurvelist = getattr(self.resources[dc_uri].resource,'DERCurve')
            # build uri of current dercurve
            if not 'dc_id' in kwargs: dc_id = dercurvelist.__len__()+1
            uri = f"{dc_uri}/{dc_id}"
            # Create dercurve instance: Memo pass list of dict as curve data params , CurveData = [m.CurveData(**kw) for kw in kwargs.get('CurveData',[])]
            creationTime= _now().timestamp().__ceil__()
            ctrl_description = kwargs.get('ctrl_description',f'curve {dc_id}')
            ctrl_mRID = '0'*6 + uuid.uuid1().hex[6:]    
            # print(uri)        
            self.add_resource('DERCurve',uri= uri,mRID=ctrl_mRID,creationTime=creationTime,description=ctrl_description,
                              rule=uri, http_methods = ['GET','POST'],**kwargs)
            # Add dercurve to dercurvelist
            getattr(self.resources[dc_uri].resource,'DERCurve').append(self.resources[uri].resource)
        elif ctrl_type == 'der_control':
            # build uris
            derc_uri = f"{prog_uri}/derc"  
            # Check if a dercontrollist resource is registered in the server resources , otherwhise create new one
            if not derc_uri in self.resources:
                self.add_resource('DERControlList',uri = derc_uri,rule=derc_uri, http_methods = ['GET','POST'],**kwargs)
                # update derprogram instance
                self.update_resource(prog_uri,DERControlListLink=m.DERControlListLink(derc_uri))
            # retrieve dercontrollist instance attr dercontrol
            dercontrollist = getattr(self.resources[derc_uri].resource,'DERControl')
            # build uri of current dercurve
            if not 'derc_id' in kwargs: derc_id = dercontrollist.__len__()+1
            uri = f"{derc_uri}/{derc_id}"
            # Create dercontrol instance: Memo pass directly derc control directly
            cb = getattr(m,"DERControlBase")()
            for key,val in kwargs.items():
                if key in cb.__dict__: setattr(cb,key,val)            
            creationTime= _now().timestamp().__ceil__()
            ctrl_description = kwargs.get('ctrl_description',f'derc {derc_id}')
            ctrl_mRID = '0'*6 + uuid.uuid1().hex[6:]
            self.add_resource('DERControl',uri= uri,mRID= ctrl_mRID,DERControlBase =cb,description = ctrl_description,creationTime = creationTime,
                              rule=uri, http_methods = ['GET','POST'], **kwargs)
            # Add dercurve to dercurvelist
            dercontrollist.append(self.resources[uri].resource)
            # check if responRequired is in kwargs and create rsps resources
            rsp_req = kwargs.get('responseRequired')
            if rsp_req is not None:
                # check if rsps is on the server
                replyTo = kwargs.get("replyTo")
                if replyTo is not None:
                    _,rsps_base_uri,rsps_id ,_= replyTo.split('/')
                    self.add_response(f"/{rsps_base_uri}",rsps_id)
        elif ctrl_type == 'default_control':
            # build uris
            dderc_uri = f"{prog_uri}/dderc"  
            # Check if a defaultdercontrol resource is registered in the server resources , otherwhise create new one
            creationTime= _now().timestamp().__ceil__()
            ctrl_description = kwargs.get('ctrl_description',f'dderc')   
            ctrl_mRID = '0'*6 + uuid.uuid1().hex[6:]         
            if not dderc_uri in self.resources:
                self.add_resource('DefaultDERControl',uri = dderc_uri,mRID= ctrl_mRID,creationTime = creationTime,description=ctrl_description,
                                  rule=dderc_uri, http_methods = ['GET','PUT','DELETE'],**kwargs)
                # update derprogram instance
                self.update_resource(prog_uri,DefaultDERControlLink=m.DefaultDERControlLink(dderc_uri))
            # Create defaultdercontrol instance: Memo pass directly dderc control directly
            cb = getattr(m,"DERControlBase")()
            for key,val in kwargs.items():
                if key in cb.__dict__: setattr(cb,key,val)                      
            self.update_resource(dderc_uri,DERControlBase =cb)
        return    
    
    #####################################################################
    # Currently WChaMax is the only SunSpec register we support         #
    # writing to. Because of the way IEEE 2030.5 is set up, we can read #
    # any register by giving it a proper IEEE 2030.5 resource and field #
    # but writing to registers will require special agent config        #
    #####################################################################

    def b124_WChaMax(self, value):
        now = datetime.utcnow().replace(tzinfo=pytz.utc)
        mrid = mrid_helper(self.id, int(time.mktime(now.timetuple())))
        self.der_control.get_DERControlBase().set_opModFixedFlow(xsd_models.SignedPerCent(valueOf_=value))
        self.der_control.set_mRID(xsd_models.mRIDType(valueOf_=mrid))
        self.der_control.set_creationTime(IEEE2030_5Time(now))
        self.der_control.set_EventStatus(xsd_models.EventStatus(
            currentStatus=IEEE2030_5.EVENT_STATUS_ACTIVE,
            dateTime=IEEE2030_5Time(now),
            potentiallySuperseded=True,
            potentiallySupersededTime=IEEE2030_5Time(now),
            reason="Dispatch"
        ))
        self.der_control.set_interval(xsd_models.DateTimeInterval(duration=3600 * 24, start=IEEE2030_5Time(now)))

    def field_value(self, resource, field):
        """ Given a IEEE 2030.5 field name, return the value of that field.
        :param resource: IEEE 2030.5 resource name
        :param field: IEEE 2030.5 field name (may be dotted notation if a nested field)
        :return: field value
        """

        # Special Corner cases that exist outside of official IEEE 2030.5 fields
        if field == 'sFDI':
            return self.sfdi
        elif field == 'SOC':
            _log.debug('Calculating DERAvailability.soc...')
            if self.field_value("DERAvailability", "availabilityDuration") is not None and \
                            self.field_value("DERSettings", "setMaxChargeRate") is not None:
                duration = self.field_value("DERAvailability", "availabilityDuration") / 3600.0
                max_charge = self.field_value("DERSettings", "setMaxChargeRate")
                soc = duration * max_charge
            else:
                soc = None
            return soc

        # Translate from IEEE 2030.5 resource (DeviceInformation) to EndDevice attribute (device_information)
        converted_resource = IEEE2030_5.RESOURCE_MAPPING[resource]
        if hasattr(self, converted_resource):
            IEEE2030_5_resource = getattr(self, converted_resource)
        else:
            raise AttributeError("{} is not a valid IEEE 2030.5 Resource".format(resource))

        # MUPs have special case handling
        if converted_resource == "mup":
            return self.meter_reading_helper(field)

        IEEE2030_5_field = self.get_field(IEEE2030_5_resource, field)
        if hasattr(IEEE2030_5_field, 'value'):
            field_value = IEEE2030_5_field.value
            if hasattr(IEEE2030_5_field, 'multiplier') and type(IEEE2030_5_field.multiplier) == \
                xsd_models.PowerOfTenMultiplierType:
                field_value = float(field_value) * pow(10, int(IEEE2030_5_field.multiplier.get_valueOf_()))
            elif type(field_value) == xsd_models.PerCent:
                field_value = int(field_value.get_valueOf_()) / 100.0
            else:
                # Depending on field choice, this could be a nested xsd model, not JSON serializable.
                pass
        else:
            field_value = IEEE2030_5_field

        return field_value

    @staticmethod
    def get_field(resource, field):
        """ Recursive helper method to retrieve field from IEEE 2030.5 resource

        If IEEE 2030.5 fields have not been defined, this method will return None

        :param resource: IEEE 2030.5 resource (xsd_models object)
        :param field: IEEE 2030.5 field name
        :return: value of field
        """
        fields = field.split('.', 1)
        if len(fields) == 1:
            IEEE2030_5_field = getattr(resource, field, None)
        else:
            meta_field = getattr(resource, fields[0], None)
            IEEE2030_5_field = EndDevice.get_field(meta_field, fields[1]) if meta_field else None
        return IEEE2030_5_field

    ############################################################
    # XSD Object representation methods.                       #
    # These objects represent various IEEE2030_5 Resources.    #
    # These Resource objects mirror HTTP request GET and POSTS #
    ############################################################

    @property
    def end_device(self):
        return self._end_device

    @property
    def device_information(self):
        return self._device_information

    @device_information.setter
    def device_information(self, value):
        self._device_information = value
        self._device_information.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['di'].url.format(self.id))

    @property
    def device_status(self):
        return self._device_status

    @device_status.setter
    def device_status(self, value):
        self._device_status = value
        self._device_status.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['dstat'].url.format(self.id))

    @property
    def function_set_assignments(self):
        return self._function_set_assignments

    @property
    def power_status(self):
        return self._power_status

    @power_status.setter
    def power_status(self, value):
        self._power_status = value
        self._power_status.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['ps'].url.format(self.id))

    @property
    def registration(self):
        return self._registration

    @property
    def der(self):
        return self._der

    @property
    def der_program(self):
        return self._der_program

    @property
    def der_control(self):
        return self._der_control

    @property
    def der_availability(self):
        return self._der_availability

    @der_availability.setter
    def der_availability(self, value):
        self._der_availability = value
        self._der_availability.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['dera'].url.format(self.id))

    @property
    def der_capability(self):
        return self._der_capability

    @der_capability.setter
    def der_capability(self, value):
        self._der_capability = value
        self._der_capability.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['dercap'].url.format(self.id))

    @property
    def der_status(self):
        return self._der_status

    @der_status.setter
    def der_status(self, value):
        self._der_status = value
        self._der_status.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['ders'].url.format(self.id))

    @property
    def der_settings(self):
        return self._der_settings

    @der_settings.setter
    def der_settings(self, value):
        self._der_settings = value
        self._der_settings.set_href(IEEE2030_5.IEEE2030_5_EDEV_ENDPOINTS['derg'].url.format(self.id))

    @property
    def mup(self):
        return self._mup

    @mup.setter
    def mup(self, value):
        self._mup = value


class MUP:
    """ Object representing an MUP in IEEE2030_5 """
    mup_id = 0

    def __init__(self, xsd):
        self.id = MUP.mup_id
        MUP.mup_id += 1
        self.mup_xsd = xsd


class IEEE2030_5Renderer:
    """ Takes IEEE 2030.5 Type objects and renders them as XML formatted data for HTTP response. """

    media_type = 'application/sep+xml'

    @staticmethod
    def export(xsd_object, make_pretty=True):
        """Export IEEE 2030.5 object into serializable XML

        :param xsd_object: IEEE 2030.5 object to export
        :param make_pretty: Boolean value determining whether or not to use newline characters between XML elements.

        :return: String of XML serialized data.
        """
        buff = io.StringIO()
        xsd_object.export(
            buff,
            1,
            namespacedef_='xmlns="http://zigbee.org/sep" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            pretty_print=make_pretty
        )
        return buff.getvalue()

    @staticmethod
    def render(data):
        """ Wrapper function around the export method.

        :param data: XSD object to render. Empty string if data does not come in correctly.
        :return: Formatted XML string.
        """
        if data is None:
            return ''

        if 'rendered_result' not in data:
            if 'result' not in data:
                data['rendered_result'] = ''
            else:
                make_pretty = True
                data['rendered_result'] = IEEE2030_5Renderer.export(data['result'], make_pretty)

        return data['rendered_result']


class IEEE2030_5Parser:
    """ Takes XML formatted string and renders it as an XSD object. """
    media_type = 'application/sep+xml'

    @staticmethod
    def parse(stream):
        """ Parses the incoming bytestream as XML and returns the resulting data. """
        return xsd_models.parseString(stream, silence=True)


def mrid_helper(edev_pk, resource_suffix):
    """ Helper method to create universally unique ID for any resource object

    :param edev_pk: Primary Key of End Device object
    :param resource_suffix: Suffix to add to hash to create unique ID
    :return: UUID (MRID) value. (In hex-decimal)
    """
    hex_string = hex(int(edev_pk)*10000000000000+resource_suffix*100)[2:].upper()
    if hex_string.endswith('L'):
        hex_string = hex_string[:-1]
    if (len(hex_string)) % 2 == 1:
        hex_string = "0{0}".format(hex_string)
    return hex_string


def IEEE2030_5Time(dt_obj, local=False):
    """ Return a proper IEEE2030_5 TimeType object for the dt_obj passed in.

        From IEEE 2030.5 spec:
            TimeType Object (Int64)
                Time is a signed 64 bit value representing the number of seconds
                since 0 hours, 0 minutes, 0 seconds, on the 1st of January, 1970,
                in UTC, not counting leap seconds.

    :param dt_obj: Datetime object to convert to IEEE2030_5 TimeType object.
    :param local: dt_obj is in UTC or Local time. Default to UTC time.
    :return: Time XSD object
    :raises: If utc_dt_obj is not UTC
    """

    if dt_obj.tzinfo is None:
        raise Exception("IEEE 2030.5 times should be timezone aware UTC or local")

    if dt_obj.utcoffset() != timedelta(0) and not local:
        raise Exception("IEEE 2030.5 TimeType should be based on UTC")

    if local:
        return xsd_models.TimeType(valueOf_=int(time.mktime(dt_obj.timetuple())))
    else:
        return xsd_models.TimeType(valueOf_=int(calendar.timegm(dt_obj.timetuple())))
