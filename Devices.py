#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'
import subprocess
import time
from lib_to import app_logger
from TN_action import TN_act as TN_act
import autentification as AUTH

class DEVICES_TPLINK:
    base_data = {'model': "",
                 'firmware': "",
                 'firmware_file': "",
                 'conf_standart': "",
                 'list_stsw_port': [1, 21],
                 'method_upd': ''   #telnet|snmp|mikrotik
                 }
    connect_data = {'ip': '',
                    'user': 'admin',
                    'password': 'admin',
                    'port': 23,
                    'part_answer': '',
                    }
    snmp_get_param = {'model': '',
                      'vendor_firmware': '',
                      'newsw_serial': '',
                      'newsw_mac': ''
                      }

    stend_data = {"IP": '',
                  'port': ''}
    mik_data = {"IP": '',
                "MAC": '',
                "port": ''}
    status_snmp_data = {'status_model': '',
                        'status_fw': '',
                        'Errors': {}
                        }
    dev_params_behind = { 'model': '',
                          'vendor_firmware': '',
                          'newsw_serial': '',
                          'newsw_mac': ''
                        }
    dev_params_after = {}
    statuses_foo_devices = {}
    good_model = ['T2600G-28TS-DC', 'T2700G-28TQ 2.20', 'T2700G-28TQ_2.20', 'T2600G-28TS-DC 1.0']
    loger = app_logger.get_logger("Devices/snmp")


    def set_mirk_ip(self, ip):
        self.stmik_IP = ip

    def get_param_snmp(self, newsw_ip):
        name_foo = 'get_param_snmp'
        self.statuses_foo_devices[name_foo] = 'Start'

        time.sleep(4)
        for name, snmp_cmd in self.snmp_get_param.items():
            try:
                request = snmp_cmd.replace('<newsw_ip>', newsw_ip)
                self.loger.info(request)
                responce = subprocess.check_output(request, shell=True)
                res = responce.decode('utf-8')
                res = res.replace('"', '')
                res = res.replace('\n', '')
                res = res.replace('\r', '')
                self.dev_params_behind[name] = res
                self.loger.info(res)
            except Exception as ex:
                self.loger.error("Error on get snmp params on ip %s on step %s. Error: %s" %(newsw_ip, str(name), str(ex)))
                self.statuses_foo_devices[name_foo] = 'Break'
        time.sleep(1)
        for name, snmp_cmd in self.snmp_get_param.items():
            try:
                request = snmp_cmd.replace('<newsw_ip>', newsw_ip)
                self.loger.info(request)
                responce = subprocess.check_output(request, shell=True)
                res = responce.decode('utf-8')
                res = res.replace('"', '')
                res = res.replace('\n', '')
                res = res.replace('\r', '')
                self.dev_params_behind[name] = res
                self.loger.info(res)
            except Exception as ex:
                self.loger.error("Error on get snmp params on ip %s on step %s. Error: %s" %(newsw_ip, str(name), str(ex)))
                self.statuses_foo_devices[name_foo] = 'Break'

        self.statuses_foo_devices[name_foo] = 'Ok'


    def check_snmp_param(self):
        self.statuses_foo_devices['check_snmp_param'] = 'Start'
        result_foo = {}

        self.get_param_snmp(self.stend_data['IP'])

        if self.dev_params_behind == {}:
            self.loger.error("Error on get snmp on ip %s. " %(self.stend_data['IP']))
            self.statuses_foo_devices['check_snmp_param'] = 'Break'
            return
        self.loger.info("Get snmp params on ip %s - OK" %(self.stend_data['IP']))

        # если модель не из списка - ошибку и переходим к следующему
        if self.dev_params_behind.get('model', '') not in self.good_model:
            self.status_snmp_data['status_model'] = ('Error, Not valid model')
            self.loger.error("Not valid model: %s" %self.dev_params_behind.get('model', ''))
        else:
            self.status_snmp_data['status_model'] = 'Ok'
            self.loger.info("Model %s on %s - OK" %(self.dev_params_behind.get('model', ''), self.stend_data['IP']))

        #если прошивка не соответствует то ее надо обновить, иначе записать в бд что обновлять не будем
        if self.dev_params_behind.get('vendor_firmware', '') == self.base_data['firmware']:
            self.status_snmp_data['status_fw'] = 'OK'
            self.loger.error("Device wasn't updated. Firmware is latest already: %s" %(self.dev_params_behind.get('vendor_firmware', '')))
        else:
            self.status_snmp_data['status_fw'] = 'Error'
            self.loger.info("Firmware to be replaced %s on %s - OK" %(self.dev_params_behind.get('vendor_firmware', ''), self.base_data['firmware']))

        if (self.status_snmp_data['status_model'] == 'Ok') and (self.status_snmp_data['status_fw'] == 'Error'):
            self.status_snmp_data['status_fw_up'] = 'Yes'
        else:
            self.status_snmp_data['status_fw_up'] = 'No'
        #todo прикрутить запись этих ошибок в бд!!!!!

        return


    def fw_update(self, tftp_server, stsw_port_number):

        #statuses_foo_devices внутри fw_update_snmp например
        newsw_ip = self.stend_data['IP']

        if self.base_data['method_upd'] == 'snmp':
            self.loger.info("Start snmp firmware update on port %s" %(str(stsw_port_number)))
            if '2700' in self.dev_params_behind['model']:
                self.fw_update_snmp_2700(newsw_ip, tftp_server)
            elif '2600' in self.dev_params_behind['model']:
                self.fw_update_snmp(newsw_ip, tftp_server)
            self.loger.info("Snmp-request for firmware update has sended")


        elif self.base_data['method_upd'] == 'telnet':
            pass

        elif self.base_data['method_upd'] == 'mikrotik':
            pass
        else:
            self.loger.error('Error, incorrect method firmware update')


    def fw_update_snmp(self, newsw_ip, tftp_server):
        name_foo = "fw_update_ip_%s" %(newsw_ip)
        self.statuses_foo_devices[name_foo] = 'Start'
        self.dev_params_after['status_upd'] = 'start'
        for step, snmp_cmd in (self.snmp_fw_up).items():
            try:
                snmp_request = snmp_cmd['req'].replace("<newsw_ip>", newsw_ip)
                snmp_request = snmp_request.replace("<tftp_serever>", tftp_server)
                snmp_request = snmp_request.replace("<name_firmware>", self.base_data['firmware_file'])
                snmp_request = snmp_request.replace("<config_name>", self.base_data['conf_standart'])
                self.loger.info("Step: %s. Request: %s" %(str(step), snmp_request))
                responce_snmp = subprocess.check_output(snmp_request, shell=True)
                if step == 4:
                    time.sleep(5)
                res = responce_snmp.decode('utf-8')
                res = res.replace('"', '')
                res = res.replace('\n', '')
                res = res.replace('\r', '')
                self.loger.info("Step firmware upgrade: %s. Responce snmp: %s" %(step, res))
                if step == 4:
                    if 'system is upgrading' in res:
                        self.dev_params_after['status_upd'] = 'Process'
                        self.statuses_foo_devices[name_foo] = 'Ok'
                    else:
                        self.dev_params_after['status_upd'] = 'Error'
                        self.statuses_foo_devices[name_foo] = 'Error'
            except Exception as ex:
                self.loger.error("Error on firmware upgrade. Step %s: %s" %(step, str(ex)))
                self.dev_params_after['status_upd'] = 'Error'
                self.statuses_foo_devices[name_foo] = 'Break'


    def fw_update_telnet(self, newsw_ip, tftp_server, port):
        status_foo = {'port': port,
                      'IP': newsw_ip,
                      'Errors': {},
                      'status' : 'start'}
        subswitch_TN_a = TN_act()
        subswitch_TN_a.telnet_connect(newsw_ip, port, self.connect_data['user'], self.connect_data['password'], (self.connect_data['part_answer'] + ">"))
        if (subswitch_TN_a.status_connect == 'null') or ("Error" in subswitch_TN_a.status_connect):
            status_foo['Errors']['other'] = ("Error connect telnet %s %s" %(newsw_ip, str(port)))
            status_foo['status'] = 'Error'
            self.loger.error(status_foo['Errors']['other'])
            return status_foo
        self.loger.info("Telnet connect to %s %s - OK" %(newsw_ip, port))
        request_responce = self.telnet_fw_up
        for step, tn_cmd in request_responce.items():
            request_responce[step]['req'] = (tn_cmd['req']).replace('<tftp_server>', tftp_server)

        status_foo['Errors']['telnet'] = subswitch_TN_a.telnet_dialog(request_responce, flag_cycle='break')
        if status_foo['Errors']['telnet'] == {}:
            status_foo['status'] = 'FW UP is OK'

        return status_foo

    def fw_update_mikrotik(self):
        return

    def fw_update_snmp_2700(self, newsw_ip, tftp_server):
        name_foo = "fw_update_ip_%s" %(newsw_ip)
        self.statuses_foo_devices[name_foo] = 'Start'
        self.dev_params_after['status_upd'] = 'start'
        for step, snmp_cmd in (self.snmp_fw_up).items():
            try:
                snmp_request = snmp_cmd['req'].replace("<newsw_ip>", newsw_ip)
                snmp_request = snmp_request.replace("<tftp_serever>", tftp_server)
                snmp_request = snmp_request.replace("<name_firmware>", self.base_data['firmware_file'])
                snmp_request = snmp_request.replace("<config_name>", self.base_data['conf_standart'])
                self.loger.info("Step: %s. Request: %s" %(str(step), snmp_request))


                responce_snmp = subprocess.check_output(snmp_request, shell=True)
                if step == 3:
                    time.sleep(5)
                res = responce_snmp.decode('utf-8')
                res = res.replace('"', '')
                res = res.replace('\n', '')
                res = res.replace('\r', '')
                self.loger.info("Step firmware upgrade: %s. Responce snmp: %s" %(step, res))
                if step == 4:
                    for try_get_0 in range(1, 6):

                        if '0' in res:
                            self.dev_params_after['cfg'] = 'Ok'
                            break
                        else:
                            self.dev_params_after['cfg'] = 'Error'
                            self.loger.info("Try get answer status update cfg %s" %str(try_get_0))
                            time.sleep(1)
                            responce_snmp = subprocess.check_output(snmp_request, shell=True)
                            res = responce_snmp.decode('utf-8')
                            res = res.replace('"', '')
                            res = res.replace('\n', '')
                            res = res.replace('\r', '')
                if step == 8:
                    if 'system is upgrading' in res:
                        self.dev_params_after['status_upd'] = 'Process'
                        self.statuses_foo_devices[name_foo] = 'Ok'
                    else:
                        self.dev_params_after['status_upd'] = 'Error'
                        self.statuses_foo_devices[name_foo] = 'Error'
            except Exception as ex:
                # result_foo_fw_up['errors'][step] = "Error on firmware upgrade.  %s" %(str(ex))
                self.loger.error("Error on firmware upgrade. Step %s: %s" %(step, str(ex)))
                self.dev_params_after['status_upd'] = 'Error'
                self.statuses_foo_devices[name_foo] = 'Break'



    def check_status_fw_up(self, newsw_ip):
        name_foo = 'check_status_fw_up_ip_%s' %newsw_ip
        self.statuses_foo_devices['name_foo'] = 'Start'
        snmp_cmd = {}
        snmp_cmd = self.snmp_fw_up[4]
        try:
            snmp_request = snmp_cmd['req'].replace("<newsw_ip>", newsw_ip)
            self.loger.info("Request: %s" %(snmp_request))
            responce_snmp = subprocess.check_output(snmp_request, shell=True)
            res = responce_snmp.decode('utf-8')
            res = res.replace('"', '')
            res = res.replace('\n', '')
            res = res.replace('\r', '')
            self.loger.info("Responce snmp: %s" %(res))
            if 'system is upgrading' in res:
                self.dev_params_after['status_upd'] = 'Process'
                self.statuses_foo_devices[name_foo] = 'Ok'
            elif 'the system is not upgrading' in res:
                self.dev_params_after['status_upd'] = 'No fw up'
                self.statuses_foo_devices[name_foo] = 'Ok'

        except Exception as ex:
            self.loger.error("Error on check firmware upgrade. %s" %(str(ex)))

            self.dev_params_after['status_upd'] = 'Reboot'
            self.statuses_foo_devices[name_foo] = 'Ok'



class TP_LINK_T2700G_28TQ_2_20(DEVICES_TPLINK):
    def __init__(self):
        self.base_data = {'model': "T2700G-28TQ 2.20",
                          'firmware': "2.20.1 Build 20200623 Rel.59799(Beta)",
                          'firmware_file': "T2700G-28TQv2_2.20.1_20200623-rel59799(Beta).bin",
                          'conf_standart': "T2700G-28TQblank.cfg",
                          'list_stsw_port': [1, 21],
                          'method_upd' : 'snmp'
                          }
        self.connect_data = AUTH.get_connest_data()
        self.snmp_get_param = {'model': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.5.0',
                               'vendor_firmware': 'snmpget -Oqv -c private -v 2c <newsw_ip>  .1.3.6.1.4.1.11863.6.1.1.6.0',
                               'newsw_serial': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.8.0',
                               'newsw_mac': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.7.0'
                               }


        self.snmp_fw_up = {1: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.8.1.0 s <tftp_serever>',
                               'resp': '"<tftp_serever>"'},
                           2: {'req': 'snmpset -Oqv -v2c -c private  <newsw_ip>  .1.3.6.1.4.1.11863.6.3.1.8.2.0 s <config_name>',
                               'resp': ''},
                           3: {'req': 'snmpset -Oqv -v2c -c private <newsw_ip>  .1.3.6.1.4.1.11863.6.3.1.8.4.0 i 1',
                               'resp': ''},
                           4: {'req': 'snmpget -Oqv -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.8.4.0',
                               'resp': '1'},
                           5: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.1.0 s <tftp_serever>',
                               'resp': '1'},
                           6: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.2.0 s <name_firmware>',
                               'resp': ''},
                           7: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.3.0 i 1',
                               'resp': ''},
                           8: {'req': 'snmpget -Oqv -v2c -c private <newsw_ip> 1.3.6.1.4.1.11863.6.3.1.5.4.0',
                               'resp': '''"the system is upgrading,please don't turn off the device while upgrading!"'''},
                           }
        self.stend_data = {"IP": '',
                           'port': ''}


        self.status_snmp_data = {'status_model': '',
                            'status_fw': '',
                            'Errors': {}
                            }
        self.dev_params_behind = {'model': '',
                                  'vendor_firmware': '',
                                  'newsw_serial': '',
                                  'newsw_mac': ''
                                  }
        self.dev_params_after = {}
        self.statuses_foo_devices = {}
        self.good_model = ['T2700G-28TQ 2.20', 'T2700G-28TQ_2.20']
        self.loger = app_logger.get_logger("Devices/snmp/2700")


class TP_LINK_T2600G_28TS_DC_1_0(DEVICES_TPLINK):
    def __init__(self):
        self.base_data = {
            'model': "T2600G-28TS-DC 1.0",
            'firmware': "1.0.0 Build 20200514 Rel.40674(Beta)",
            'firmware_file': "T2600G-28TS-DCv1_1.0.0_20200514-rel40674(Beta).bin",
            'conf_standart': "T2600G-28TS-DCblank.cfg",
            'list_stsw_port': [1, 21],
            'method_upd' : 'snmp'
        }
        self.connect_data = AUTH.get_connest_data()
        self.snmp_get_param = {'model': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.5.0',
                               'vendor_firmware': 'snmpget -Oqv -c private -v 2c <newsw_ip>  .1.3.6.1.4.1.11863.6.1.1.6.0',
                               'newsw_serial': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.8.0',
                               'newsw_mac': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.7.0'
                               }

        self.snmp_fw_up = {1: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.1.0 s <tftp_serever>',
                               'resp': 'SNMPv2-SMI::enterprises.11863.6.3.1.8.1.0 = STRING: "<tftp_serever>"'},
                           2: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.2.0 s <name_firmware>',
                               'resp': 'SNMPv2-SMI::enterprises.11863.6.3.1.8.2.0 = STRING: <name_firmware>'},
                           3: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.3.0 i 1',
                               'resp': '1'},
                           4: {'req': 'snmpget -Oqv -v2c -c private <newsw_ip> 1.3.6.1.4.1.11863.6.3.1.5.4.0',
                               'resp': '0'},
                           }
        self.telnet_fw_up = {1: {'req': 'en',
                                 'resp': self.connect_data['part_answer'] + '#'},
                             2: {'req': 'firmware upgrade ip-address <tftp_server> filename ' + self.base_data['firmware_file'],
                                 'resp': 'It will only upgrade the backup image. Continue? (Y/N):'},
                             3: {'req': 'y',
                                 # 'resp': 'Operation OK!\n'
                                 'resp': 'Reboot with the backup image? (Y/N):'},
                             4: {'req': 'n',
                                 'resp': self.connect_data['part_answer'] + '#'},
                             5: {'req': 'configure',
                                 'resp': self.connect_data['part_answer'] + '(config)#'},
                             6: {'req': 'boot application filename image2  startup',
                                 'resp': self.connect_data['part_answer'] + '(config)#'},
                             7: {'req': 'exit',
                                 'resp': self.connect_data['part_answer'] + '#'},
                             8: {'req': 'copy tftp startup-config ip-address <tftp_server> filename ' + self.base_data['conf_standart'] + '.cfg',
                                 'resp': 'Operation OK! Now rebooting system......'}
                             }
        self.stend_data = {"IP": '',
                           'port': ''}


        self.status_snmp_data = {'status_model': '',
                                 'status_fw': '',
                                 'Errors': {}
                                 }
        self.dev_params_behind = {'model': '',
                                  'vendor_firmware': '',
                                  'newsw_serial': '',
                                  'newsw_mac': ''
                                  }
        self.dev_params_after = {}
        self.statuses_foo_devices = {}
        self.good_model = ['T2600G-28TS-DC', 'T2600G-28TS-DC 1.0']
        self.loger = app_logger.get_logger("Devices/snmp/2700")






