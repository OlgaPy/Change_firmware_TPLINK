#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'

from typing import Tuple, List, Optional
import subprocess
import time
import app_logger
from TN_action import TN_act as TN_act
import autentification as AUTH


class DEVICES_TPLINK:
    def __init__(self) -> None:
        """
        A parent class for parameters and a function for interacting with TPLINK models
        :return: None
        """
        self.base_data = {'model': "",
                          'firmware': "",
                          'firmware_file': "",
                          'conf_standart': "",
                          'list_stsw_port': [1, 21],
                          'method_upd': ''  # telnet|snmp|mikrotik
                          }
        self.connect_data = {'ip': '',
                             'user': 'admin',
                             'password': 'admin',
                             'port': 23,
                             'part_answer': '',
                             }
        self.snmp_get_param = {'model': '',
                               'vendor_firmware': '',
                               'newsw_serial': '',
                               'newsw_mac': ''
                               }

        self.stend_data = {"IP": '',
                           'port': ''}
        self.mik_data = {"IP": '',
                         "MAC": '',
                         "port": ''}
        self.status_snmp_data = {'status_model': '',
                                 'status_fw': '',
                                 'Errors': {}
                                 }
        self.dev_params_behind = {'model': '',
                                  'vendor_firmware': '',
                                  'newsw_serial': '',
                                  'newsw_mac': ''
                                  }
        self.telnet_fw_up = {1: {'req': 'en',
                                 'resp': self.connect_data['part_answer'] + '#'},
                             2: {'req': 'firmware upgrade ip-address <tftp_server> filename ' + self.base_data[
                                 'firmware_file'],
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
                             8: {'req': 'copy tftp startup-config ip-address <tftp_server> filename ' + self.base_data[
                                 'conf_standart'] + '.cfg',
                                 'resp': 'Operation OK! Now rebooting system......'}
                             }
        self.dev_params_after = {}
        self.statuses_foo_devices = {}
        self.good_model = ['T2600G-28TS-DC', 'T2700G-28TQ 2.20', 'T2700G-28TQ_2.20', 'T2600G-28TS-DC 1.0']
        self.logger = app_logger.get_logger("Devices/snmp")

    def set_mikr_ip(self, ip: str) -> None:
        """
        Writes the new mikrotik ip into a variable of the class instance.
        :param ip: str
        :return: None
        """
        self.stmik_IP = ip

    def get_param_snmp(self, newsw_ip: str) -> None:
        """
        Getting data about the model, serial number, firmware and mac address of the switch by snmp-request
        :param newsw_ip:
        :return:
        """
        name_foo = 'get_param_snmp'
        self.statuses_foo_devices[name_foo] = 'Start'

        time.sleep(10)
        for name, snmp_cmd in self.snmp_get_param.items():
            try:
                request = snmp_cmd.replace('<newsw_ip>', newsw_ip)
                self.logger.info(f"Send: {request}")
                response = subprocess.check_output(request, shell=True)
                response_clear = response.decode('utf-8')
                response_clear = response_clear.replace('"', '')
                response_clear = response_clear.replace('\n', '')
                response_clear = response_clear.replace('\r', '')
                self.dev_params_behind[name] = response_clear
                self.logger.info(f"Received: {response_clear}")
            except Exception as ex:
                self.logger.error(f"Error on get snmp params on ip {newsw_ip} on step {name}. Error: {ex}")
                self.statuses_foo_devices[name_foo] = 'Break'
                return

        self.statuses_foo_devices[name_foo] = 'Ok'

    def check_snmp_param(self) -> None:
        """
        Checking the parameters received by snmp-request. The data must exist.
        The switch model must be from a valid list. The firmware must be from the list of firmware to be replaced.
        :return: None
        """
        self.statuses_foo_devices['check_snmp_param'] = 'Start'

        self.get_param_snmp(self.stend_data['IP'])

        if self.dev_params_behind:
            self.logger.error(f"Error on get snmp on ip {self.stend_data['IP']}.")
            self.statuses_foo_devices['check_snmp_param'] = 'Break'
            return
        self.logger.info(f"Get snmp params on ip {self.stend_data['IP']} - OK")

        # если модель не из списка - ошибку и переходим к следующему
        if self.dev_params_behind.get('model', '') not in self.good_model:
            self.status_snmp_data['status_model'] = ('Error, Not valid model')
            self.logger.error(f"Not valid model: {self.dev_params_behind.get('model')}")
        else:
            self.status_snmp_data['status_model'] = 'Ok'
            self.logger.info(f"Model {self.dev_params_behind.get('model')} on {self.stend_data['IP']} - OK")

        # если прошивка не соответствует то ее надо обновить, иначе записать в бд что обновлять не будем
        if self.dev_params_behind.get('vendor_firmware', '') == self.base_data['firmware']:
            self.status_snmp_data['status_fw'] = 'OK'
            self.logger.error(
                f"Device wasn't updated. Firmware is latest already: {self.dev_params_behind.get('vendor_firmware')}")
        else:
            self.status_snmp_data['status_fw'] = 'Error'
            self.logger.info(
                f"Firmware to be replaced {self.dev_params_behind.get('vendor_firmware')} on "
                f"{self.base_data['firmware']} - OK")

        if (self.status_snmp_data['status_model'] == 'Ok') and (self.status_snmp_data['status_fw'] == 'Error'):
            self.status_snmp_data['status_fw_up'] = 'Yes'
        else:
            self.status_snmp_data['status_fw_up'] = 'No'

        return

    def fw_update(self, tftp_server: str, stsw_port_number: int) -> None:
        """
        Depending on the model and method of flashing, the methods or methods of the child classes are called.
        :param tftp_server: str
        :param stsw_port_number: int
        :return: None
        """

        # statuses_foo_devices внутри fw_update_snmp например
        newsw_ip = self.stend_data['IP']

        if self.base_data['method_upd'] == 'snmp':
            self.logger.info(f"Start snmp firmware update on port {stsw_port_number}")
            self.fw_update_snmp(newsw_ip, tftp_server)
            self.logger.info("Snmp-request for firmware update has sended")

        elif self.base_data['method_upd'] == 'telnet':
            self.logger.info(f"Start telnet firmware update on port {stsw_port_number}")
            self.fw_update_telnet(newsw_ip, tftp_server, stsw_port_number)
            self.logger.info("Snmp-request for firmware update has sended")
        elif self.base_data['method_upd'] == 'mikrotik':
            self.fw_update_mikrotik()
        else:
            self.logger.error('Error, incorrect method firmware update')

    def fw_update_telnet(self, newsw_ip: str, tftp_server: str, port: int) -> None:
        """
        Firmware update via telnet. Firmware update via telnet. Connects to the switch behind the port port with
        ip=newsw_ip and downloads the firmware from tftp_server with commands from self.telnet_fw_up

        :param newsw_ip:
        :param tftp_server: str
        :param port: int
        :return: None
        """
        self.statuses_foo_devices['fw_update_telnet'] = 'Start'

        tn_a_subswitch = TN_act()
        tn_a_subswitch.telnet_connect(newsw_ip, port, self.connect_data['user'], self.connect_data['password'],
                                      f"{self.connect_data['part_answer']}>")
        if tn_a_subswitch.status_connect.lower() != 'ok':
            self.statuses_foo_devices['fw_update_telnet'] = "Error"
            self.logger.error(f"Error connect telnet {newsw_ip} {port}")
            return
        self.logger.info(f"Telnet connect to {newsw_ip} {port} - OK")
        request_response = self.telnet_fw_up
        for step, tn_cmd in request_response.items():
            request_response[step]['req'] = (tn_cmd['req']).replace('<tftp_server>', tftp_server)

        errors_fw_up = tn_a_subswitch.telnet_dialog(request_response, flag_cycle='break')
        if errors_fw_up:
            self.statuses_foo_devices['fw_update_telnet'] = 'OK'

    def fw_update_mikrotik(self) -> None:
        return

    def check_status_fw_up(self, newsw_ip: str) -> None:
        """
        Checks the status of the firmware update via snmp-request
        :param newsw_ip: str
        :return: None
        """
        name_foo = f'check_status_fw_up_ip_{newsw_ip}'
        self.statuses_foo_devices['name_foo'] = 'Start'
        snmp_cmd = self.snmp_fw_up[4]
        try:
            snmp_request = snmp_cmd['req'].replace("<newsw_ip>", newsw_ip)
            self.logger.info(f"Request: {snmp_request}")
            response_snmp = subprocess.check_output(snmp_request, shell=True)
            res = response_snmp.decode('utf-8')
            res = res.replace('"', '')
            res = res.replace('\n', '')
            res = res.replace('\r', '')
            self.logger.info(f"Response snmp: {res}")
            if 'system is upgrading' in res:
                self.dev_params_after['status_upd'] = 'Process'
                self.statuses_foo_devices[name_foo] = 'Ok'
            elif 'the system is not upgrading' in res:
                self.dev_params_after['status_upd'] = 'No fw up'
                self.statuses_foo_devices[name_foo] = 'Ok'

        except Exception as ex:
            self.logger.error(f"Error on check firmware upgrade. {ex}")
            self.dev_params_after['status_upd'] = 'Reboot'
            self.statuses_foo_devices[name_foo] = 'Ok'


class TP_LINK_T2700G_28TQ_2_20(DEVICES_TPLINK):
    def __init__(self) -> None:
        """
        Child class for different parameters and functions TP-LINK-T2700G-28TQ2.20
        """
        super(TP_LINK_T2700G_28TQ_2_20, self).__init__()
        self.base_data = {'model': "T2700G-28TQ 2.20",
                          'firmware': "2.20.1 Build 20200623 Rel.59799(Beta)",
                          'firmware_file': "T2700G-28TQv2_2.20.1_20200623-rel59799(Beta).bin",
                          'conf_standart': "T2700G-28TQblank.cfg",
                          'list_stsw_port': [1, 21],
                          'method_upd': 'snmp'
                          }
        self.connect_data = AUTH.get_connest_data()
        self.snmp_get_param = {'model': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.5.0',
                               'vendor_firmware': 'snmpget -Oqv -c private -v 2c <newsw_ip>  .1.3.6.1.4.1.11863.6.1.1.6.0',
                               'newsw_serial': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.8.0',
                               'newsw_mac': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.7.0'
                               }

        self.snmp_fw_up = {
            1: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.8.1.0 s <tftp_serever>',
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
        self.logger = app_logger.get_logger("Devices/snmp/2700")

    def fw_update_snmp(self, newsw_ip, tftp_server) -> None:
        """
        Loads the firmware located on the tftp_server on the T2700G switch behind the newsw_ip port via snmp requests.

        :param newsw_ip: str
        :param tftp_server: str
        :return: None
        """
        name_foo = f"fw_update_ip_{newsw_ip}"
        self.statuses_foo_devices[name_foo] = 'Start'
        self.dev_params_after['status_upd'] = 'start'
        for step, snmp_cmd in (self.snmp_fw_up).items():
            try:
                snmp_request = snmp_cmd['req'].replace("<newsw_ip>", newsw_ip)
                snmp_request = snmp_request.replace("<tftp_serever>", tftp_server)
                snmp_request = snmp_request.replace("<name_firmware>", self.base_data['firmware_file'])
                snmp_request = snmp_request.replace("<config_name>", self.base_data['conf_standart'])
                self.logger.info(f"Step: {step}. Request: {snmp_request}")

                response_snmp = subprocess.check_output(snmp_request, shell=True)
                if step == 3:
                    time.sleep(5)
                res = response_snmp.decode('utf-8')
                res = res.replace('"', '')
                res = res.replace('\n', '')
                res = res.replace('\r', '')
                self.logger.info(f"Step firmware upgrade: {step}. Response snmp: {res}")
                if step == 4:
                    for try_get_0 in range(1, 6):

                        if '0' in res:
                            self.dev_params_after['cfg'] = 'Ok'
                            break
                        else:
                            self.dev_params_after['cfg'] = 'Error'
                            self.logger.info(f"Try get answer status update cfg {try_get_0}")
                            time.sleep(1)
                            response_snmp = subprocess.check_output(snmp_request, shell=True)
                            res = response_snmp.decode('utf-8')
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
                self.logger.error(f"Error on firmware upgrade. Step {step}: {ex}")
                self.dev_params_after['status_upd'] = 'Error'
                self.statuses_foo_devices[name_foo] = 'Break'


class TP_LINK_T2600G_28TS_DC_1_0(DEVICES_TPLINK):
    def __init__(self) -> None:
        """
        Child class for different parameters and functions TP-LINK-T2600G-28TS-DC1.0
        """
        super(TP_LINK_T2600G_28TS_DC_1_0, self).__init__()
        self.base_data = {
            'model': "T2600G-28TS-DC 1.0",
            'firmware': "1.0.0 Build 20200514 Rel.40674(Beta)",
            'firmware_file': "T2600G-28TS-DCv1_1.0.0_20200514-rel40674(Beta).bin",
            'conf_standart': "T2600G-28TS-DCblank.cfg",
            'list_stsw_port': [1, 21],
            'method_upd': 'snmp'
        }
        self.connect_data = AUTH.get_connest_data()
        self.snmp_get_param = {'model': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.5.0',
                               'vendor_firmware': 'snmpget -Oqv -c private -v 2c <newsw_ip>  .1.3.6.1.4.1.11863.6.1.1.6.0',
                               'newsw_serial': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.8.0',
                               'newsw_mac': 'snmpget -Oqv -c private -v 2c <newsw_ip> .1.3.6.1.4.1.11863.6.1.1.7.0'
                               }

        self.snmp_fw_up = {
            1: {'req': 'snmpset -v2c -c private <newsw_ip> .1.3.6.1.4.1.11863.6.3.1.5.1.0 s <tftp_serever>',
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
                             2: {'req': 'firmware upgrade ip-address <tftp_server> filename ' + self.base_data[
                                 'firmware_file'],
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
                             8: {'req': 'copy tftp startup-config ip-address <tftp_server> filename ' + self.base_data[
                                 'conf_standart'] + '.cfg',
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

    def fw_update_snmp(self, newsw_ip, tftp_server) -> None:
        """
        Loads the firmware located on the tftp_server on the T2600G switch behind the newsw_ip port via snmp requests.

        :param newsw_ip: str
        :param tftp_server: str
        :return: None
        """
        name_foo = f"fw_update_ip_{newsw_ip}"
        self.statuses_foo_devices[name_foo] = 'Start'
        self.dev_params_after['status_upd'] = 'start'
        for step, snmp_cmd in (self.snmp_fw_up).items():
            try:
                snmp_request = snmp_cmd['req'].replace("<newsw_ip>", newsw_ip)
                snmp_request = snmp_request.replace("<tftp_serever>", tftp_server)
                snmp_request = snmp_request.replace("<name_firmware>", self.base_data['firmware_file'])
                snmp_request = snmp_request.replace("<config_name>", self.base_data['conf_standart'])
                self.logger.info(f"Step: {step}. Request: {snmp_request}")
                response_snmp = subprocess.check_output(snmp_request, shell=True)
                if step == 4:
                    time.sleep(5)
                res = response_snmp.decode('utf-8')
                res = res.replace('"', '')
                res = res.replace('\n', '')
                res = res.replace('\r', '')
                self.logger.info(f"Step firmware upgrade: {step}. Response snmp: {res}")
                if step == 4:
                    if 'system is upgrading' in res:
                        self.dev_params_after['status_upd'] = 'Process'
                        self.statuses_foo_devices[name_foo] = 'Ok'
                    else:
                        self.dev_params_after['status_upd'] = 'Error'
                        self.statuses_foo_devices[name_foo] = 'Error'
            except Exception as ex:
                self.logger.error(f"Error on firmware upgrade. Step {step}: {ex}")
                self.dev_params_after['status_upd'] = 'Error'
                self.statuses_foo_devices[name_foo] = 'Break'
