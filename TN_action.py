#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'

import app_logger
import telnetlib
import time
import re
import os


class TN_act:
    def __init__(self):
        """
        Class of the telnet connection to the switch. Contains all necessary (within this application)
        methods and parameters for used actions
        """
        self.status_connect = ''
        self.tn = ''
        self.ip = ''
        self.user = ''
        self.connect_answer = ''
        self.port = ''
        self.user = ''
        self.password = ''
        self.connect_answer = ''
        self.rlogin = ''
        self.rpass = ''
        self.part_answer = ''
        self.real_response_b = ''
        self.statuses_foo_telnet = {}

    def telnet_connect(self, ip: str, port: int, user: str, password: str,
                       timeout_tn=20, rlogin="User:", rpass="Password:") -> None:
        """
        Establishes a telnet connection to the switch. fills in the passed parameters in the variables of the
        class object for further use.
        :param ip: str
        :param port: int
        :param user: str
        :param password: str
        :param timeout_tn: int
        :param rlogin: str
        :param rpass: str
        :return: None
        """
        self.logger = app_logger.get_logger(f"Telnet_action ip={ip}")
        self.status_connect = 'null'
        self.tn = 'null'
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.rlogin = rlogin
        self.rpass = rpass

        try:
            self.tn = telnetlib.Telnet(ip, port, timeout_tn)
            self.status_connect = 'OK'
            self.logger.info(f"Telnet connect ip {ip} - OK")
        except Exception as ex:
            self.status_connect = 'Error'
            self.logger.error(f"Telnet connect ip {ip} - Error: {ex}")
            return

        # self.tn.read_until(b"User:")
        self.tn.read_until(self.rlogin.encode("ascii"))
        self.tn.write(self.user.encode("ascii") + b"\r\n")

        # tn.read_until(b"Password:")
        self.tn.read_until(self.rpass.encode("ascii"))
        self.tn.write(self.password.encode("ascii") + b"\r\n")

        re_part_answer = re.compile(b"(\S+)(\>|\#)")
        part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
        if part_answer_tup is not None:
            self.status_connect = 'OK'
            self.real_response_b = part_answer_tup[1].group(1)

    def turn_off_all_ports(self) -> None:
        """
        Turns off all ports on the stand switch
        :return: None
        """
        self.statuses_foo_telnet['turn_off_port'] = 'Start'
        algoritm_configure_port = {1: {'req': 'en',
                                       'part_resp': ''},
                                   2: {'req': 'configure',
                                       'part_resp': '(config)'},
                                   3: {'req': 'interface ra gigabitEthernet 1/0/1-20',
                                       'part_resp': '(config-if-range)'},
                                   4: {'req': 'shutdown',
                                       'part_resp': '(config-if-range)'},
                                   }
        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_configure_port.items():
            try:
                time.sleep(1)
                self.logger.info(f"Request: {dialog['req']}")
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                if part_answer_tup is not None:
                    self.logger.info(f"Response: {(part_answer_tup[1].group(0)).decode('utf-8')}")

            except Exception as ex:
                self.statuses_foo_telnet['turn_off_all_ports'] = 'Error'
                self.logger.error(f"Error turn off all ports at step {step}. Error: {ex}")
                return
            self.statuses_foo_telnet['turn_off_all_ports'] = 'Ok'

    def telnet_dialog(self, request_response: dict, flag_tn_close='', flag_cycle='continue', step_stop=100) -> dict:
        """
        Universal function for telnet dialog. It takes as its argument the request_response dictionary,
        which stores commands to be sent and expected responses or part of them.
        :param request_response: dict
        :param flag_tn_close: str
        :param flag_cycle: str
        :param step_stop: int
        :return: errors : dict
        """

        errors = {}
        for step, dialog in request_response.items():
            request = dialog['req']
            response = dialog['resp']
            try:
                time.sleep(1)
                self.tn.write(request.encode("ascii") + b"\r\n")
                if step != step_stop:
                    self.tn.read_until(response.encode("ascii"))
            except Exception as ex:
                errors[step] = str(ex)
                if 'step' in flag_tn_close:
                    self.status_connect = 'Close'
                    self.tn.close()
                if flag_cycle == 'continue':
                    continue
                elif flag_cycle == 'break':
                    break
        if 'after_cycle' in flag_tn_close:
            self.status_connect = 'Close'
            self.tn.close()

        return errors

    def turn_on_port(self, stsw_port_number: int) -> None:
        """
        Turns on one port on stand switch
        :param stsw_port_number: int
        :return: None
        """

        name_foo = (f"turn_on_port_{stsw_port_number}")
        self.statuses_foo_telnet[name_foo] = 'Ok'
        algoritm_turn_on_port = {1: {'req': f'interface gigabitEthernet 1/0/{stsw_port_number}',
                                     'resp_part': "(config-if)"},
                                 2: {'req': 'no shutdown',
                                     'resp_part': "(config-if)"},
                                 }
        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_turn_on_port.items():
            try:
                time.sleep(1)
                self.logger.info(f"Request: {dialog['req']}")
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                if part_answer_tup is not None:
                    self.logger.info(f"Response: {(part_answer_tup[1].group(0)).decode('utf-8')} ")

            except Exception as ex:
                self.statuses_foo_telnet[name_foo] = 'Error'
                self.logger.error(f"Error turn on port {stsw_port_number} at step {step}. Error: {ex}")
                return
            self.statuses_foo_telnet[name_foo] = 'Ok'

    def turn_off_port(self, stsw_port_number: int) -> None:
        """
        Turns off one port on stand switch
        :param stsw_port_number:
        :return:
        """
        name_foo = (f"turn_off_port_{stsw_port_number}")
        self.statuses_foo_telnet[name_foo] = 'Start'
        algoritm_turn_on_port = {1: {'req': f'interface gigabitEthernet 1/0/{stsw_port_number}',
                                     'resp_part': "(config-if)"},
                                 2: {'req': 'shutdown',
                                     'resp_part': "(config-if)"},
                                 }
        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_turn_on_port.items():
            try:
                time.sleep(1)
                self.logger.info(f"Request: {dialog['req']}")
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                if part_answer_tup is not None:
                    self.logger.info(f"Response: {(part_answer_tup[1].group(0)).decode('utf-8')}")

            except Exception as ex:
                self.statuses_foo_telnet[name_foo] = 'Error'
                self.logger.error(f"Error turn on port {stsw_port_number} at step {step}. Error: {ex}")
                return
            self.statuses_foo_telnet[name_foo] = 'Ok'

    def change_one_ip(self, newsw_ip: str) -> None:
        """
        Enabling snmp on the switch and changing the ip-address of the switch.
        :param newsw_ip: str
        :return: None
        """
        name_foo = (f"change_one_ip_{newsw_ip}")
        self.statuses_foo_telnet[name_foo] = 'Start'
        algoritm_change_ip = {1: {'req': 'en',
                                  'resp_part': '#'},
                              2: {'req': 'configure',
                                  'resp_part': '(config)#'},
                              3: {'req': 'snmp-server',
                                  'resp_part': '(config)#'},
                              4: {'req': 'snmp-server community private read-write',
                                  'resp_part': '(config)#'},
                              5: {'req': 'ip route 0.0.0.0 0.0.0.0 192.168.0.100',
                                  'resp_part': '(config)#'},
                              6: {'req': 'interface vlan 1',
                                  'resp_part': '(config-if)#'},
                              7: {'req': f'ip address {newsw_ip} 255.255.255.0',
                                  'resp_part': ''}
                              }

        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_change_ip.items():
            try:
                time.sleep(1)
                self.logger.info(f"Request: {dialog['req']}")
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                if step != 7:  # после команды на смену ip выкидывает с телнета
                    part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                    if part_answer_tup is not None:
                        self.logger.info(f"Responce: {(part_answer_tup[1].group(0)).decode('utf-8')}")

            except Exception as ex:
                self.statuses_foo_telnet[name_foo] = 'Error'
                self.logger.error(f"Error change ip {newsw_ip} at step {step}. Error: {ex}")
                return
            self.statuses_foo_telnet[name_foo] = 'Ok'

    def get_actual_fw(self) -> str:
        """
        Getting the current firmware version from the switch.
        :return: real_fw: str
        """
        self.tn.write('en'.encode("ascii") + b"\r\n")

        self.tn.write('show system-info'.encode("ascii") + b"\r\n")

        re_fw = (b"(Firmware|Software) Version(.*?)\n")
        real_fw = 'No data'
        for step in range(1, 5):
            part_answer_tup = self.tn.expect([re_fw], timeout=5)
            if part_answer_tup is not None:
                real_fw = part_answer_tup[1].group(2)
                break
            self.tn.write(b"\r\n")
        return real_fw

    def telnet_close(self) -> None:
        """
        Closing telnet connection
        :return: None
        """
        self.status_connect = 'Close'
        self.tn.close()
