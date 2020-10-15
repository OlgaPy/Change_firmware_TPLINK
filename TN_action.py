#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'
from lib_to import app_logger
import telnetlib
import time
import re
import os


class TN_act:
    def __init__(self):
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
        self.real_responce_b = ''
        self.statuses_foo_telnet = {}


    def telnet_connect(self, ip, port, user, password, timeout_tn=20, rlogin="User:", rpass="Password:"):
        self.loger = app_logger.get_logger("Telnet_action ip=%s" %ip)
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
            self.loger.info("Telnet connect ip %s - OK" %(ip))
        except Exception as ex:
            self.status_connect = 'Error ' + str(ex)
            self.loger.error("Telnet connect ip %s - Error: %s" %(ip, str(ex)))
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
            self.status_connect = 'OK, login'
            self.real_responce_b = part_answer_tup[1].group(1)
        # self.tn.read_until(self.connect_answer.encode("ascii"))
        # print("telnet successful")

    def turn_off_all_ports(self):
        self.statuses_foo_telnet['turn_off_port'] = 'Start'
        algoritm_configure_port = { 1: {'req': 'en',
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
                self.loger.info("Request: %s" %(dialog['req']))
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                if part_answer_tup is not None:
                    self.loger.info("Responce: %s " %((part_answer_tup[1].group(0)).decode('utf-8')))

            except Exception as ex:
                self.statuses_foo_telnet['turn_off_all_ports'] = 'Error'
                self.loger.error("Error turn off all ports at step %s. Error: %s" %(str(step), str(ex)))
                return
            self.statuses_foo_telnet['turn_off_all_ports'] = 'Ok'



    def telnet_dialog(self, request_responce, flag_tn_close='', flag_cycle='continue', step_stop=100):

        errors = {}
        for step, dialog in request_responce.items():
            request = dialog['req']
            responce = dialog['resp']
            try:
                time.sleep(1)
                self.tn.write(request.encode("ascii") + b"\r\n")
                if step != step_stop:
                    self.tn.read_until(responce.encode("ascii"))
            except Exception as ex:
                errors[step] = str(ex)
                if 'step' in flag_tn_close:
                    self.status_connect = 'Close'
                    self.tn.close()
                if flag_cycle == 'break':
                    break
                elif flag_cycle == 'continue':
                    continue
        if 'after_cycle' in flag_tn_close:
            self.status_connect = 'Close'
            self.tn.close()

        return errors

    def turn_on_port(self, stsw_port_number):

        name_foo = ("turn_on_port_%s" %(str(stsw_port_number)))
        self.statuses_foo_telnet[name_foo] = 'Ok'
        algoritm_turn_on_port = { 1: {'req': 'interface gigabitEthernet 1/0/' + str(stsw_port_number),
                                      'resp_part': "(config-if)"},
                                  2: {'req': 'no shutdown',
                                      'resp_part': "(config-if)"},
                                }
        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_turn_on_port.items():
            try:
                time.sleep(1)
                self.loger.info("Request: %s" %(dialog['req']))
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                if part_answer_tup is not None:
                    self.loger.info("Responce: %s " %((part_answer_tup[1].group(0)).decode('utf-8')))

            except Exception as ex:
                self.statuses_foo_telnet[name_foo] = 'Error'
                self.loger.error("Error turn on port %s at step %s. Error: %s" %(str(stsw_port_number), str(step), str(ex)))
                return
            self.statuses_foo_telnet[name_foo] = 'Ok'


    def turn_off_port(self, stsw_port_number):
        name_foo = ("turn_off_port_%s" %(str(stsw_port_number)))
        self.statuses_foo_telnet[name_foo] = 'Start'
        algoritm_turn_on_port = { 1: {'req': 'interface gigabitEthernet 1/0/' + str(stsw_port_number),
                                      'resp_part': "(config-if)"},
                                  2: {'req': 'shutdown',
                                      'resp_part': "(config-if)"},
                                  }
        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_turn_on_port.items():
            try:
                time.sleep(1)
                self.loger.info("Request: %s" %(dialog['req']))
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                if part_answer_tup is not None:
                    self.loger.info("Responce: %s " %((part_answer_tup[1].group(0)).decode('utf-8')))

            except Exception as ex:
                self.statuses_foo_telnet[name_foo] = 'Error'
                self.loger.error("Error turn on port %s at step %s. Error: %s" %(str(stsw_port_number), str(step), str(ex)))
                return
            self.statuses_foo_telnet[name_foo] = 'Ok'


    def change_one_ip(self, newsw_ip):
        name_foo = ("change_one_ip_%s" %(newsw_ip))
        self.statuses_foo_telnet[name_foo] = 'Start'
        algoritm_change_ip = {1: {'req': 'en',
                                  'resp_part':  '#'},
                              2: {'req': 'configure',
                                  'resp_part': '(config)#'},
                              3: {'req': 'snmp-server',
                                  'resp_part': '(config)#'},
                              4: {'req': 'snmp-server community private read-write',
                                  'resp_part': '(config)#'},
                              5: {'req': 'ip route 0.0.0.0 0.0.0.0 192.168.0.100',
                                  'resp_part':  '(config)#'},
                              6: {'req': 'interface vlan 1',
                                  'resp_part':  '(config-if)#'},
                              7: {'req': 'ip address ' + newsw_ip + ' 255.255.255.0',
                                  'resp_part': ''}
                              }

        re_part_answer = re.compile(b"(.*?)(\>|\#)")
        for step, dialog in algoritm_change_ip.items():
            try:
                time.sleep(1)
                self.loger.info("Request: %s" %(dialog['req']))
                self.tn.write(dialog['req'].encode("ascii") + b"\r\n")
                if step != 7: # после команды на смену ip выкидывает с телнета
                    part_answer_tup = self.tn.expect([re_part_answer], timeout=5)
                    if part_answer_tup is not None:
                        self.loger.info("Responce: %s " %((part_answer_tup[1].group(0)).decode('utf-8')))

            except Exception as ex:
                self.statuses_foo_telnet[name_foo] = 'Error'
                self.loger.error("Error change ip %s at step %s. Error: %s" %(str(newsw_ip), str(step), str(ex)))
                return
            self.statuses_foo_telnet[name_foo] = 'Ok'


    def get_actual_fw(self):
        self.tn.write('en'.encode("ascii") + b"\r\n")

        self.tn.write('show system-info'.encode("ascii") + b"\r\n")

        re_fw = (b"(Firmware|Software) Version(.*?)\n")
        real_fw = 'No data'
        for step in range(1, 5):
            # while flag_exit == 0:
            part_answer_tup = self.tn.expect([re_fw], timeout=5)
            if part_answer_tup is not None:
                real_fw = part_answer_tup[1].group(2)
                break
            self.tn.write(b"\r\n")
        return real_fw



    def telnet_close(self):
        self.status_connect = 'Close'
        self.tn.close()
