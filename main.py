#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'
from PyQt5.QtCore import pyqtSignal, QObject

from Devices import *
from lib_to import app_logger
import librouteros
import psycopg2
import os
import time
import psutil
from threading import Thread
from sys import argv
from TN_action import TN_act as TN_act
import autentification as AUTH

class BOLVANIZATOR(QObject):
    mysignal = pyqtSignal(dict)
    button_sig = pyqtSignal()
    after_sig = pyqtSignal()
    final = pyqtSignal()
    def __init__(self):
        super().__init__()
        self.loger = app_logger.get_logger("Main")
        # self.params = []
        # self.params = argv
        self.stsw_IP = AUTH.get_stsw_ip()
        self.stmik_IP = AUTH.get_stmik_ip()
        self.parent_ip = '192.168.0.1'
        self.tftp_server = AUTH.get_tftp_server_ip()
        self.to_bd = {'ports': {}}
        self.stend ={'ip': self.stsw_IP,
                     'port': 23,
                     'list_stsw_port': [1,6],
                     'dialog': {'user': AUTH.get_stend_login(),
                                'password': AUTH.get_stend_pass(),
                                'part_answer': 'T2600G-28TS-DC',

                                },
                     }

        self.mikrotik= {'ip': self.stmik_IP,
                        'port': 23,
                        'dialog': {'user': AUTH.get_mik_login(),
                                   'password': AUTH.get_mik_pass(),
                                   'part_answer': '[admin@MikroTik] >',
                                   }
                        }
        self.fact_devices = {}
        self.good_port = []

        self.statuses_foo = {}
        self.actual_table = {'general': {'MIKROTIK': False,
                                         'SWITCH': False,
                                         'TFTP_SERVER': False,
                                         'BD': False  },
                             'main_table': {}
                             }
        self.log_fw_up = {}
        self.db_cursor = ''
        self.deb_connect = ''



    def run_action(self):
        self.statuses_foo['run_action'] = 'Start'

        flag_exit = self.test_systems()
        if flag_exit:
            self.loger.error("Test systems was failed")
            self.statuses_foo['run_action'] = 'Break'
            return


        #смена IP
        self.action_at_stend() #запись в actual_table внутри, объекты в self.fact_devices
        self.mysignal.emit(self.actual_table)


        # #______TO TEST______
        # self.test_devices = { '1': TP_LINK_T2700G_28TQ_2_20(),
        #                  '2': TP_LINK_T2600G_28TS_DC_1_0(),
        #                  '3': TP_LINK_T2700G_28TQ_2_20()}
        #
        # for port, object_dev in self.test_devices.items():
        #     model_N = object_dev
        #     model_N.stend_data['IP'] = '192.168.0.10' + port
        #     model_N.stend_data['port'] = port
        # #-----TO TEST---------


        threads = []
        # for stsw_port_number, object_dev in self.test_devices.items():


        for stsw_port_number, object_dev in (self.fact_devices).items():
            self.mysignal.emit(self.actual_table)
            if object_dev == {}:
                continue
            model_N = object_dev
            model_ip = model_N.stend_data['IP']
            model_N.set_mirk_ip(self.stmik_IP)
            name = "Thread for port #%s" + str(stsw_port_number)
            if model_ip != 0 and model_ip != '':
                snmp_thread = Thread(name=name, target=model_N.check_snmp_param)
                snmp_thread.start()
                threads.append(snmp_thread)

        for j in threads:
            j.join()
        self.mysignal.emit(self.actual_table)

        for port, object_dev in (self.fact_devices).items():
            if object_dev == {}:
                continue
            model_N = object_dev
            try:
                self.actual_table['main_table'][port]['snmp_params'] = model_N.statuses_foo_devices['get_param_snmp']
                self.actual_table['main_table'][port]['model'] = model_N.dev_params_behind['model']
                self.actual_table['main_table'][port]['serial_number'] = model_N.dev_params_behind['newsw_serial']
                self.actual_table['main_table'][port]['MAC'] = model_N.dev_params_behind['newsw_mac']
                self.actual_table['main_table'][port]['actual_firmware'] = model_N.dev_params_behind['vendor_firmware']
                self.actual_table['main_table'][port]['status_fw_up'] = model_N.status_snmp_data['status_fw_up']
            except Exception as ex:
                self.loger.error("Error from add param snmp to table on port %s. Error: %s" %(str(port), str(ex)))
        self.statuses_foo['run_action'] = 'Ok'
        self.mysignal.emit(self.actual_table)

        self.button_sig.emit() #разблокировать кнопку в gui

    def test_systems(self):
        self.statuses_foo['test_systems'] = 'Start'
        flag_exit = False
        stend_TN_a = TN_act()
        stend_TN_a.telnet_connect(self.stend['ip'], self.stend['port'], self.stend['dialog']['user'], self.stend['dialog']['password'])
        if (stend_TN_a.status_connect == 'null') or ("Error" in stend_TN_a.status_connect):
            self.loger.error('EXIT!! Telnet connect to stend %s - Error' %self.stend['ip'])
            flag_exit = True
        else:
            self.actual_table['general']['SWITCH'] = True
            self.loger.info("Telnet connect stend %s - OK" %self.stend['ip'])
        self.mysignal.emit(self.actual_table)


        test_model_1 = TP_LINK_T2700G_28TQ_2_20()
        test_model_2 = TP_LINK_T2600G_28TS_DC_1_0()


        #---------проверяем что файл на сервере C:\tftp conf_standart для моделей sp_model существует-------
        flag_cfg = False
        path_1 = 'C:\\tftp\\' + (test_model_1.base_data['conf_standart'])
        # path_2 = 'C:\\tftp\\' + (test_model_2.base_data['conf_standart'])

        try:
            check_file = open(path_1)
            check_file.close()
            self.loger.info("%s on tftp - OK" % test_model_1.base_data['conf_standart'])

            flag_cfg = True
        except Exception as ex:
            self.loger.error("EXIT!! ERROR ON FILE WITH FIRMWARE")
            flag_exit = True
        self.mysignal.emit(self.actual_table)


        #--------проверить что тфтп сервер запущен----------------------
        flag_tftp = False
        for process in psutil.process_iter():
            if "tftpd32.exe" in (process.name()):
                flag_tftp = True
        if not flag_tftp:
            self.loger.error("EXIT!! tftpd32.exe IS NOT RUNNIN")
            flag_exit = True

        if (flag_cfg == True) and (flag_tftp == True):
            self.actual_table['general']['TFTP_SERVER'] = True
            self.loger.info("tftpd32.exe is running - OK")
            self.mysignal.emit(self.actual_table)


        #Проверка соединения с микротиком
        # try:
        #     mik_client = librouteros.connect(self.mikrotik['ip'], self.mikrotik['dialog']['user'], self.mikrotik['dialog']['password'])
        #     if mik_client is not None:
        #         self.actual_table['general']['MIKROTIK'] = True
        # except Exception as ex:
        #     self.loger.error("Error on connect to mikrotik %s" %ex)
        # self.mysignal.emit(self.actual_table)

        #Проверка доступности БД
        if self.connect_db():
            self.actual_table['general']['BD'] = True
            self.loger.info("Connect to DB - OK")
        else:
            self.loger.error("EXIT!! Not connect to BD")
            # flag_exit = True
        self.statuses_foo['test_systems'] = 'Ok'
        self.mysignal.emit(self.actual_table)

        return flag_exit

    def action_at_stend(self):

        #----------открываем сессию на стендовый коммутатор --------------/////stsw_ip
        self.statuses_foo['action_at_stend'] = 'Start'

        stend_TN_a = TN_act()
        stend_TN_a.telnet_connect(self.stend['ip'], self.stend['port'], self.stend['dialog']['user'], self.stend['dialog']['password'])
        if (stend_TN_a.status_connect == 'null') or ("Error" in stend_TN_a.status_connect):
            self.loger.error('EXIT!! Telnet connect to stend %s - Error' %self.stend['ip'])
            self.statuses_foo['action_at_stend'] = 'Break'
            return
        self.loger.info("Telnet connect stend %s - OK" %self.stend['ip'])

        #---------выключаем порты в сторону тфтп компа и микротика---------
        stend_TN_a.turn_off_all_ports()
        if (stend_TN_a.statuses_foo_telnet.get('turn_off_all_ports', 0) == 0) or (stend_TN_a.statuses_foo_telnet.get('turn_off_all_ports') != 'Ok'):
            self.loger.error("Error! Stend %s is not connected" %(self.stend['ip']))
            self.statuses_foo['action_at_stend'] = 'Break'
            return
        self.loger.info("Stend %s telnet connect - Ok" %(self.stend['ip']))
        self.mysignal.emit(self.actual_table)

        #---------смена айпишников на всех свичах----------------------
        for stsw_port_number in range(self.stend['list_stsw_port'][0], self.stend['list_stsw_port'][1]):
            # if (stsw_port_number in [1, 2, 3, 4]) or stsw_port_number in ['1', '2', '3', '4']:
            #     continue
            self.mysignal.emit(self.actual_table)
            self.actual_table['main_table'][stsw_port_number] = { 'port': stsw_port_number,
                                                                  'status_port':  'Down',
                                                                  'IP_switch': 'No data',
                                                                  'snmp_params': 'No data',
                                                                  'ping': 'No data',
                                                                  'model': 'No data',
                                                                  'serial_number': 'No data',
                                                                  'MAC': 'No data',
                                                                  'status_fw_up': 'No data',
                                                                  'actual_firmware': 'No data',
                                                                  'firmware_up': 'No data',
                                                                  'cfg_up': 'No data',
                                                                  'write_bd': 'No data'
                                                                  }
            self.fact_devices[stsw_port_number] = {}
            req_arp_1 = 'arp -d %s' %self.parent_ip
            req_arp_2 = 'arp -d %s' %('192.168.0.' + str(100 + int(stsw_port_number)))
            arp_k_1 = os.system(req_arp_1)
            arp_k_2 = os.system(req_arp_2)
            stend_TN_a.turn_on_port(stsw_port_number)
            name_foo = ("turn_on_port_%s" %(str(stsw_port_number)))
            if (stend_TN_a.statuses_foo_telnet.get(name_foo, 0) == 0) or (stend_TN_a.statuses_foo_telnet.get(name_foo) != 'Ok'):
                self.loger.error("Error port %s turn on" %(str(stsw_port_number)))
                continue
            self.loger.info("Port %s turn on - Ok" %(str(stsw_port_number)))
            self.actual_table['main_table'][stsw_port_number]['status_port'] = 'Up'

            name_foo_ch_ip = ('change_ip_at_stend_port_%s' %str(stsw_port_number))

            self.change_ip_at_stend(
                stsw_port_number)  # name_foo = ('change_ip_at_stend_port_%s' %str(stsw_port_number)) #это внутри!!!
            # IP, ping в actual_table внутри


            if self.statuses_foo[name_foo_ch_ip] == 'Ok':
                self.good_port.append(stsw_port_number)
            else:
                self.actual_table['main_table'][stsw_port_number]['ping'] = 'Error'
                stend_TN_a.turn_off_port(stsw_port_number)
                name_foo = ("turn_off_port_%s" %(str(stsw_port_number)))
                if (stend_TN_a.statuses_foo_telnet.get(name_foo, 0) == 0) or (stend_TN_a.statuses_foo_telnet.get(name_foo) != 'Ok'):
                    self.loger.error("Error port %s turn off" %(str(stsw_port_number)))
                self.actual_table['main_table'][stsw_port_number]['status_port'] = 'Down'
                continue
            self.mysignal.emit(self.actual_table)
        self.mysignal.emit(self.actual_table)


        #---------все свитчи модели настроены на временные айпи---------
        stend_TN_a.telnet_close()
        self.loger.info("Close telnet connect to send - Ok")
        self.statuses_foo['action_at_stend'] = 'Ok'

    def change_ip_at_stend(self, stsw_port_number, parrent_part_ip='192.168.0.'):

        name_foo = ('change_ip_at_stend_port_%s' %str(stsw_port_number))
        self.statuses_foo[name_foo] = 'Start'
        newsw_ip = parrent_part_ip + str(100 + stsw_port_number)
        # #может  ивм обычный коммут, а может со смененным ip и его надо только в fact_devices добавить определив модель


        subswitch_TN_a = {}
        TPLINK = {}
        objects_classes = {}
        real_ip = ''
        threads_tn = []
        for ip in self.parent_ip, newsw_ip:
            subswitch_TN_a_test = TN_act()
            TPLINK_test = DEVICES_TPLINK()
            objects_classes[ip] = {'tn': subswitch_TN_a_test,
                                   'dev': TPLINK_test}
            tn_thread = Thread(name=ip, target=subswitch_TN_a_test.telnet_connect, args=(ip, TPLINK_test.connect_data['port'], TPLINK_test.connect_data['user'], TPLINK_test.connect_data['password']), kwargs={"timeout_tn": 30})
            tn_thread.start()
            threads_tn.append(tn_thread)

        for k in threads_tn:
            k.join()
        self.mysignal.emit(self.actual_table)
        for ip, objects in objects_classes.items():
            if 'OK' in (objects['tn']).status_connect:
                real_ip = ip
                subswitch_TN_a = objects['tn']
                TPLINK = objects['dev']
                self.loger.info("Telnet connect to ip %s from port %s - OK" %(ip, stsw_port_number))
        if subswitch_TN_a == {}:
            self.loger.error("Error connect to ip %s and ip %s from port %s.")
            self.loger.error("Error connect ip %s : %s" %(self.parent_ip, (objects_classes[self.parent_ip]['tn']).status_connect))
            self.loger.error("Error connect ip %s : %s"%(newsw_ip, (objects_classes[newsw_ip]['tn']).status_connect))
            self.statuses_foo[name_foo] = 'Error'
            self.actual_table['main_table'][stsw_port_number]['ping'] = 'Error'
            self.mysignal.emit(self.actual_table)
            return

        self.actual_table['main_table'][stsw_port_number]['ping'] = 'Ok'
        self.loger.info("Telnet connect to ip %s from port %s - OK" %(ip, stsw_port_number))


        if b'T2700G-28TQ' in subswitch_TN_a.real_responce_b :
            model_N = TP_LINK_T2700G_28TQ_2_20()
        elif b'T2600G-28TS-DC' in subswitch_TN_a.real_responce_b:
            model_N = TP_LINK_T2600G_28TS_DC_1_0()
        else:
            self.loger.error("Unknown model %s" % subswitch_TN_a.real_responce_b)
            self.actual_table['main_table'][stsw_port_number]['model'] = 'Unknown model'
            self.statuses_foo[name_foo] = 'Break'
            self.mysignal.emit(self.actual_table)
            return

        self.fact_devices[stsw_port_number] = model_N

        if real_ip == newsw_ip:
            self.statuses_foo[name_foo] = 'Ok'
            model_N.stend_data['IP'] = ip
            model_N.stend_data['port'] = stsw_port_number
            self.statuses_foo['name_foo'] = 'Ok'
            self.actual_table['main_table'][stsw_port_number]['IP_switch'] = real_ip
            self.actual_table['main_table'][stsw_port_number]['ping'] = 'Nu Ok'
            self.mysignal.emit(self.actual_table)
            return


        subswitch_TN_a.change_one_ip(newsw_ip)
        name_foo_ip = ("change_one_ip_%s" %(newsw_ip))

        if (subswitch_TN_a.statuses_foo_telnet.get(name_foo_ip, 0) == 0) or (subswitch_TN_a.statuses_foo_telnet.get(name_foo_ip) != 'Ok'):
            self.loger.error("Error change ip %s " %(newsw_ip))
            self.statuses_foo[name_foo_ip] = 'Error'
            self.mysignal.emit(self.actual_table)
            return
        self.statuses_foo[name_foo_ip] = 'Ok'
        self.loger.info("Change ip %s on port %s - Ok" %(newsw_ip, str(stsw_port_number)))
        self.actual_table['main_table'][stsw_port_number]['IP_switch'] = newsw_ip


        model_N.stend_data['IP'] = newsw_ip
        model_N.stend_data['port'] = stsw_port_number
        self.statuses_foo[name_foo] = 'Ok'
        self.mysignal.emit(self.actual_table)

    def set_ip(self, ip):
        self.stsw_ip = ip

    def set_port(self, start, finish):
        self.stend['list_stsw_port'].clear()
        self.stend['list_stsw_port'].append(int(start))
        self.stend['list_stsw_port'].append(int(finish) + 1)

    def obolvanit(self):
        #шить только если у object_dev  в status_snmp_data в status_model и status_fw стоит OK!!

        threads = []
        self.mysignal.emit(self.actual_table)
        # for stsw_port_number, object_dev in self.test_devices.items():
        for stsw_port_number, object_dev in self.fact_devices.items():
            if object_dev == {}:
                continue
            if object_dev.status_snmp_data['status_fw_up'] != 'Yes':
                continue
            model_N = object_dev
            successful_ip = model_N.stend_data['IP']
            fw_up_thread = Thread(target=model_N.fw_update, args=(self.tftp_server, stsw_port_number))
            fw_up_thread.start()
            threads.append(fw_up_thread)

        for j in threads:
            j.join()
        self.mysignal.emit(self.actual_table)

        for stsw_port_number, object_dev in self.fact_devices.items():
            if object_dev == {}:
                continue
            if object_dev.dev_params_after == '':
                continue
            model_N = object_dev
            self.actual_table['main_table'][stsw_port_number]['cfg_up'] = (model_N.dev_params_after).get('cfg')
            self.mysignal.emit(self.actual_table)

        self.after_sig.emit()

    def connect_db(self, flag_close=True):
        status = False
        self.db_connect = psycopg2.connect(
            database="grafana_db",
            user="grafana",
            password="Grafana!@",
            host="grafana-db.ertelecom.ru",
            port="49196"
        )
        try:
            self.db_cursor = self.db_connect.cursor()
            status = True
            if flag_close:
                self.db_cursor.close()
        except Exception as ex:
            self.loger.error("Error connect to db, %s" %str(ex))

        return status


    def get_one_fw_telnet(self, stsw_port_number, parrent_ip='192.168.0.1'):
        self.loger.info("Try telnet connect to port %s" %(str(stsw_port_number)))
        subswitch_TN_a = {}
        TPLINK = {}
        objects_classes = {}
        newsw_ip = '192.168.0.' + str(100 + int(stsw_port_number))
        real_ip = ''
        threads_tn = []
        for ip in self.parent_ip, newsw_ip:
            subswitch_TN_a_test = TN_act()
            TPLINK_test = DEVICES_TPLINK()
            objects_classes[ip] = {'tn': subswitch_TN_a_test,
                                   'dev': TPLINK_test}
            tn_thread = Thread(name=ip, target=subswitch_TN_a_test.telnet_connect, args=(ip, TPLINK_test.connect_data['port'], TPLINK_test.connect_data['user'], TPLINK_test.connect_data['password']), kwargs={"timeout_tn": 30})
            tn_thread.start()
            threads_tn.append(tn_thread)
        for k in threads_tn:
            k.join()
        for ip, objects in objects_classes.items():
            if 'OK' in (objects['tn']).status_connect:
                if ip == newsw_ip:
                    # real_ip = ip
                    self.actual_table['main_table'][stsw_port_number]['actual_firmware'] = 'Error'

                    self.loger.info("Telnet connect to old ip %s from port %s - OK" %(ip, stsw_port_number))
                    self.loger.error("Error! Firmware update is not successful. Ip %s is old. Port: %s" %(ip, str(stsw_port_number)))
                    return
                else:
                    subswitch_TN_a = objects['tn']
                    TPLINK = objects['dev']
        if subswitch_TN_a == {}:
            self.loger.error("Error connect to ip %s and ip %s from port %s.")
            self.loger.error("Error connect ip %s : %s" %(self.parent_ip, (objects_classes[self.parent_ip]['tn']).status_connect))
            self.loger.error("Error connect ip %s : %s"%(newsw_ip, (objects_classes[newsw_ip]['tn']).status_connect))
            self.actual_table['main_table'][stsw_port_number]['actual_firmware'] = 'Error'
            return



        actual_firmware = ''
        self.loger.info("Try to get actual fw on port %s" %(str(stsw_port_number)))
        actual_firmware = subswitch_TN_a.get_actual_fw()
        if actual_firmware != '':
            actual_firmware = actual_firmware.decode('utf-8')
            actual_firmware = actual_firmware.replace('\r', '')
            actual_firmware = actual_firmware.replace('-', '')
            actual_firmware = actual_firmware.lstrip()
            self.actual_table['main_table'][stsw_port_number]['actual_firmware'] = actual_firmware
            self.actual_table['main_table'][stsw_port_number]['firmware_up'] = 'Ok'
        else:
            self.actual_table['main_table'][stsw_port_number]['actual_firmware'] = actual_firmware
            self.actual_table['main_table'][stsw_port_number]['firmware_up'] = 'Error'


    def check_after_fw_up(self):
        #тут начало таймера в 5 мин
        self.mysignal.emit(self.actual_table)
        staff_dict = {}
        for step_try in range(1, 25):
            self.loger.info("Try get responce about fw up try %s" %(str(step_try)))
            # опрос по snmp кто как прошивается
            check_threads = []
            for stsw_port_number, object_dev in self.fact_devices.items():
                if object_dev == {}:
                    continue
                if object_dev.status_snmp_data['status_fw_up'] != 'Yes':
                    continue
                staff_dict[stsw_port_number] = ''
                model_N = object_dev
                successful_ip = model_N.stend_data['IP']
                fw_up_check_thread = Thread(target=model_N.check_status_fw_up, args=(successful_ip,))
                fw_up_check_thread.start()
                check_threads.append(fw_up_check_thread)

            #дожидаемся окончания всех потоков
            for j in check_threads:
                j.join()

            self.mysignal.emit(self.actual_table)
            #запись в общую таблицу
            for stsw_port_number, object_dev in self.fact_devices.items():
                # staff_dict = {}
                if object_dev == {}:
                    continue
                if object_dev.status_snmp_data['status_fw_up'] != 'Yes':
                    continue
                model_N = object_dev

                try:
                    self.actual_table['main_table'][stsw_port_number]['firmware_up'] = model_N.dev_params_after['status_upd']
                    staff_dict[stsw_port_number] = model_N.dev_params_after['status_upd']
                    self.mysignal.emit(self.actual_table)
                except Exception as ex:
                    self.loger(str(ex))

            self.mysignal.emit(self.actual_table)
            # проверка на предварительный выход
            flag_pre_exit = True
            for port, status in staff_dict.items():
                if status != 'Reboot':
                    flag_pre_exit = False
            if flag_pre_exit:
                break

            self.loger.info("Will be sleep 20sec")
            # self.final.emit()
            time.sleep(20)


        #вы ключение всех портов, включение по обному и опрос о новой прошивке по телнету
        #----------открываем сессию на стендовый коммутатор --------------/////stsw_ip

        self.mysignal.emit(self.actual_table)
        stend_TN_a = TN_act()
        stend_TN_a.telnet_connect(self.stend['ip'], self.stend['port'], self.stend['dialog']['user'], self.stend['dialog']['password'])
        if (stend_TN_a.status_connect == 'null') or ("Error" in stend_TN_a.status_connect):
            self.loger.error('EXIT!! Telnet connect to stend %s - Error' %self.stend['ip'])
            self.statuses_foo['action_at_stend'] = 'Break'
            return
        self.loger.info("Telnet connect stend %s - OK" %self.stend['ip'])

        #---------выключаем порты в сторону тфтп компа и микротика---------
        stend_TN_a.turn_off_all_ports()
        if (stend_TN_a.statuses_foo_telnet.get('turn_off_all_ports', 0) == 0) or (stend_TN_a.statuses_foo_telnet.get('turn_off_all_ports') != 'Ok'):
            self.loger.error("Error! Stend %s is not connected" %(self.stend['ip']))
            self.statuses_foo['action_at_stend'] = 'Break'
            return
        self.loger.info("Stend %s telnet connect - Ok" %(self.stend['ip']))

        #три попытки опросить по телнету новую прошивку
        for step_try in range(1, 10):
            self.mysignal.emit(self.actual_table)

            for stsw_port_number, object_dev in staff_dict.items():

                stend_TN_a.turn_on_port(stsw_port_number)

                self.mysignal.emit(self.actual_table)

                self.get_one_fw_telnet(stsw_port_number)

                self.mysignal.emit(self.actual_table)

                stend_TN_a.turn_off_port(stsw_port_number)

                self.mysignal.emit(self.actual_table)
            flag_pre_exit_telnet = True
            for port, status in staff_dict.items():
                if self.actual_table['main_table'][port]['firmware_up'] != 'Ok':
                    flag_pre_exit_telnet = False
            if flag_pre_exit_telnet:
                break

            time.sleep(15)
        self.mysignal.emit(self.actual_table)

        self.loger.info("Will be try write to bd")
        self.write_to_bd()
        time.sleep(20)
        self.final.emit()
        self.loger.info("Will be end programm")





    def check_ping(self, ip): #не забыть выпилить
        errors = 0
        # time.sleep(4)
        # arp_k = os.system('arp -d 192.168.0.1')
        time.sleep(5)
        response_ping = os.system('ping -n 5 ' + ip)
        if response_ping == 0:
            self.loger.info("Ping pi %s - Ok" %ip)
            errors = 0
        else:
            self.loger.error("Error ping ip %s" %ip)
            errors = 1
        return errors


    def write_to_bd(self):
        status_connect = self.connect_db(flag_close=False)
        if not status_connect:
            self.loger.error("Error connect to db")
            flag_connect = False
        else:
            flag_connect = True

        name_file = "will_be_write_to_bd_" + str(time.strftime("%H_%M_%S__%d_%m_%Y.", time.localtime()))
        flag_write_bd = True
        for stsw_port_number, info_device in (self.actual_table['main_table']).items():
            if (info_device['firmware_up'] != 'Ok'):
                continue
            model = info_device['model']
            fw_version = info_device['actual_firmware']
            serial_num = info_device['serial_number']
            mac_addr = info_device['MAC']

            if flag_connect:
                try:
                    request = "INSERT INTO eqm.sw_fw_upd_res (model, fw_version, serial_num, mac_addr) VALUES ('%s', '%s', '%s', '%s')" %(model, fw_version, serial_num,mac_addr)
                    self.loger.info("Try to write bd. Request: %s" %request)
                    self.db_cursor.execute(request)
                    self.db_connect.commit()
                    self.loger.info("Write to bd - OK. Request %s" %(request))
                    self.actual_table['main_table'][stsw_port_number]['write_bd'] = 'Ok'
                except Exception as ex:
                    self.actual_table['main_table'][stsw_port_number]['write_bd'] = 'Error'
                    self.loger.error("Error write to bd. Error: %s" %(ex))
                    flag_write_bd = False
                self.mysignal.emit(self.actual_table)
            elif (flag_connect == False) or (flag_write_bd == False):
                with open (name_file, 'a') as loc_file:
                    loc_file.write(model + '    ' + fw_version + '    ' + serial_num + '    ' + mac_addr + '\n')



        self.db_connect.close()



        # model text NULL,
        # fw_version text NULL,
        # serial_num text NULL,
        # mac_addr text NULL
        #в бд, пятый не заполнять, там таймстамп





if __name__ == "__main__":
    process_fw_up = BOLVANIZATOR()
    process_fw_up.run_action()
    process_fw_up.obolvanit()
    process_fw_up.check_after_fw_up()

