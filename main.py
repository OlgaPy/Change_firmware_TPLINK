#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'

import librouteros
from typing import Tuple, List, Optional
from PyQt5.QtCore import pyqtSignal, QObject
from Devices import *
import app_logger
import os
import time
import psutil
from threading import Thread
from TN_action import TN_act as TN_act
import autentification as AUTH
from grafana import Grafana


class CHANGER_FW(QObject):
    """
    Basic class to manage the firmware change process on the switches connected to the TP-LINK 2600/2700 assembled
    stand.
    Inherited from QObject
    """
    S_SIG = pyqtSignal(dict)
    BUTTON_SIG = pyqtSignal()
    AFTER_S_SIG = pyqtSignal()
    FINAL_SIG = pyqtSignal()

    def __init__(self) -> None:
        """
        Sets the basic parameters for the stand and microtic. Sets the actual_table_devices structure
        :return: None
        """
        super().__init__()
        self.logger = app_logger.get_logger("Main")
        self.stsw_ip = AUTH.get_stsw_ip()
        self.stmik_ip = AUTH.get_stmik_ip()
        self.base_ip = '192.168.0.1'
        self.tftp_server = AUTH.get_tftp_server_ip()
        self.stand_params = {'ip': self.stsw_ip,
                             'port': 23,
                             'range_stsw_port': [1, 28],
                             'user': AUTH.get_stend_login(),
                             'password': AUTH.get_stend_pass(),
                             'part_answer': 'T2600G-28TS-DC',
                             }

        self.mikrotik_params = {'ip': self.stmik_ip,
                                'port': 23,
                                'user': AUTH.get_mik_login(),
                                'password': AUTH.get_mik_pass(),
                                'part_answer': '[admin@MikroTik] >',

                                }
        self.relevant_devices = {}
        self.relevant_port = []

        self.statuses_foo = {}
        self.actual_table_devices = {'general': {'MIKROTIK': False,
                                                 'SWITCH': False,
                                                 'TFTP_SERVER': False,
                                                 'BD': False},
                                     'main_table': {}
                                     }

    def prepare_upgrade(self) -> None:
        """
        Multithreading.
        Prepares the switches connected to the bench for firmware upgrade. Calls function to change ip switches,
        fills actual_table_devices.
        Defines the relevant_devices that contain the "serviceable" switches
        :return: None
        """
        flag_exit = self.test_systems()
        if flag_exit:
            self.logger.error("Test systems was failed")
            return

        # смена IP
        self.preparing_switches_bw_stand()  # запись в actual_table_devices внутри, объекты в self.relevant_devices
        self.S_SIG.emit(self.actual_table_devices)

        threads = []

        for stsw_port, inst_device in (self.relevant_devices).items():
            self.S_SIG.emit(self.actual_table_devices)
            if inst_device == {}:
                continue
            model_n = inst_device
            ip = model_n.stend_data.get('IP')
            model_n.set_mikr_ip(self.stmik_ip)
            name = f"Thread for port #{stsw_port}"
            if ip != 0 and ip != '':
                snmp_thread = Thread(name=name, target=model_n.check_snmp_param)
                snmp_thread.start()
                threads.append(snmp_thread)

        for j in threads:
            j.join()
        self.S_SIG.emit(self.actual_table_devices)

        for port, inst_device in (self.relevant_devices).items():
            if inst_device == {}:
                continue
            model_n = inst_device
            try:
                self.actual_table_devices['main_table'][port]['snmp_params'] = model_n.statuses_foo_devices[
                    'get_param_snmp']
                self.actual_table_devices['main_table'][port]['model'] = model_n.dev_params_behind['model']
                self.actual_table_devices['main_table'][port]['serial_number'] = model_n.dev_params_behind[
                    'newsw_serial']
                self.actual_table_devices['main_table'][port]['MAC'] = model_n.dev_params_behind['newsw_mac']
                self.actual_table_devices['main_table'][port]['actual_firmware'] = model_n.dev_params_behind[
                    'vendor_firmware']
                self.actual_table_devices['main_table'][port]['status_fw_up'] = model_n.status_snmp_data['status_fw_up']
            except Exception as ex:
                self.logger.error(f"Error from add param snmp to table on port {port}. Error: {ex}")
        self.S_SIG.emit(self.actual_table_devices)

        self.BUTTON_SIG.emit()  # разблокировать кнопку в gui

    def test_systems(self) -> bool:
        """
        It checks the availability of the stand, that tftpd32.exe is running,
        the existence of firmware on the server, the connection to the mikrotik and the availability of the database.
        Returns a sign that determines whether the application will continue to work or not.
        :return: flag_exit : bool
        """
        flag_exit = False
        stend_tn_a = TN_act()
        stend_tn_a.telnet_connect(self.stand_params.get('ip'), self.stand_params.get('port'),
                                  self.stand_params.get('user'),
                                  self.stand_params.get('password'))
        if (stend_tn_a.status_connect == 'null') or ("Error" in stend_tn_a.status_connect):
            self.logger.error(f'EXIT!! Telnet connect to stand {self.stand_params.get("ip")} - Error')
            flag_exit = True
        else:
            self.actual_table_devices['general']['SWITCH'] = True
            self.logger.info(f"Telnet connect stend {self.stand_params.get('ip')} - OK")
        self.S_SIG.emit(self.actual_table_devices)

        inst_tp_2700 = TP_LINK_T2700G_28TQ_2_20()
        inst_tp_2600 = TP_LINK_T2600G_28TS_DC_1_0()

        # ---------проверяем что файл на сервере C:\tftp conf_standart для моделей sp_model существует-------
        flag_cfg = False
        path_1 = f"C:\\tftp\\{inst_tp_2700.base_data.get('conf_standart')}"
        # path_2 = 'C:\\tftp\\' + (test_model_2.base_data['conf_standart'])

        try:
            check_file = open(path_1)
            check_file.close()
            self.logger.info(f"{inst_tp_2700.base_data.get('conf_standart')} on tftp - OK")
            flag_cfg = True
        except Exception as ex:
            self.logger.error(f"EXIT!! ERROR ON FILE WITH FIRMWARE {ex}")
            flag_exit = True
        self.S_SIG.emit(self.actual_table_devices)

        # --------проверить что тфтп сервер запущен----------------------
        flag_tftp = False
        for process in psutil.process_iter():
            if "tftpd32.exe" in (process.name()):
                flag_tftp = True
        if not flag_tftp:
            self.logger.error("EXIT!! tftpd32.exe IS NOT RUNNING")
            flag_exit = True

        if flag_cfg and flag_tftp:
            self.actual_table_devices['general']['TFTP_SERVER'] = True
            self.logger.info("tftpd32.exe is running - OK")
            self.S_SIG.emit(self.actual_table_devices)

        # Проверка соединения с микротиком
        try:
            mik_client = librouteros.connect(self.mikrotik.get('ip'), self.mikrotik.get('user'),
                                             self.mikrotik.get('password'))
            if mik_client is not None:
                self.actual_table['general']['MIKROTIK'] = True
        except Exception as ex:
            self.loger.error(f"Error on connect to mikrotik {ex}")
        self.mysignal.emit(self.actual_table)

        # Проверка доступности БД
        if self.connect_db():
            self.actual_table_devices['general']['BD'] = True
            self.logger.info("Connect to DB - OK")
        else:
            self.logger.error("EXIT!! Not connect to BD")
            # flag_exit = True
        self.S_SIG.emit(self.actual_table_devices)

        return flag_exit

    def preparing_switches_bw_stand(self) -> None:
        """
        Opens the session to the booth. Turns off ports towards tftp and mikrotik.
        Changes ip of each available switch. Then closes the connection to the stand. Updates actual_table_devices.
        :return: None
        """
        # ----------открываем сессию на стендовый коммутатор --------------/////stsw_ip
        stend_tn_a = TN_act()
        stend_tn_a.telnet_connect(self.stand_params.get('ip'), self.stand_params.get('port'),
                                  self.stand_params.get('user'), self.stand_params.get('password'))

        if stend_tn_a.status_connect.lower() != 'ok':
            self.logger.error(f'EXIT!! Telnet connect to stand {self.stand_params["ip"]}- Error')
            return
        self.logger.info(f"Telnet connect stend {self.stand_params['ip']} - OK")

        # ---------выключаем порты в сторону тфтп компа и микротика---------
        stend_tn_a.turn_off_all_ports()
        if stend_tn_a.statuses_foo_telnet.get('turn_off_all_ports', '').lower() != 'ok':
            self.logger.error(f"Error! Stand {self.stand_params['ip']} is not connected")
            return
        self.logger.info(f"Stand {self.stand_params['ip']} telnet connect - Ok")
        self.S_SIG.emit(self.actual_table_devices)

        # ---------смена айпишников на всех свичах----------------------
        for port_i in range(self.stand_params['range_stsw_port'][0], self.stand_params['range_stsw_port'][1]):
            port = str(port_i)
            self.S_SIG.emit(self.actual_table_devices)
            self.actual_table_devices['main_table'][port] = {'port': port,
                                                             'status_port': 'Down',
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
            self.relevant_devices[port] = {}
            clear_arp_stand = f'arp -d {self.base_ip}'
            clear_arp_switch = f'arp -d 192.168.0.{100 + int(port)}'
            arp_k_stand = os.system(clear_arp_stand)
            arp_k_switch = os.system(clear_arp_switch)
            self.logger.info(f"Clear arp stand {arp_k_stand}. Clear arp switch {arp_k_switch}")
            stend_tn_a.turn_on_port(port)
            name_foo = f"turn_on_port_{port}"
            if stend_tn_a.statuses_foo_telnet.get(name_foo, '').lower() != 'ok':
                self.logger.error(f"Error port {port} turn on")
                continue
            self.logger.info(f"Port {port} turn on - Ok" )
            self.actual_table_devices['main_table'][port]['status_port'] = 'Up'

            name_foo_ch_ip = f'change_ip_at_stand_port_{port}'

            self.change_ip_at_stand(port)
            # IP, ping в actual_table внутри

            if self.statuses_foo[name_foo_ch_ip] == 'Ok':
                self.relevant_port.append(port)
            else:
                self.actual_table_devices['main_table'][port]['ping'] = 'Error'
                stend_tn_a.turn_off_port(port)
                name_foo = f"turn_off_port_{port}"
                if stend_tn_a.statuses_foo_telnet.get(name_foo, '').lower() != 'ok':
                    self.logger.error(f"Error port {port} turn off")
                self.actual_table_devices['main_table'][port]['status_port'] = 'Down'
                continue
            self.S_SIG.emit(self.actual_table_devices)
        self.S_SIG.emit(self.actual_table_devices)

        # ---------все свитчи модели настроены на временные айпи---------
        stend_tn_a.telnet_close()
        self.logger.info("Close telnet connect to stand - Ok")

    def change_ip_at_stand(self, port: int, parrent_part_ip='192.168.0.') -> None:
        """
        Multithreading.
        Changes the ip on each switch from the standard ip to 192.168.0.(100 + the port number behind the switch)
        After changing ip in several threads it telnet to each switch and looks at its response in cli.
        Depending on the response creates a set of class objects.
        Updates actual_table_devices.

        :param port: int
        :param parrent_part_ip: str
        :return:
        """
        name_foo = f'change_ip_at_stand_port_{port}'
        self.statuses_foo[name_foo] = 'Start'
        newsw_ip = f"{parrent_part_ip}{100 + port}"
        # может  ивм обычный коммут, а может со смененным ip и его надо только в fact_devices добавить определив модель

        subswitch_TN_a = {}
        TPLINK = {}
        instances_devices = {}
        actual_ip = ''
        threads_tn = []
        for ip in self.base_ip, newsw_ip:
            subswitch_TN_a_test = TN_act()
            TPLINK_test = DEVICES_TPLINK()
            instances_devices[ip] = {'tn': subswitch_TN_a_test,
                                     'dev': TPLINK_test}
            tn_thread = Thread(name=ip, target=subswitch_TN_a_test.telnet_connect, args=(
                ip, TPLINK_test.connect_data['port'], TPLINK_test.connect_data['user'],
                TPLINK_test.connect_data['password']), kwargs={"timeout_tn": 30})
            tn_thread.start()
            threads_tn.append(tn_thread)

        for k in threads_tn:
            k.join()
        self.S_SIG.emit(self.actual_table_devices)
        for ip, inst_dev in instances_devices.items():
            if 'OK' in (inst_dev['tn']).status_connect:
                actual_ip = ip
                subswitch_TN_a = inst_dev['tn']
                TPLINK = inst_dev['dev']
                self.logger.info(f"Telnet connect to ip {ip} from port {port} - OK")
        if subswitch_TN_a == {}:
            self.logger.error(f"Error connect to ip {ip} from port {port}.")
            self.logger.error(
                f"Error connect ip self.base_ip : {(instances_devices[self.base_ip]['tn']).status_connect}")
            self.logger.error(f"Error connect ip newsw_ip : {(instances_devices[newsw_ip]['tn']).status_connect}")
            self.statuses_foo[name_foo] = 'Error'
            self.actual_table_devices['main_table'][port]['ping'] = 'Error'
            self.S_SIG.emit(self.actual_table_devices)
            return

        self.actual_table_devices['main_table'][port]['ping'] = 'Ok'
        self.logger.info(f"Telnet connect to ip {ip} from port {port} - OK")

        if b'T2700G-28TQ' in subswitch_TN_a.real_response_b:
            model_inst = TP_LINK_T2700G_28TQ_2_20()
        elif b'T2600G-28TS-DC' in subswitch_TN_a.real_response_b:
            model_inst = TP_LINK_T2600G_28TS_DC_1_0()
        else:
            self.logger.error(f"Unknown model {subswitch_TN_a.real_response_b}")
            self.actual_table_devices['main_table'][port]['model'] = 'Unknown model'
            self.statuses_foo[name_foo] = 'Break'
            self.S_SIG.emit(self.actual_table_devices)
            return

        self.relevant_devices[port] = model_inst

        if actual_ip == newsw_ip:
            self.statuses_foo[name_foo] = 'Ok'
            model_inst.stend_data['IP'] = ip
            model_inst.stend_data['port'] = port
            self.statuses_foo['name_foo'] = 'Ok'
            self.actual_table_devices['main_table'].setdefault(port, {})['IP_switch'] = actual_ip
            self.actual_table_devices['main_table'].setdefault(port, {})['ping'] = '_Ok'
            self.S_SIG.emit(self.actual_table_devices)
            return

        subswitch_TN_a.change_one_ip(newsw_ip)
        name_foo_ip = f"change_one_ip_{newsw_ip}"

        if subswitch_TN_a.statuses_foo_telnet.get(name_foo_ip, '').lower() != 'ok':
            self.logger.error(f"Error change ip {newsw_ip}")
            self.statuses_foo[name_foo_ip] = 'Error'
            self.S_SIG.emit(self.actual_table_devices)
            return
        self.statuses_foo[name_foo_ip] = 'Ok'
        self.logger.info(f"Change ip {newsw_ip} on port {port} - Ok")
        self.actual_table_devices['main_table'].setdefault(port, {})['IP_switch'] = newsw_ip

        model_inst.stend_data['IP'] = newsw_ip
        model_inst.stend_data['port'] = port
        self.statuses_foo[name_foo] = 'Ok'
        self.S_SIG.emit(self.actual_table_devices)

    def set_ip(self, ip: str) -> None:
        """
        Writes the new ip into a variable of the class instance.
        :param ip: str
        :return: None
        """
        self.stsw_ip = ip

    def set_range_ports(self, first_port: str, end_port: str) -> None:
        """
        Writes the start and end port of the gui form to a variable of the class instance.
        :param first_port: str
        :param end_port: str
        :return: None
        """
        self.stand_params['range_stsw_port'].clear()
        self.stand_params['range_stsw_port'].append(int(first_port))
        self.stand_params['range_stsw_port'].append(int(end_port) + 1)

    def upgrade_up(self) -> None:
        """
        Multithreading.
        Checks that the class instance has OK in status_snmp_data, status_model, status_fw.
        In this case, multithreaded starts the firmware upgrade process by snmp.
        :return: None
        """
        # шить только если у object_dev  в status_snmp_data в status_model и status_fw стоит OK!!

        threads = []
        self.S_SIG.emit(self.actual_table_devices)
        for port, inst_dev in self.relevant_devices.items():
            if not inst_dev:
                continue
            if inst_dev.status_snmp_data['status_fw_up'] != 'Yes':
                continue
            model_inst = inst_dev
            successful_ip = model_inst.stend_data['IP']
            fw_up_thread = Thread(target=model_inst.fw_update, args=(self.tftp_server, port))
            fw_up_thread.start()
            threads.append(fw_up_thread)

        for thread in threads:
            thread.join()
        self.S_SIG.emit(self.actual_table_devices)

        for port, inst_dev in self.relevant_devices.items():
            if not inst_dev:
                continue
            if inst_dev.dev_params_after == '':
                continue
            model_inst = inst_dev
            self.actual_table_devices['main_table'].setdefault(port, {})['cfg_up'] = (model_inst.dev_params_after).get(
                'cfg')
            self.S_SIG.emit(self.actual_table_devices)

        self.AFTER_S_SIG.emit()

    def connect_db(self) -> bool:
        """
        Checks if it is possible to connect to the database.

        :return: bool
        """
        status = False
        try:
            with Grafana() as conn:
                grafana_cursor = conn.cursor()
                status = True
        except Exception as ex:
            self.logger.error(f"Error connect to db, {ex}")
        return status

    def get_one_fw_telnet(self, port: int, parrent_ip='192.168.0.1') -> None:
        """
        For one switch, while checking the status of the firmware process, connects via telnet and asks for
        the firmware version
        :param port: int
        :param parrent_ip: str
        :return:
        """
        self.logger.info(f"Try telnet connect to port {port}")
        tn_subswitch = {}
        TPLINK = {}
        instances_devices = {}
        newsw_ip = f'192.168.0.{100 + int(port)}'
        real_ip = ''
        threads_tn = []
        for ip in self.base_ip, newsw_ip:
            tn_b_subswitch = TN_act()
            TPLINK_b = DEVICES_TPLINK()
            instances_devices[ip] = {'tn': tn_b_subswitch,
                                     'dev': TPLINK_b}
            tn_thread = Thread(name=ip, target=tn_b_subswitch.telnet_connect, args=(
                ip, TPLINK_b.connect_data['port'], TPLINK_b.connect_data['user'],
                TPLINK_b.connect_data['password']), kwargs={"timeout_tn": 30})
            tn_thread.start()
            threads_tn.append(tn_thread)

        for thread in threads_tn:
            thread.join()

        for ip, inst_dev in instances_devices.items():
            if 'OK' in (inst_dev['tn']).status_connect:
                if ip == newsw_ip:
                    self.actual_table_devices['main_table'].setdefault(port, {})['actual_firmware'] = 'Error'
                    self.logger.info(f"Telnet connect to old ip {ip} from port {port} - OK")
                    self.logger.error(f"Error! Firmware update is not successful. Ip {ip} is old. Port: {port}")
                    return
                else:
                    tn_subswitch = inst_dev['tn']
                    TPLINK = inst_dev['dev']
        if tn_subswitch == {}:
            self.logger.error(f"Error connect to ip{ip} from port {port}.")
            self.logger.error(f"Error connect ip {self.base_ip}: "
                              f"{(instances_devices[self.base_ip]['tn']).status_connect}")
            self.logger.error(f"Error connect ip {newsw_ip} : {(instances_devices[newsw_ip]['tn']).status_connect}")
            self.actual_table_devices['main_table'][port]['actual_firmware'] = 'Error'
            return

        self.logger.info(f"Try to get actual fw on port {port}")
        actual_firmware = tn_subswitch.get_actual_fw()
        if actual_firmware != '':
            actual_firmware = actual_firmware.decode('utf-8')
            actual_firmware = actual_firmware.replace('\r', '')
            actual_firmware = actual_firmware.replace('-', '')
            actual_firmware = actual_firmware.lstrip()
            self.actual_table_devices['main_table'][port]['actual_firmware'] = actual_firmware
            self.actual_table_devices['main_table'][port]['firmware_up'] = 'Ok'
        else:
            self.actual_table_devices['main_table'][port]['actual_firmware'] = actual_firmware
            self.actual_table_devices['main_table'][port]['firmware_up'] = 'Error'

    def check_after_fw_up(self) -> None:
        """
        Checks switches after starting the firmware upgrade process. Polls the switches 25 times at 5 minute
        intervals via snmp.
        When responses are received from all switches or the number of attempts is over, shuts down all ports.
        And, one by one, it polls the firmware version via telnet. Three times with a pause of 15 seconds.

        :return: None
        """
        # тут начало таймера в 5 мин
        self.S_SIG.emit(self.actual_table_devices)
        statuses_dev_fw_up = {}
        for step_try in range(1, 25):
            self.logger.info(f"Try get response about fw up try {step_try}")
            # опрос по snmp кто как прошивается
            check_threads = []
            for stsw_port_number, inst_dev in self.relevant_devices.items():
                if not inst_dev:
                    continue
                if inst_dev.status_snmp_data['status_fw_up'] != 'Yes':
                    continue
                statuses_dev_fw_up[stsw_port_number] = ''
                model_inst = inst_dev
                successful_ip = model_inst.stend_data['IP']
                fw_up_check_thread = Thread(target=model_inst.check_status_fw_up, args=(successful_ip,))
                fw_up_check_thread.start()
                check_threads.append(fw_up_check_thread)

            # дожидаемся окончания всех потоков
            for thread in check_threads:
                thread.join()

            self.S_SIG.emit(self.actual_table_devices)
            # запись в общую таблицу
            for stsw_port_number, inst_dev in self.relevant_devices.items():
                if not inst_dev:
                    continue
                if inst_dev.status_snmp_data['status_fw_up'] != 'Yes':
                    continue
                model_inst = inst_dev

                try:
                    self.actual_table_devices['main_table'][stsw_port_number]['firmware_up'] = \
                        model_inst.dev_params_after['status_upd']
                    statuses_dev_fw_up[stsw_port_number] = model_inst.dev_params_after['status_upd']
                    self.S_SIG.emit(self.actual_table_devices)
                except Exception as ex:
                    self.logger(str(ex))

            self.S_SIG.emit(self.actual_table_devices)
            # проверка на предварительный выход
            flag_pre_exit = True
            for port, status in statuses_dev_fw_up.items():
                if status != 'Reboot':
                    flag_pre_exit = False
            if flag_pre_exit:
                break

            self.logger.info("Will be sleep 20sec")
            # self.final.emit()
            time.sleep(20)

        # выключение всех портов, включение по обному и опрос о новой прошивке по телнету
        # ----------открываем сессию на стендовый коммутатор --------------/////stsw_ip

        self.S_SIG.emit(self.actual_table_devices)
        stend_tn_a = TN_act()
        stend_tn_a.telnet_connect(self.stand_params['ip'], self.stand_params['port'],
                                  self.stand_params['user'],
                                  self.stand_params['password'])
        if (stend_tn_a.status_connect == 'null') or ("Error" in stend_tn_a.status_connect):
            self.logger.error(f'EXIT!! Telnet connect to stend {self.stand_params["ip"]} - Error')
            self.statuses_foo['action_at_stend'] = 'Break'
            return
        self.logger.info(f"Telnet connect stend {self.stand_params['ip']} - OK")

        # ---------выключаем порты в сторону тфтп компа и микротика---------
        stend_tn_a.turn_off_all_ports()
        if stend_tn_a.statuses_foo_telnet.get('turn_off_all_ports', '').lower() != 'ok':
            self.logger.error(f"Error! Stend {self.stand_params['ip']} is not connected")
            self.statuses_foo['action_at_stend'] = 'Break'
            return
        self.logger.info(f"Stand {self.stand_params['ip']} telnet connect - Ok")

        # три попытки опросить по телнету новую прошивку
        for step_try in range(1, 10):
            self.S_SIG.emit(self.actual_table_devices)

            for stsw_port_number, inst_dev in statuses_dev_fw_up.items():
                stend_tn_a.turn_on_port(stsw_port_number)

                self.S_SIG.emit(self.actual_table_devices)

                self.get_one_fw_telnet(stsw_port_number)

                self.S_SIG.emit(self.actual_table_devices)

                stend_tn_a.turn_off_port(stsw_port_number)

                self.S_SIG.emit(self.actual_table_devices)
            flag_pre_exit_telnet = True
            for port, status in statuses_dev_fw_up.items():
                if self.actual_table_devices['main_table'][port]['firmware_up'] != 'Ok':
                    flag_pre_exit_telnet = False
            if flag_pre_exit_telnet:
                break

            time.sleep(15)
        self.S_SIG.emit(self.actual_table_devices)

        self.logger.info("Will be try write to bd")
        self.write_to_bd()
        time.sleep(20)
        self.FINAL_SIG.emit()
        self.logger.info("Will be end")

    def check_ping(self, ip: str) -> int:
        """
        Ping with five packets on the transmitted ip
        :param ip: str
        :return: count_error: int
        """
        time.sleep(5)
        response_ping = os.system(f'ping -n 5 {ip}')
        if response_ping == 0:
            self.logger.info(f"Ping ip {ip} - Ok")
            return 0

        self.logger.error(f"Error ping ip {ip}")
        return 1

    def write_to_bd(self) -> None:
        """
        Writes the data about the switches that were successfully/unsuccessfully flashed into the database
        :return: None
        """
        try:
            with Grafana() as conn:
                grafana_cursor = conn.cursor()
                for stsw_port_number, info_device in (self.actual_table_devices['main_table']).items():
                    if (info_device['firmware_up'] != 'Ok'):
                        continue
                    model = info_device['model']
                    fw_version = info_device['actual_firmware']
                    serial_num = info_device['serial_number']
                    mac_addr = info_device['MAC']
                    request = f"INSERT INTO eqm.sw_fw_upd_res (model, fw_version, serial_num, mac_addr) " \
                              f"VALUES ('{model}', '{fw_version}', '{serial_num}', '{mac_addr}')"

                    self.logger.info(f"Try to write bd. Request: {request}")
                    self.db_cursor.execute(request)
                    self.db_connect.commit()
                    self.logger.info(f"Write to bd - OK. Request {request}")
                    self.actual_table_devices['main_table'][stsw_port_number]['write_bd'] = 'Ok'

        except Exception as ex:
            self.logger.error(f"Error connect to db. {ex}")
            name_file = f'will_be_write_to_bd_{time.strftime("%H_%M_%S__%d_%m_%Y.", time.localtime())}'
            with open(name_file, 'a') as loc_file:
                for stsw_port_number, info_device in (self.actual_table_devices['main_table']).items():
                    if (info_device['firmware_up'] != 'Ok'):
                        continue
                    loc_file.write(f"{info_device['model']}    {info_device['actual_firmware']}    "
                                   f"{info_device['serial_number']}    {info_device['MAC']}\n")

        # model text NULL,
        # fw_version text NULL,
        # serial_num text NULL,
        # mac_addr text NULL
        # в бд, пятый не заполнять, там таймстамп


if __name__ == "__main__":
    process_fw_up = CHANGER_FW()
    process_fw_up.prepare_upgrade()
    process_fw_up.upgrade_up()
    process_fw_up.check_after_fw_up()
