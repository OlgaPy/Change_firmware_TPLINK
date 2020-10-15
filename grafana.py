#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-
__author__ = 'PykhovaOlga'

import psycopg2
import autentification as AUTH

class Grafana:
    def __init__(self):
        """
        A class for easy connection to the graphana database through the context manager.
        :return: None
        """
        self.database, self.user, self.password, self.host, self.port = AUTH.get_grafana_params()

    def __enter__(self) -> psycopg2.connect:
        """
        Establishes a connection to the Grafana database. Returns the db_connect

        :return: self.db_connect: psycopg2.connect
        """
        self.db_connect = psycopg2.connect(
            database=self.database,
            user=self.user,
            password=self.password,
            host=self.host,
            port=self.port
        )
        return self.db_connect

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Closes the connection to the graphana database.

        :return: None
        :raises: Exception
        """
        self.db_connect.close()
        if exc_val:
            raise Exception(exc_val)
