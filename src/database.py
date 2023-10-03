#!/usr/bin/python3

"""
Developper of the former "PraxisBot" used as based for this bot
Copyright (C) 2018 MonaIzquierda (mona.izquierda@gmail.com)

Developper of "YetAnotherFork" and "Manager Sylvie 2.0"
Copyright (C) 2022-2023 Powi (powi@powi.fr)

This file is part of Manager Sylvie 2.0.
Manager Sylvie 2.0 is a rework of YetAnotherFork which is a fork of PraxisBot

Manager Sylvie 2.0 is free software: you can redistribute it and/or  modify
it under the terms of the GNU Affero General Public License, version 3,
as published by the Free Software Foundation.

Manager Sylvie 2.0 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with Manager Sylvie 2.0.  If not, see <http://www.gnu.org/licenses/>.
"""
import mysql.connector as sql
from mysql.connector import errorcode
import os
import utils
import sqlite3

MYSQL = 0
SQLITE3 = 1

################
#   Database   #
################


class Database():

    def databasetable(self, name): return self.databaseprefix + name

    def execute_and_commit(self, request):
        self.databasecursor.execute(request)
        self.databasecon.commit()

    def execute(self, request):
        return self.databasecursor.execute(request)

    def __init__(self, dev_mode):

        self.databaseprefix = "ms2_"

        if not dev_mode:
            database_user = os.environ.get('SQL_USER')
            database_passwd = os.environ.get('SQL_PASSWD')
            database_database = os.environ.get('SQL_DATABASE')

            self.databasecon = sql.connect()
            self.databasetype = MYSQL

        else:
            database_file = 'database/dev.database'
            if not os.path.exists(database_file):
                database_dirs, database_filename = database_file.rsplit('/', 1)
                os.makedirs(database_dirs)
            self.databasecon = sqlite3.connect(
                database_file, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.databasetype = SQLITE3

        self.databasecursor = self.databasecon.cursor()
        self.databasecursor.execute(
            f"CREATE TABLE IF NOT EXISTS {self.databaseprefix}guilds(gid INTEGER PRIMARY KEY, command_prefix TEXT)")

    def create_sql_table(self, name, fields):
        database = self.databasetable(name)
        joined_fields = ", ".join(fields)
        sqlQuery = f"CREATE TABLE IF NOT EXISTS {database} ({joined_fields})"
        self.execute(sqlQuery)

        for field in fields:
            sqlQuery = f"ALTER TABLE {database} ADD {field}"

    def get_sql_data(self, name, fields, where=None, array=False):
        database = self.databasetable(name)
        joined_fields = ", ".join(fields)
        sqlQuery = f"SELECT {joined_fields} FROM {database}"
        if where:
            split_where = list(
                f"{key}={value}" for key,
                value in where.items())
            joined_where = " AND ".join(split_where)
            sqlQuery += f" WHERE {joined_where}"
        datas = self.execute(sqlQuery)
        response = datas.fetchall() if array else datas.fetchone()
        return response

    def set_sql_data(self, name, fields, where, id="id"):
        database = self.databasetable(name)
        found_id = self.get_sql_data(name, [id], where)
        if found_id:
            split_fields = list(
                f"{key}={value}" for key,
                value in fields.items())
            joined_fields = ",".join(split_fields)
            sqlQuery = f"UPDATE {database} SET {joined_fields} WHERE {id}={found_id}"
        else:
            fields.update(where)
            joined_keys = ",".join(fields.keys())
            joined_values = ",".join(fields.values())
            sqlQuery = f"INSERT INTO {database} ({joined_keys}) VALUES ({joined_values})"
        self.execute_and_commit(sqlQuery)

    def add_sql_data(self, name, fields):
        database = self.databasetable(name)
        joined_keys = ",".join(fields.keys())
        joined_values = ",".join(fields.values())
        sqlQuery = f"INSERT INTO {database} ({joined_keys}) VALUES ({joined_values})"
        self.execute_and_commit(sqlQuery)
        return self.databasecursor.lastrowid

    def delete_sql_data(self, name, where):
        database = self.databasetable(name)
        split_where = list(f"{key}={value}" for key, value in where.items())
        joined_where = " AND ".join(split_where)
        sqlQuery = f"DELETE FROM {database} WHERE {joined_where}"
        self.execute_and_commit(sqlQuery)
