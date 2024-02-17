#!/usr/bin/python3
"""
Main file of Manager Sylvie 2.0, a discord all-in-one bot.

Manager Sylvie 2.0 is a rework of YetAnotherFork
YetAnotherFork is a fork of PraxisBot,
PraxisBot was developped by MonaIzquierda.
Manager Sylvie 2.0 is a bot developped by Powi,
Manager Sylvie 2.0 is intended to be an all-in-one bot for Discord.

Developper of the former "Sylvie" used as based for this bot
Copyright (C) 2018 MonaIzquierda (mona.izquierda@gmail.com).
Developper of "YetAnotherFork" and "Manager Sylvie 2.0" (this bot)
Copyright (C) 2022-2023 Powi (powi@powi.fr).

This file is part of Manager Sylvie 2.0.

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

# standard library
import os
import sqlite3

# third-party library
import pymysql as sql

MYSQL = 0
SQLITE3 = 1

################
#   Database   #
################

# TODO: Add a way to use the database without the bot, for example in a web interface.

CREATE = "CREATE TABLE IF NOT EXISTS"


class Database():
    """Database class, used to interact with the database."""

    def databasetable(self, name):
        """Return the name of the table with the prefix."""
        return self.databaseprefix + name

    def execute_and_commit(self, request):
        """
        Execute a request and commit it to the database.

        Args:
            request (str): The request to execute (SQL).
        """
        self.databasecursor.execute(request)
        self.databasecon.commit()

    def execute(self, request):
        """Execute a request to the database."""
        return self.databasecursor.execute(request)

    def __init__(self, dev_mode):
        """
        Initialize the database.

        Initialize the database, and create the guild tables if they don't exist.
        Set to sqlite3 if in development mode, else runs mysql.

        Args:
            dev_mode (bool): If the bot is in development mode or not.
        """

        self.databaseprefix = "ms2_"

        if not dev_mode:
            database_user = os.environ.get('SQL_USER')
            database_passwd = os.environ.get('SQL_PASSWD')
            database_database = os.environ.get('SQL_DATABASE')

            self.databasecon = sql.connections.Connection(
                user=database_user,
                password=database_passwd,
                database=database_database)
            self.databasetype = MYSQL

        else:
            database_file = 'database/dev.database'
            if not os.path.exists(database_file):
                database_dirs = database_file.rsplit('/', 1)[0]
                try:
                    os.makedirs(database_dirs)
                except FileExistsError:
                    pass
            self.databasecon = sqlite3.connect(
                database_file, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
            self.databasetype = SQLITE3

        self.databasecursor = self.databasecon.cursor()
        self.databasecursor.execute(
            f"{CREATE} {self.databaseprefix}guilds(gid INTEGER PRIMARY KEY, command_prefix TEXT)")

    def create_sql_table(self, name, fields):
        """
        Create a table in the database.

        Args:
            name (str): The name of the table.
            fields (list): The fields of the table.
        """
        database = self.databasetable(name)
        joined_fields = ", ".join(fields)
        sql_query = f"{CREATE} {database} ({joined_fields})"
        self.execute(sql_query)

        for field in fields:
            sql_query = f"ALTER TABLE {database} ADD {field}"

    def get_sql_data(self, name, fields, where=None, array=False):
        """
        Get data from the database.

        Args:
            name (str): The name of the table.
            fields (list): The fields to get.
            where (dict): The where clause.
            array (bool): If the response should be an array or not.
        """
        database = self.databasetable(name)
        joined_fields = ", ".join(fields)
        sql_query = f"SELECT {joined_fields} FROM {database}"
        if where:
            split_where = list(
                f"{key}={value}" for key,
                value in where.items())
            joined_where = " AND ".join(split_where)
            sql_query += f" WHERE {joined_where}"
        datas = self.execute(sql_query)
        response = datas.fetchall() if array else datas.fetchone()
        return response

    def set_sql_data(self, name, fields, where, b_id="id"):
        """
        Set data in the database.

        Args:
            name (str): The name of the table.
            fields (dict): The fields to set.
            where (dict): The where clause.
            b_id (str): The id of the table. Defaults to "id".
        """
        database = self.databasetable(name)
        found_id = self.get_sql_data(name, [b_id], where)
        if found_id:
            split_fields = list(
                f"{key}={value}" for key,
                value in fields.items())
            joined_fields = ",".join(split_fields)
            sql_query = f"UPDATE {database} SET {joined_fields} WHERE {b_id}={found_id}"
        else:
            fields.update(where)
            joined_keys = ",".join(fields.keys())
            joined_values = ",".join(fields.values())
            sql_query = f"INSERT INTO {database} ({joined_keys}) VALUES ({joined_values})"
        self.execute_and_commit(sql_query)

    def add_sql_data(self, name, fields):
        """
        Add data to the database.

        Args:
            name (str): The name of the table.
            fields (dict): The fields to add.
        """
        database = self.databasetable(name)
        joined_keys = ",".join(fields.keys())
        joined_values = ",".join(fields.values())
        sql_query = f"INSERT INTO {database} ({joined_keys}) VALUES ({joined_values})"
        self.execute_and_commit(sql_query)
        return self.databasecursor.lastrowid

    def delete_sql_data(self, name, where):
        """
        Delete data from the database.

        Args:
            name (str): The name of the table.
            where (dict): The where clause.
        """
        database = self.databasetable(name)
        split_where = list(f"{key}={value}" for key, value in where.items())
        joined_where = " AND ".join(split_where)
        sql_query = f"DELETE FROM {database} WHERE {joined_where}"
        self.execute_and_commit(sql_query)
