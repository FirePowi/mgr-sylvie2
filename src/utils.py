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

# Standard library imports
import random
import re
import shlex
from enum import Enum, auto
from functools import wraps
from typing import Optional, Union
import collections.abc
import traceback
import asyncio

# Third-party imports
import discord
import discord.interactions

# Local imports
import argparse

###########
# Enums   #
###########


class UserPermission(Enum):
    """Enum for user permissions."""
    MEMBER = auto()
    SCRIPT = auto()
    ADMIN = auto()
    BOTOWNER = auto()


class Verbose(Enum):
    """Enum for verbose levels."""
    SILENT = auto()
    ERROR = auto()
    INFO = auto()
    DEBUG = auto()


################
#  Exceptions  #
################


class Error(Exception):
    """Generic Error."""
    pass


class ErrorInCode(Exception):
    """There is an error in the code."""
    pass


class TooLongScriptError(Error):
    """Script is too long for discord."""
    pass


class DiscordPermissionError(Error):
    """Discord user doesn’t have permission to use a command."""

    def __init__(self, required_permission):
        self.required_permission = required_permission


class ParameterPermissionError(Error):
    """Discord user doesn’t have permission to use a parameter."""
    def __init__(self, parameter):
        self.parameter = parameter


class CommandNotFoundError(Error):
    """Command is not found."""
    def __init__(self, command):
        self.command = command


class ObjectNameError(Error):
    """Object name is not valid."""
    def __init__(self, parameter, name):
        self.parameter = parameter
        self.name = name


class IntegerError(Error):
    """Error thrown when integer is not valid."""
    def __init__(self, parameter, name):
        self.parameter = parameter
        self.name = name


class RegexError(Error):
    """Error thrown when regex is not valid."""
    def __init__(self, regex):
        self.regex = regex


################
#  Decorators  #
################


def command(description=None):
    """
    Store command in the tree.

    Decorator for prefix command,
    get the given description and pass it as description to the function.

    Args:
        func: decorated function.

    Returns:
        The wrapped function.
    """

    def decorator(func):
        """Decorator for prefix command,

        Get the given description and pass it as description to the function.

        Args:
            func (function): Function to decorate.

        Returns:
            function: The decorated function.
        """
        @wraps(func)
        def wrapper(self, scope, command, options, lines):
            return func(self, scope, command, options,
                        lines, description=description)
        return wrapper
    return decorator


def slash_command(**kwarg):
    """Decorator for discord slash command.

    Get the given description and pass it as description to the function."""
    def slash_wrapper(func):
        @wraps(func)
        @discord.app_commands.command(**kwarg)
        def wrapper(self, *args):
            return func(self, *args)
        return wrapper
    return slash_wrapper


def permission_bot_owner(func):
    """Check if member has Bot Owner permission.

    Args:
        func (function): The function for which the permission is required.

    Raises:
        DiscordPermissionError: If the Member doesn't have said permission.

    Returns:
        The function (if everything worked fine).
    """
    @wraps(func)
    def wrapper(self, scope, command, options, lines, **kwargs):
        if scope.permission < UserPermission.BOTOWNER:
            raise DiscordPermissionError('Bot Owner')
        return func(self, scope, command, options, lines, **kwargs)
    return wrapper


def permission_admin(func):
    """Check if member has Admin permission.

    Args:
        func (function): The function for which the permission is required.

    Raises:
        DiscordPermissionError: If the Member doesn't have said permission.

    Returns:
        The function (if everything worked fine).
    """
    @wraps(func)
    def wrapper(self, scope, command, options, lines, **kwargs):
        if scope.permission < UserPermission.ADMIN:
            raise DiscordPermissionError('Admin')
        return func(self, scope, command, options, lines, **kwargs)
    return wrapper


def permission_script(func):
    """Check if member has Script permission.

    Args:
        func (function): The function for which the permission is required.

    Raises:
        DiscordPermissionError: If the Member doesn't have said permission.

    Returns:
        The function (if everything worked fine).
    """
    @wraps(func)
    def wrapper(self, scope, command, options, lines, **kwargs):
        if scope.permission < UserPermission.SCRIPT:
            raise DiscordPermissionError('Script')
        return func(self, scope, command, options, lines, **kwargs)
    return wrapper

###########
#  Scope  #
###########


class ExecutionScope:
    """Scope of a command execution."""
    def __init__(self, shell, guild, prefixes):
        """Init the scope.

        Args:
            shell (Sylvie.Shell): The shell of the bot.
            guild (discord.Guild): The guild in which the command is executed.
            prefixes (str): Prefixes of the commands.
        """
        self.shell = shell
        self.prefixes = prefixes
        self.guild = guild
        self.channel = None
        self.user = None
        self.message = None

        self.permission = UserPermission.MEMBER

        self.iter = 0
        self.vars = {}
        self.member_vars = {}
        self.session_vars = {}
        self.plugin_vars = {}
        self.abort = False
        self.deletecmd = False
        self.verbose = Verbose.DEBUG

        self.shell.database.create_sql_table(
            "variable", [
                "id INTEGER PRIMARY KEY",
                "discord_gid INTEGER",
                "name TEXT",
                "value TEXT"
                ])
        self.shell.database.create_sql_table(
            "member_variables",
            [
                "id INTEGER PRIMARY KEY",
                "discord_gid INTEGER",
                "discord_mid INTEGER",
                "name TEXT",
                "value TEXT"])

    async def execute_script(self, command_line):
        """Execute a command.

        Args:
            command_line (str): The command to execute.
        """
        await self.shell.execute_command(self, command_line)

    def set_user(self, user):
        """Set the user of the scope.

        Args:
            user (discord.User): The user to set to the scope.
        """
        self.user = user
        if user == self.shell.owner:
            self.permission = UserPermission.BOTOWNER
        elif user.guild_permissions.administrator:
            self.permission = UserPermission.ADMIN
        else:
            self.permission = UserPermission.MEMBER

    def create_subscope(self):
        """Generate a subscope.

        Returns:
            ExecutionScope: The subscope.
        """
        subscope = ExecutionScope(self.shell, self.guild, self.prefixes)

        subscope.channel = self.channel
        subscope.set_user(self.user)
        subscope.message = self.message
        subscope.permission = self.permission

        subscope.iter = self.iter
        subscope.vars = self.vars
        subscope.member_vars = self.member_vars
        subscope.session_vars = self.session_vars
        subscope.abort = self.abort
        subscope.deletecmd = self.deletecmd

        return subscope

    def continue_from_subscope(self, subscope):
        """Continue the scope from a subscope.

        Args:
            subscope (ExecutionScope): The subscope to continue from.
        """
        self.iter = subscope.iter
        self.vars = subscope.vars
        self.member_vars = subscope.member_vars
        self.session_vars = subscope.session_vars
        self.abort = subscope.abord
        self.deletecmd = subscope.deletecmd

    def can_they_see(self, what):
        """Check if the user can see the attribute.

        Args:
            what (discord.*): The attribute to check if the user can see.
        """
        member = self.user
        guild_permissions = member.guild_permissions()

        # Administrator can see everything
        if guild_permissions.administrator or self.permission:
            return True

        # user
        if isinstance(what, discord.User):
            if any(guild_permissions.manage_guild,
                   guild_permissions.ban_members,
                   guild_permissions.kick_members,
                   guild_permissions.moderate_members):
                return True
            if set(member.channels) & set(what.channels):
                # Test if the user and the member share a channel
                return True
            return False

        # guild
        if isinstance(what, discord.Guild):
            return what is self.guild

        # emoji
        if isinstance(what, discord.Emoji):
            return True

        # channel
        if isinstance(what, discord.Channel):
            return what.permissions_for(member).view_channel

        # message
        if isinstance(what, discord.Message):
            return what.channel.permissions_for(member).read_message_history

        # role
        if isinstance(what, discord.Role):
            if guild_permissions.manage_roles:
                return True
            if what in member.roles:
                return True
            return False

        # client
        if isinstance(what, discord.Client):
            return True

    # (#) Remember : regex groups "start" from 1, not 0. 0 is the fullmatch
    # Regex :
    # ([*@#])?(user|guild|emoji|channel|message|role|client)(?:([\_:])([A-z]+))?(?:=(.+))?
    #
    # group(1) [opt] => display_type is either `*`, `@`, `#` or None
    #   `*` -> ID
    #   `@` -> Mention
    #   `#` -> Human-Machine readable form
    #   None -> Assume best fit
    #     (Exemples [without group(3,4)]):
    #     | user -> display_name
    #     | guild -> display_name
    #     | emoji -> The emoji itself
    #     | channel -> The name
    #     | message -> content
    #     | role -> Display_name
    #     | client -> Display_name)
    #
    # group(2) [] => discord_class_name
    # (user, guild, emoji, channel, message, role, client)
    #
    # group(3) [co-opt 4] => attribute_location is `` is either `:` or `_`
    # *Represent what we want from the class*
    #   `:` -> Means the variable group(4) is in MS2.0 database
    #   `_` -> Means the variable group(4) needs a discord API call
    #
    # group(4) [co-opt 3] => attribute_name is the actual variable we want
    # (may then be reinterpreted depending on group(1))
    # ! -> Possible security breach
    # => clue DON’T want users to have access to more than
    # they should have access to.
    # -> Default programming behavior:
    # ! **NO sensitive data accessible this way**
    #
    # group(5) => [opt] clue Clue (Not always the 'ID' but
    # anything that allow MS2.0 to identify which instance of
    # `discord_class_name` we’re refering to).
    #
    # Exemples:
    #
    # user=123456789012345678 has
    # group(1) = None,
    # group(2) = user,
    # group(3) = None,
    # group(4) = None,
    # group(5) = 123456789012345678
    #
    # @channel_mention=general has
    # group(1) = @,
    # group(2) = channel,
    # group(3) = _,
    # group(4) = mention,
    # group(5) = general

    def format_text_class(self,
                          display_type: Optional[str],
                          discord_class_name: str,
                          attribute_location: Optional[str],
                          attribute_name: Optional[str],
                          clue: Optional[str]):
        """
        Text formater in class context.

        Get the instance searched for and return the formated text.
        1. Error checks
        2. find discord_class_name's Discord Object
        3. Check if scope can access the attribute
        3a. if attribute_location and attribute_name are None,
        return following the display_type.
        3b. elif both are not None:
        3b.1. if attribute_location is `_`,
        return following the display_type.
        3b.2. elif attribute_location is `:`,
        return the variable from the database.
        3c. else, error in the regex, should not happend.

        Args:
            display_type (Optional[str]):
                * -> ID,
                @ -> Mention,
                # -> (unique-)name
                # None -> assume best.

            discord_class_name (str):
                user|guild|emoji|sticker|channel|message|role|client.

            attribute_location (Optional[str]): Where the attribute is located
                (either in the database or in the discord API).

            attribute_name (Optional[str]):
                The actual attribute we want.

            clue (Optional[str]):
                The clue to find the instance of the class we want.

        Raises:
            RegexError: Wrong regex match, should not happend
        """

        # 1. Error checks

        if not discord_class_name:
            # Error in the Regex, should not happend.
            # Check format_text -> pattern.
            raise RegexError(f"Regex matched with empty group(2)\
                               [shouldn't happend]\n\
                               All groups: (`{display_type}`,\
                               `{discord_class_name}`,\
                               `{attribute_location}`,\
                               `{attribute_name}`,\
                               `{clue}`)")

        # Check if both group(3) and group(4) are either None or not None
        # (XNOR)
        if (attribute_location is None) is (attribute_name is None):
            raise RegexError(f"Regex matched with either group(3) or group(4)\
                               but not the other one [shouldn't happend]\n\
                               All groups: (`{display_type}`,\
                                `{discord_class_name}`,\
                                `{attribute_location}`,\
                                `{attribute_name}`,\
                                `{clue}`)")

        # End of error checks

        # 2. find discord_class_name's Discord Object
        # Get the parent class where the instance is expected to be found
        try:
            parent = {
                'channel': self.guild,
                'user': self.shell.client,
                'emoji': self.guild,
                'sticker': self.guild,
                'message': self.channel,
                'role': self.guild}[discord_class_name]
            host = self.shell.find_anything(parent,
                                            discord_class_name,
                                            joker=clue)
            if not host:
                print(f"Host {discord_class_name} not found in {parent}.\n\
                        Clue if any: '{clue}'")
                return discord_class_name
        except KeyError:
            # Error in the Regex, check format_text -> pattern.
            raise RegexError(
                f"Regex matched with invalid discord_class_name\
                `{discord_class_name}` [shouldn't happend]\n\
                All groups: (`{display_type}`,\
                `{discord_class_name}`,\
                `{attribute_location}`,\
                `{attribute_name}`,\
                `{clue}`)")

        # 3. Check if scope can access the attribute "host"
        if not self.can_they_see(host):
            print(f"User {self.user} can't see {host}.")
            return discord_class_name

    def format_text(self, text):
        """Format the text with the variables.

        Args:
            text (str): The text to format.

        Returns:
            str: The formatted text.
        """
        if not text:
            return ''

        # Entre {{ et }}, tout sauf }
        pattern = re.compile(r'\{\{([^\}]+)\}\}')

        formated_text = ''
        text_iter = 0

        match_iterations = pattern.finditer(text) or []
        for match in match_iterations:
            formated_text += text[text_iter:match.start()]
            text_iter = match.end()

            # Process tag
            tag = match.group(1).strip()

            if '|' in tag:
                tag = random.choice(tag.split('|'))

            # It's fullmatch, if you want to test it on regexkit.com,
            # use options "gm" at the end (where it's written of gmixsu)
            # ALSO add ^ add the beginning of the pattern and $ at the end
            # It should look like this: (without carriage returns)
            # "^([*@#])?
            # (user|guild|emoji|sticker|channel|message|role|client)
            # (?:([\_:])([A-z]+))?(?:=(.+))?$"
            # gm
            groups = []
            groups.append(r"([*@#])?")
            # catch the display_type
            # () => group
            #   [*@#] => one of these characters
            #   ? => 0 or 1 time (ie. optional)
            discord_classes = []
            discord_classes.append('user')
            discord_classes.append('guild')
            discord_classes.append('emoji')
            discord_classes.append('sticker')
            discord_classes.append('channel')
            discord_classes.append('message')
            discord_classes.append('role')
            discord_classes.append('client')
            groups.append(rf"({'|'.join(discord_classes)})")
            # catch the discord_class_name
            # (|) => one of these strings
            groups.append(r"(?:([\_:])([A-z]+))?")
            # catch the attribute_location and attribute_name
            # (?:) => non-capturing group
            #   () => group
            #     [\_:] => one of these characters
            #   () => group
            #     [A-z] => one of these characters
            #     + => 1 or more time
            # ? => 0 or 1 time (ie. optional)
            groups.append(r"(?:=(.+))?")
            # catch the clue
            # (?:) => non-capturing group
            #   =  => this character
            #   () => group
            #     . => any character
            #     + => 1 or more time
            # ? => 0 or 1 time (ie. optional)
            pattern = ''.join(groups)
            tag_match = re.fullmatch(pattern, tag)

            if tag_match:
                tag_output = self.format_text_class(*tag_match.groups())
                formated_text += tag_output
            else:
                formated_text += match.group(0)

        formated_text += text[text_iter:]
        return formated_text

###########
#  Shell  #
###########

class Shell:
    """A shell for the bot that provides various utility functions.

    Args:
        client: (discord.Client): The Discord client object.
        database: (Database): The database object.
        tree: (Tree): The tree object.
    """

    def __init__(self, client, database, tree):
        self.plugins = []
        self.client = client
        self.database = database
        self.tree = tree
        self.logger = None

    def setup_logger(self, logger):
        """Setup the logger.

        Args:
            logger: (logging.Logger): The logger object.
        """
        self.logger = logger

    async def print(self, scope, msg, level):
        """Prints a message to the specified scope with the given level.

        Args:
            scope: (ExecutionScope): The scope where the message is printed.
            msg: (str): The message to print.
            level: (str): The level of the message.

        Raises:
            ErrorInCode: The level is not recognized.
        """
        levels = {
            'info': [Verbose.INFO, ':information_source:'],
            'debug': [Verbose.DEBUG, ':large_blue_circle:'],
            'success': [Verbose.DEBUG, ':white_check_mark:'],
            'permission': [Verbose.ERROR, ':close_lock_with_key:'],
            'error': [Verbose.ERROR, ':no_entry:'],
            'fatal': [Verbose.ERROR, ':skull_crossbones:'],
            'usage': [Verbose.DEBUG, '']
        }
        if level not in levels.keys():
            # This should NEVER happen, error in the code!
            # Check the traceback to see where print has been called.
            raise ErrorInCode(f'the level "{level}" does not exist. Contact Powi')

        if scope.verbose >= levels.get(level)[0]:
            # Send the message to the channel
            # if the verbose level is high enough.
            await scope.channel.send(f"{levels.get(level)[1]} {msg}")
        return

    def find_anything(self,
                      scope,
                      host: Union[discord.Guild,
                                  discord.abc.GuildChannel,
                                  discord.User,
                                  discord.Member,
                                  discord.Emoji,
                                  discord.Role],
                      search_item,
                      **kwargs):
        """Find anything in a host class.

        Args:
            scope: (ExecutionScope): The scope where the item is searched.
            host: (Union[discord.*]): The host class to search in.
            search_item: (str): The item to search for in the host class.

        Raises:
            TypeError: The type of the host is not valid.
            ErrorInCode: The type of the search_item is not valid.

        Returns:
            Any: The found item.
        """
        try:
            # Get the type of the host
            host_type = 'guild' if isinstance(host, discord.Guild) \
                else 'channel' if isinstance(host, discord.abc.GuildChannel) \
                else 'user' if isinstance(host, discord.User) \
                else 'emoji' if isinstance(host, discord.Emoji) \
                else 'sticker' if isinstance(host, discord.GuildSticker) \
                else 'role' if isinstance(host, discord.Role) \
                else 'client' if isinstance(host, discord.Client) \
                else None
            if not host_type:
                raise TypeError(f"Type {type(host)} not recognized")

            # List the possible locations of the search_item for each host type
            locations = {
                'guild': ['client', 'channels', 'members', 'emojis', 'stickers', 'me'],
                'channel': ['guild', 'category_channel', 'text_channel', 'forum_channel', 'widget'],
                'user': ['client', 'reaction', 'scheduled_event', 'guild', 'team', 'role', 'channel', 'widget'],
                'emoji': ['client', 'guild'],
                'sticker': ['guild'],
                'sound': ['guild'],
                'role': ['audit_log_diff', 'guild', 'member', 'emoji'],
                'client': ['users', 'user', 'guilds', 'emojis', 'stickers', 'application']
            }
            # Get the list of possible search_items for the host_type
            host_resources = locations.get(host_type)

            if search_item not in host_resources:
                # Should never happen, error in the code! Check the traceback to see where find_anything has been called.
                raise ErrorInCode(f"Type {search_item} can not be found in {host_type}")

            source = getattr(host, search_item)
            # getattr is a function that
            # returns the value of the named attribute of an object.
            # Here, it returns the value of the attribute
            # "search_item" of the object "host"
            #Example: getattr(Discord.Guild, 'members')
            # returns the list of members of the guild.
            #Example: getattr(Discord.Guild, 'me')
            # returns the bot's member object in the guild.

            if not isinstance(source, collections.abc.Iterable):
                return source

            joker = kwargs.get('joker', None)

            for tested in ['name', 'id', 'mention']:
                if tested in kwargs.keys() or joker:
                    for item in source:
                        if getattr(item, tested) == kwargs.get(tested, joker):
                            return item
            return None

        except IndexError:
            self.print()

    def is_plugin_loaded(self, plugin):
        """Checks if a plugin is already loaded.

        Args:
            plugin: (Plugin): The plugin to check.

        Returns:
            bool: True if the plugin is loaded, False otherwise.
        """
        for plugin_iter in self.plugins:
            if isinstance(plugin_iter, plugin):
                return True
            return False

    def load_plugin(self, plugin):
        """Loads a plugin.

        Args:
            plugin: (Plugin): The plugin to load.
        """
        if self.is_plugin_loaded(plugin):
            self.logger.info(f"Plugin {plugin.name} is already loaded")
            return
        try:
            instance = plugin(self)
            self.plugins.append(instance)
            self.logger.info(f"Plugin {plugin.name} loaded.")
        except BaseException:
            self.logger.error(f"Plugin {plugin.name} can't be loaded. See Traceback:\n")
            self.logger.error(traceback.format_exc())

    def find_command_and_option(self, command_line, prefixes):
        """Finds the command and options in a command line.

        Args:
            command_line: (str): The command line to parse.
            prefixes: (list): The list of prefixes to check.

        Returns:
            tuple: A tuple containing the command, options, and arguments.
        """
        for prefix in prefixes:
            if not command_line.startswith(prefix):
                continue
            command_line = command_line[len(prefix):]
            lines = command_line.split('\n')
            command = lines[0].split(" ")[0].strip()
            options = lines[0][len(command):].strip()
            if not len(command.strip()):
                return None
            return (command, options, lines[1:])
        return None

    def get_default_channel(self, guild):
        """Gets the default channel for a guild.

        Args:
            guild: (discord.Guild): The guild to get the default channel for.

        Returns:
            discord.TextChannel: The default channel or the first "good fit" channel.
        """
        possibilities = [guild.system_channel,
                         guild.public_updates_channel,
                         guild.text_channels[0],
                         guild.owner.dm_channel,
                         guild.owner.create_dm(),
                         guild.me.owner.dm_channel,
                         guild.me.owner.create_dm()]
        missing_write_permissions = None
        for possibility in possibilities:
            # Check if possibility is an async function and await it if it is
            if hasattr(possibility, '__await__'):
                possibility = asyncio.run(possibility)
            if not possibility:
                continue
            if not possibility.permissions_for(guild.me).send_messages:
                #check if the bot can send messages in the channel
                #if not, we keep track of the missing permissions
                if missing_write_permissions is []:
                    missing_write_permissions = possibility
                continue

            default_channel = possibility
            break

        #Pick the first channel that is not None
        if not default_channel:
            raise Error("No channel found (what?).")
        if missing_write_permissions is not None:
            scope = self.create_scope(guild, [''])
            self.print(scope, f"{guild.me.mention} does **not** have permission to send messages in {missing_write_permissions[0].mention}.", 'fatal')

        return default_channel

    def create_scope(self, guild, prefixes):
        """Creates a new execution scope.

        Args:
            guild: (discord.Guild): The guild to create the scope for.
            prefixes: (list): The list of prefixes to use for the scope.

        Returns:
            ExecutionScope: The new execution scope.
        """
        scope = ExecutionScope(self, guild, prefixes)

        # Get variables from the database
        # scope.vars = {row[0]:row[1] for row in self.database.get_sql_data(
        #     'variable', ['name', 'value'],
        #     {'discord_gid': guild.id}, True)} or None
        scope.vars = {}
        for row in self.database.get_sql_data('variable', ['name', 'value'], {'discord_gid': guild.id}, True):
            scope.vars[row[0]] = row[1]

        # Get member variables from the database
        member_vars = {}
        def assignate_member_vars(member, key, value):
            if member not in member_vars.keys():
                member_vars[member] = {}
            member_vars[member][key] = value
        member_vars = {assignate_member_vars(row) for row in self.database.get_sql_data(
            'member_variables', ['discord_mid', 'name', 'value'], None, True)} or None

        return scope

    def scope_from_interaction(self, interaction):
        """Creates a new execution scope from an interaction.

        Args:
            interaction: (discord.Interaction): The interaction to create the scope from.

        Returns:
            ExecutionScope: The new execution scope.
        """
        scope = self.create_scope(interaction.guild, ['/'])
        scope.channel = interaction.channel or self.get_default_channel(interaction.guild)
        scope.set_user(interaction.user)

        return scope

    async def execute_command(self, scope, command_line):
        """
        Execute a command.

        Args:
            Scope (ExecutionScope): The scope in which the command is executed.
            command_line (str): The command to execute.

        Raises:
            TooLongScriptError: The script is too long.
            CommandNotFoundError: The command is not found.

        Returns:
            bool: True if the command has been executed, False otherwise.
        """
        if scope.iter > 256:
            raise TooLongScriptError()

        if not (parsedCommand := self.find_command_and_option(
                command_line, scope.prefixes)):
            return False

        for plugin in self.plugins:
            if await plugin.execute_command(scope, parsedCommand[0], parsedCommand[1], parsedCommand[2]):
                scope.iter += 1
                return True
        raise CommandNotFoundError(parsedCommand[0])

    async def execute_script(self, scope, script):
        """
        Execute a script.

        Try to execute each line of the script until an error is raised.

        Args:
            Scope (ExecutionScope): The scope in which the script is executed.
            script (str): The script to execute.

        Raises:
            CommandNotFoundError: The command is not found.
            DiscordPermissionError: The user does not have the required permission.
            ParameterPermissionError: The user does not have the required permission for a parameter.
            ObjectNameError: The object name is not valid.
            IntegerError: The integer is not valid.
            RegexError: The regex is not valid.
            Exception: An unknown error occured.
        """
        lines = script.split('\n')
        for line in lines:
            line = line.strip()

            command = self.find_command_and_option(line, scope.prefixes)[0]
            try:
                scope.execute_script(command, line)
            except CommandNotFoundError(command):
                await self.print(scope, f"Command `{command}` not found.", 'error')
                break
            except DiscordPermissionError as error:
                await self.print(scope, f"This command is restricted to {error.required_permission} you must have this role or higher, you don't.", 'permission')
                break
            except ParameterPermissionError as error:
                await self.print(scope, f"You are not allowed to use the parameter `{error.parameter}`.")
                break
            except ObjectNameError as error:
                await self.print(scope, f"{error.parameter} must be a letter followed by alphanumeric characters.", 'error')
                break
            except IntegerError as error:
                await self.print(scope, f"{error.parameter} must be a number.", 'error')
                break
            except RegexError as error:
                await self.print(scope, f"`{error.regex}` is not a valid regex", 'error')
                break
            except Exception as e:
                await self.print(scope, f"**Manager Sylvie Unexpected Error**\n\n```traceback\n{traceback.format_exc()}```", 'fatal')
                break
        else:
            await self.print(scope, "Script executed successfully.", 'success')

    async def send(self, recipient, content, embed=None):
        return await recipient.send(content, embed=embed)

    async def edit_roles(self, scope, member, add_roles, remove_roles, reason=None):
        try:
            roles = member.roles
            await member.add_roles(roles, reason)
            added = [role for role in member.roles if role not in roles]
            await member.remove_roles(roles, reason)
            removed = [role for role in roles if role not in member.roles]

        except discord.Forbidden as error:
            self.print(
                scope,
                f"{scope.guild.me.mention} does **not** have permission to send add role, discord API replied:\n{error.response}\n{error.message}",
                'fatal')

        return (added, removed)

############
#  Plugin  #
############


class Plugin:
    """
    Parent class of all Plugins – Is an Abstract
    """

    def __init__(self, shell):
        self.shell = shell
        self.cmds = {}

    async def on_loop(self, scope):
        return

    async def list_commands(self):
        return list(self.cmds.keys())

    async def execute_command(self, scope, command, options, lines):
        """
        Execute a command.

        Args:
            Scope (ExecutionScope): The scope in which the command is executed.
            command (str): The command to execute.
            options (str): The options of the command.
            lines (list): The lines of the command.

        Returns:
            bool: True if the command has been executed, False otherwise.
        """
        if command in self.cmds:
            scope.iter += 1
            await self.cmds[command](scope, command, options, lines)
            return True
        return False

    async def on_member_join(self, scope):
        """A member joins the guild."""
        return False
    async def on_ban(self, scope):
        """A member is banned from the guild."""
        return False
    async def on_kick(self, scope):
        """A member is kicked from the guild."""
        return False
    async def on_leave(self, scope):
        """A member leaves the guild."""
        return False
    async def on_unban(self, scope):
        """A member is unbanned from the guild."""
        return False
    async def on_message(self, scope, message, command_found):
        """A message is sent in the guild."""
        return False
    async def on_reaction(self, scope, message, emoji, member, added):
        """A reaction is added or removed from a message in the guild."""
        return False

    def add_command(self, name, cmd, register=None):
        """Add a command to the plugin.

        Args:
            name (str): The name of the command.
            cmd (function): The function to execute.

        Raises:
            ErrorInCode: The command already exists.
        """
        if name in self.cmds:
            #This should NEVER happen, error in the code! Check the name of the command for dups.
            raise ErrorInCode(f'Command {name} already exists')
        self.cmds[name] = cmd
        # TODO: Move this to the shell

    async def parse_options(self, scope, parser, options):
        """Parse the options of a prefixed command.

        Args:
            scope (ExecutionScope): The scope in which the command is executed.
            parser (ArgumentParser): The parser to use.
            options (str): The options to parse.

        Returns:
            Namespace: The parsed options.
        """
        try:
            args = parser.parse_args(shlex.split(options)) if options else None
            return args
        except ParserExit as error:
            message = getattr(error, 'text', str(error))
            await self.shell.print(scope, message, 'usage')
        except ParserError as error:
            message = getattr(error, 'text', str(error))
            if message.find(f"{parser.prog}: error: ") >= 0:
                parts = message.split(f"{parser.prog}: error: ")
                await self.shell.print(scope, f"{parts[1]}\n{parts[0]}", 'error')
            else:
                await self.shell.print(scope, "ParserError, please contact Pixels", 'error')
        return None

    def ensure_object_name(self, parameter, name):
        """Check if the object name is valid.

        Args:
            parameter (str): The parameter to check.
            name (str): The name of the parameter.

        Raises:
            ObjectNameError: The object name is not valid.
        """
        if not re.fullmatch('[A-z_]\\w*', name):
            raise ObjectNameError(parameter, name)

    def ensure_integer(self, parameter, name):
        """
        Check if the integer is valid.

        Args:
            parameter (str): The parameter to check.
            name (str): The name of the parameter.

        Raises:
            IntegerError: The integer is not valid.
        """
        if not name.isdigit():
            raise IntegerError(parameter, name)

    def ensure_regex(self, regex):
        """
        Check if the regex is valid.

        Args:
            regex (str): The regex to check.

        Raises:
            RegexError: The regex is not valid.
        """
        try:
            re.compile(regex)
        except re.error as error:
            raise RegexError(regex) from error

###################
#  MessageStream  #
###################


class MessageStream:
    """A stream for sending long messages."""
    def __init__(self, scope):
        """Init the MessageStream."""
        self.scope = scope
        self.text = ""
        self.monospace = False

    async def flush(self):
        """Flush the stream."""
        if self.monospace:
            await self.scope.channel.send(f"```\n{self.text}\n```")
        else:
            await self.scope.channel.send(self.text)
        self.text = ""

    async def send(self, text):
        """Send a message."""
        self.monospace = False

        if len(self.text) + text < 2000:
            self.text += text
        else:
            await self.flush()
            self.text = text

    async def send_monospace(self, text):
        """Send a monospace message."""
        self.monospace = True

        if len(self.text) + text < 2000 - len("```\n\n```"):
            self.text += text
        else:
            await self.flush()
            self.text = text

    async def finish(self):
        """Flush the stream."""
        await self.flush()

# sed command to replace all the "self." by "scope.":
# sed -i 's/self\./scope\./g' *.py
# to replace all the whitespace in empty lines by nothing:
# sed -i 's/^[ \t]*$//g' *.py
# ^[ \t]*$ is a regex that matches empty lines
# ^ matches the beginning of the line
# [ \t] matches a space or a tab
# * matches 0 or more times