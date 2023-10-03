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
import json
import random
import re
import shlex
import sys
from collections import abc
from enum import Enum as IntEnum, auto
from functools import wraps
from io import StringIO
from typing import Optional, Union

# Third-party imports
import discord
import discord.interactions

# Local imports
from src.homeparse import ParserError, ParserExit


################
#  Exceptions  #
################


class Error(Exception):
    """Generic Error."""
    pass


class TooLongScriptError(Error):
    """Error thrown when script is too long for discord."""
    pass


class PermissionError(Error):
    """Permission thrown when discord user doesn’t have permission to use a command."""

    def __init__(self, required_permission):
        self.required_permission = required_permission


class ParameterPermissionError(Error):
    """Error thrown when discord user doesn’t have permission to use a parameter."""
    def __init__(self, parameter):
        self.parameter = parameter

class CommandNotFoundError(Error):
    """Error thrown when command is not found."""
    def __init__(self, command):
        self.command = command


class ObjectNameError(Error):
    """Error thrown when object name is not valid."""
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
    """Decorator for discord message command, get the given description and pass it as description to the function.

    Args:
        func: decorated function.

    Returns:
        The wrapped function.
    """

    def decorator(func):
        """Decorator for discord message command, get the given description and pass it as description to the function.

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
    """Decorator for discord slash command, get the given description and pass it as description to the function."""
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
        PermissionError: If the Member doesn't have said permission.

    Returns:
        The function (if everything worked fine).
    """
    @wraps(func)
    def wrapper(self, scope, command, options, lines, **kwargs):
        if scope.permission < UserPermission.BotOwner:
            raise PermissionError('Bot Owner')
        return func(self, scope, command, options, lines, **kwargs)
    return wrapper


def permission_admin(func):
    """Check if member has Admin permission.

    Args:
        func (function): The function for which the permission is required.

    Raises:
        PermissionError: If the Member doesn't have said permission.

    Returns:
        The function (if everything worked fine).
    """
    @wraps(func)
    def wrapper(self, scope, command, options, lines, **kwargs):
        if scope.permission < UserPermission.Admin:
            raise PermissionError('Admin')
        return func(self, scope, command, options, lines, **kwargs)
    return wrapper


def permission_script(func):
    """Check if member has Script permission.

    Args:
        func (function): The function for which the permission is required.

    Raises:
        PermissionError: If the Member doesn't have said permission.

    Returns:
        The function (if everything worked fine).
    """
    @wraps(func)
    def wrapper(self, scope, command, options, lines, **kwargs):
        if scope.permission < UserPermission.Script:
            raise PermissionError('Script')
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

        self.permission = UserPermission.Member

        self.iter = 0
        self.vars = {}
        self.member_vars = {}
        self.session_vars = {}
        self.plugin_vars = {}
        self.abort = False
        self.deletecmd = False
        self.verbose = 2

        self.shell.database.create_sql_table(
            "variable", [
                "id INTEGER PRIMARY KEY", "discord_gid INTEGER", "name TEXT", "value TEXT"])
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
            self.permission = UserPermission.BotOwner
        elif user.guild_permissions.administrator:
            self.permission = UserPermission.Admin
        else:
            self.permission = UserPermission.Member

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


    # (#) Remember : regex groups "start" from 1, not 0. 0 is the fullmatch
    # Regex : ([*@#])?(user|guild|emoji|channel|message|role|client)(?:([\_:])([A-z]+))?(?:=(.+))?
    #
    # group(1) [opt] => class_main_attribute is either `*`, `@`, `#` or None
    #   `*` -> ID
    #   `@` -> Mention
    #   `#` -> Human-Machine readable form
    #   None -> Assume best fit
    #     (Exemples [without group(3,4)]): user -> display_name | guild -> display_name
    #     | emoji -> The emoji itself | channel -> The name
    #     | message -> content | role -> Display_name
    #     | client -> Display_name)
    #
    # group(2) [] => class_name (user, guild, emoji, channel, message, role, client)
    #
    # group(3) [co-opt 4] => class_secondary_attribute_location is `` is either `:` or `_`
    # *Represent what we want from the class*
    #   `:` -> Means the variable group(4) is in MS2.0 database
    #   `_` -> Means the variable group(4) needs a discord API call
    #
    # group(4) [co-opt 3] => class_secondary_attribute is the actual variable we want (may then be reinterpreted depending on group(1))
    # [!!] -> Possible security breach => We DON’T want users to have access to more than they should have access to
    #      -> Default programming behavior: **NO sensitive data accessible this way**
    #
    # group(5) => [opt] class_instance Clue (Not always the 'ID' but
    # anything that allow MS2.0 to identify which instance of `class_name`
    # we’re refering to).
    #
    # Exemples: 
    # user=123456789012345678 has group(1) = None, group(2) = user, group(3) = None, group(4) = None, group(5) = 123456789012345678
    # @channel_mention=general has group(1) = @, group(2) = channel, group(3) = _, group(4) = mention, group(5) = general
    # In this case, we 

    def class_formater(self,
                       class_main_attribute: Optional[str],
                       class_name: str,
                       class_secondary_attribute_location: Optional[str],
                       class_secondary_attribute: Optional[str],
                       class_instance: Optional[str]):
        """

        Args:
            class_main_attribute (Optional[str]): * -> ID, @ -> Mention, # -> (unique-)name, None -> assume best.
            class_name (str): user|guild|emoji|sticker|channel|message|role|client.
            class_secondary_attribute_location (Optional[str]): Where the attribute is located 
            (either in the database or in the discord API).
            class_secondary_attribute (Optional[str]): The actual attribute we want.
            class_instance (Optional[str]): The clue to find the instance of the class we want.

        Raises:
            RegexError: Wrong regex match, should not happend
        """
        if not class_name:
            raise RegexError(f"Regex matched with empty group(2) [shouldn't happend]\n\
                All groups: (`{class_main_attribute}`,`{class_name}`,`{class_secondary_attribute_location},{class_secondary_attribute},{class_instance}`)")
    
        # Check if both are None or not None (logic XNOR)
        if (class_secondary_attribute_location is None) is (class_secondary_attribute is None):
            raise RegexError(f"Regex matched with either group(3) or group(4) but not the other one [shouldn't happend]\n\
                All groups: (`{class_main_attribute}`,`{class_name}`,`{class_secondary_attribute_location},{class_secondary_attribute},{class_instance}`)")

        if class_instance is not None:
            parent = {
                'channel': self.Guild,
                'user': self.client,
                'emoji': self.Guild,
                'sticker': self.guild,
                'message': self.channel,
                'role': self.guild}[class_name]

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

            # It's fullmatch, if you want to test it on regexkit.com, use options "gm" at the end (where it's written of gmixsu)
            # ALSO add ^ add the beginning of the pattern and $ at the end
            # It should look like this:
            # " ^([*@#])?(user|guild|emoji|sticker|channel|message|role|client)(?:([\_:])([A-z]+))?(?:=(.+))?$ " gm
            pattern = r"([*@#])?(user|guild|emoji|sticker|channel|message|role|client)(?:([\_:])([A-z]+))?(?:=(.+))?"
            tag_match = re.fullmatch(pattern, tag)

            if tag_match:
                tag_output = self.class_formater(*tag_match.groups())
                formated_text += tag_output
            else:
                formated_text += match.group(0)

        formated_text += text[text_iter:]
        return formated_text

###########
#  Shell  #
###########


class UserPermission(Enum):
    Member = auto()
    Script = auto()
    Admin = auto()
    BotOwner = auto()


class Shell:
    """Shell for the bot
    """

    def __init__(self, client, database, tree):
        self.plugins = []
        self.client = client
        self.database = database
        self.tree = tree
    
    async def print(self, scope, msg, level):
        # key: [minimum verbose_level, 'Emoji_used']
        levels = {
            'info': [2, ':information_source:'],
            'debug': [3, ':large_blue_circle:'],
            'success': [2, ':white_check_mark:'],
            'permission': [1, ':close_lock_with_key:'],
            'error': [1, ':no_entry:'],
            'fatal': [1, ':skull_crossbones:'],
            'usage': [2, '']
        }
        if not level in levels.keys():
            raise ValueError(f'the level "{level}" does not exist')
            return
        if scope.verbose >= levels.get(level)[0]:
            await scope.channel.send(f"{levels.get(level)[1]} {msg}")
        return

    def find_anything(self, scope, host: Union[discord.Guild, discord.abc.Channel, discord.User, discord.Member, discord.Emoji, discord.Role], search_item, **kwargs):
        """Find anything in a host class.

        Args:
            scope: (ExecutionScope): The scope where the item is searched.
            host: (Union[discord.*]): The host class to search in.
            search_item: (str): The item to search for in the host class.

        Raises:
            TypeError: The type of the search_item is not valid.

        Returns:
            str: The found item.
        """
        try:
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
            
            locations = {
                'guild': ['client', 'channels', 'members', 'emojis', 'stickers', 'me'],
                'channel': ['guild', 'category_channel', 'text_channel', 'forum_channel', 'widget'],
                'user': ['client', 'reaction', 'scheduled_event', 'guild', 'team', 'role', 'channel', 'widget'],
                'emoji': ['client', 'guild'],
                'sticker': ['guild'],
                'role': ['audit_log_diff', 'guild', 'member', 'emoji'],
                'client': ['users', 'user', 'guilds', 'emojis', 'stickers', 'application']
            }
            
            host_resources = locations.get(host_type)
            
            if not search_item in host_resources:
                # "given_object"
                raise TypeError(f"Type {search_item} can not be found in {host_type}")
            
            source = getattr(host, search_item) 
            #getattr is a function that returns the value of the named attribute of an object.
            #Here, it returns the value of the attribute "search_item" of the object "host"
            
            
            if not isinstance(source, collections.abc.Iterable):
                return source
            
            joker = kwargs.get('joker', None)
            
            for tested in ['name', 'id', 'mention']:
                if tested in kwargs.keys() or joker:
                    for item in source:
                        if getattr(item, tested) == kwargs.get(tested, joker):
                            return item

        except IndexError:
            self.print()

    def is_plugin_loaded(self, plugin):
        for plugin_iter in self.plugins:
            if isinstance(plugin_iter, plugin):
                return True
            return False

    def load_plugin(self, plugin):
        if self.is_plugin_loaded(plugin):
            print(f"Plugin {plugin.name} is already loaded")
            return
        try:
            instance = plugin(self)
            self.plugins.append(instance)
            print(f"Plugin {plugin.name} loaded")
        except BaseException:
            print(traceback.format_exc())
            print(f"Plugin {plugin.name} can't be loaded")

    def find_command_and_option(self, command_line, prefixes):
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
        return guild.system_channel or guild.public_updates_channel or guild.text_channels[0]

    def create_scope(self, guild, prefixes):
        scope = ExecutionScope(self, guild, prefixes)
        scope.vars = {row[0]: row[1] for row in self.database.get_sql_data(
            'variable', ['name', 'value'], {'discord_gid': guild.id}, True)} or None
        member_vars = {}

        def assignate_member_vars(member, key, value):
            if member not in member_vars.keys():
                member_vars[member] = {}
            member_vars[member][key] = value
        member_vars = {assignate_member_vars(row) for row in self.database.get_sql_data(
            'member_variables', ['discord_mid', 'name', 'value'], None, True)} or None

        return scope

    def scope_from_interaction(self, interaction):
        scope = self.create_scope(interaction.guild, [''])
        scope.channel = interaction.channel
        scope.set_user(interaction.user)

    async def execute_command(self, scope, command_line):
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
        lines = script.split('\n')
        for line in lines:
            line = line.strip()

            command = self.find_command_and_option(line, scope.prefixes)[0]
            try:
                scope.execute_script(command, line)

            except CommandNotFoundError(command):
                await self.print(scope, f"Command `{command}` not found.", 'error')
                break
            except PermissionError(required_permission):
                await self.print(scope, f"This command is restricted to {required_permission} you must have this role or higher, you don't.", 'permission')
                break
            except ParameterPermissionError(parameter):
                await self.print(scope, f"You are not allowed to use the parameter `{parameter}`.")
                break
            except ObjectNameError(parameter, name):
                await self.print(scope, f"{parameter} must be a letter followed by alphanumeric characters.", 'error')
                break
            except IntegerError(parameter, name):
                await self.print(scope, f"{parameter} must be a number.", 'error')
                break
            except RegexError(regex):
                await self.print(scope, f"`{regex}` is not a valid regex", 'error')
                break
            except Exception as e:
                await self.print(scope, f"**Manager Sylvie Unexpected Error**\n\n```traceback\n{traceback.format_exc()}```", 'fatal')
                break

    async def send(self, recipient, content, embed=None):
        return await recipient.send(content, embed=embed)

    async def edit_roles(self, scope, member, add_roles, remove_roles, reason=None):
        try:
            roles = member.roles
            await member.add_roles(roles, reason)
            added = [role for role in member.roles if role not in roles]
            await member.remove_roles(roles, reason)
            removed = [role for role in roles if role not in member.roles]

        except discord.Forbidden(response, message):
            self.print(
                scope,
                f"{scope.guild.me.mention} does **not** have permission to send add role, discord API replied:\n{response}\n{message}",
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
        if command in self.cmds.keys():
            scope.iter += 1
            await self.cmds[command](scope, command, options, lines)
            return True
        return False

    async def on_member_join(self, scope): return False
    async def on_ban(self, scope): return False
    async def on_kick(self, scope): return False
    async def on_leave(self, scope): return False
    async def on_unban(self, scope): return False
    async def on_message(self, scope, message, command_found): return False

    async def on_reaction(
        self,
        scope,
        message,
        emoji,
        member,
        added): return False

    def add_command(self, name, cmd, register=None):
        if name in self.cmds.keys():
            raise Error('Command already exists')
        self.cmds[name] = cmd

    async def parse_options(self, scope, parser, options):
        is_valid = False
        try:
            args = parser.parse_args(shlex.split(options)) if options else None
            return args
        except ParserExit as e:
            message = getattr(e, 'text', str(e))
            await self.shell.print(scope, message, 'usage')
        except ParserError as e:
            message = getattr(e, 'text', str(e))
            if message.find(f"{parser.prog}: error: ") >= 0:
                parts = message.split(f"{parser.prog}: error: ")
                await self.shell.print(scope, f"{parts[1]}\n{parts[0]}", 'error')
            else:
                await self.shell.print(scope, "ParserError, please contact Pixels", 'error')
        return None

    def ensure_object_name(self, parameter, name):
        if not re.fullmatch('[A-z_]\\w*', name):
            raise ObjectNameError(parameter, name)

    def ensure_integer(self, parameter, name):
        if not re.fullmatch('\\d+', name):
            raise IntegerError(parameter, name)

    def ensure_regex(self, regex):
        try:
            re.compile(regex)
        except re.error:
            raise RegexError(regex)

###################
#  MessageStream  #
###################


class MessageStream:
    def __init__(self, scope):
        self.scope = scope
        self.text = ""
        self.monospace = False

    async def flush(self):
        if self.monospace:
            await self.scope.channel.send(f"```\n{self.text}\n```")
        else:
            await self.scope.channel.send(self.text)
        self.text = ""

    async def send(self, text):
        self.monospace = False

        if len(self.text) + text < 2000:
            self.text += text
        else:
            await self.flush()
            self.text = text

    async def send_monospace(self, text):
        self.monospace = True

        if len(self.text) + text < 2000 - len("```\n\n```"):
            self.text += text
        else:
            await self.flush()
            self.text = text

    async def finish(self):
        await self.flush()
