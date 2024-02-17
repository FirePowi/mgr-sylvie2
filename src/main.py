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
import datetime
import json
import re
import sys
import traceback
import logging
import logging.handlers
import asyncio
import os

# Third party imports
import discord
from discord.app_commands import CommandTree

# Local application imports
from database import Database
from utils import Shell, UserPermission
from plugins.core import CorePlugin

###########
#   Bot   #
###########
# TODO: Create en table for each guild, and store the data in it:
#       - On guild join, create the table
#       - On guild leave, delete the table
#       - On guild update, update the table
#       - On bot update, update the table
#       - On bot join, update the table
#       - On bot leave, update the table


class Sylvie(discord.Client):
    """
    Manager Sylvie 2.0's main class.

    Inherits:
        discord.Client.
    """

    def __init__(self, dev_mode=False):
        """Initialize the bot."""
        intents = discord.Intents.all()
        super().__init__(intents=intents)

        self.tree = CommandTree(self)
        self.mode = 'dev' if dev_mode else 'testing'
        self.database = Database(self.mode)
        self.owner = None
        self.banned_members = {}
        self.shell = Shell(self, self.database, self.tree)
        self.logger = None

    def setup_logger(self, logger):
        """Set up the logger."""
        self.logger = logger
        self.shell.setup_logger(logger)

    async def setup_hook(self):
        """Set up the bot."""
        dev_guild = discord.Object(1051692008307183656)
        self.tree.copy_global_to(guild=dev_guild)
        await self.tree.sync(guild=dev_guild)

    def load_plugins(self):
        """Load the plugins."""
        self.shell.load_plugin(CorePlugin)

    async def on_ready(self):
        """Triggered when the bot is ready to use."""
        self.logger.info(f'Bot logged on as {self.user}')

        self.owner = self.application.owner
        self.load_plugins()
        channel = await self.fetch_channel(1068165280808833114)
        await channel.send({'testing': 'I\'m ready.', 'dev': 'Dev mode started.'}[self.mode])
        for guild in self.guilds:
            scope = self.shell.create_scope(guild, [""])
            scope.channel = self.shell.get_default_channel(guild)
            scope.user = guild.me
            scope.permission = UserPermission.SCRIPT

            for plugin in self.shell.plugins:
                self.banned_members = {}
                try:
                    await plugin.on_ready(scope)
                except discord.DiscordException:
                    print(traceback.format_exc())
                else:
                    print(traceback.format_exc())

    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent):
        """
        Triggered on reaction added, trigger on_reaction_event with "added" set to true.

        Args:
            payload (discord.RawReactionActionEvent):
            Discord payload of the event.
        """
        try:
            channel = self.fetch_channel(payload.channel_id)
            message = await channel.fetch_message(payload.message_id)
            member = self.fetch_user(payload.user_id)
            emoji = payload.emoji
            if payload.event_type == 'REACTION_ADD':
                added = True
            elif payload.event_type == 'REACTION_REMOVE':
                added = False
            else:
                added = None
            await self.on_reaction_event(message, emoji, member, added)
        except AttributeError as output:
            self.logger.error(f'Error on_raw_reaction_add: {output}')

    async def on_reaction_event(self,
                                message: discord.Message,
                                emoji: discord.Emoji,
                                member: discord.Member,
                                added: bool):
        """
        Triggered on reaction even, triggers plugin reaction event.

        Args:
            message (discord.Message): Message where the reaction has been added.
            emoji (discord.Emoji): Emoji added as reaction to the message.
            member (discord.Member): Member who added the reaction.
            added (bool): True if the reaction has been added, False if it has been removed.
        """
        if not isinstance(message.channel, discord.DMChannel):
            return
        if member.bot:
            return

        scope = self.shell.create_scope(message.guild, [""])
        scope.channel = message.channel
        scope.user = member
        scope.permission = UserPermission.SCRIPT
        scope.message = message

        for plugin in self.shell.plugins:
            try:
                await plugin.on_reaction(scope, message, emoji, member, added)
            except discord.DiscordException:
                self.logger.error(traceback.format_exc())
            else:
                self.logger.error(traceback.format_exc())

    async def on_message(self, message: discord.Message):
        """
        Triggered any time the bot see a discord message.

        Args:
            message (discord.Message): The message sent by the user.

        Raises:
            discord.DiscordException: If the message is not a DM and the author is not a member.
        """
        # Check if the author is still in the guild where they sent the
        # message in [Outside of DM + Is not a "Member"]
        if not isinstance(message.channel, discord.DMChannel) and not isinstance(
                message.author, discord.Member):
            return
        if message.author.bot:
            return

        prefix = {'testing': '%', 'dev': '!'}[self.mode]
        custom_prefix = self.shell.database.get_sql_data('guilds', ['command_prefix']), {
            'discord_gid': int(message.guild.id)}
        print(f"Custom prefix: {custom_prefix}")

        scope = self.shell.create_scope(message.guild, custom_prefix or prefix)
        scope.channel = message.channel
        scope.user = message.author
        scope.message = message

        if message.author == self.owner:
            scope.permission = UserPermission.BOTOWNER
        elif message.author.guild_permissions.administrator:
            scope.permission = UserPermission.ADMIN

        command_found = await self.shell.execute_command(scope, message.content)

        for plugin in self.shell.plugins:
            await plugin.on_message(scope, message, command_found)

        if command_found and scope.deletecmd:
            try:
                await message.delete()
            except discord.DiscordException:
                print(traceback.format_exc())
            else:
                print(traceback.format_exc())

    async def on_member_join(self, member):
        """Triggered when a member joins the guild.

        Args:
            member (discord.Member): The member who joined the guild.
        """
        try:
            scope = self.shell.create_scope(member.guild, [''])
            scope.channel = self.shell.get_default_channel(member.guild)
            scope.user = member.guild.me
            scope.permission = UserPermission.SCRIPT
            scope.vars['target'] = member

            for plugin in self.shell.plugins:
                await plugin.on_member_join(scope)

        except discord.DiscordException:
            self.logger.error(traceback.format_exc())
        else:
            self.logger.error(traceback.format_exc())

    async def on_raw_member_remove(self, payload):
        """Triggered when a member leaves the guild.

        Args:
            payload (discord.RawReactionActionEvent):
            Discord payload of the event triggered.
        """
        reason = "leave"
        guild = self.fetch_guild(payload.channel_id)
        member = payload.user
        if member.id in self.banned_members:
            accepted_time = datetime.datetime.now() - datetime.timedelta(minute=1)
            if self.banned_members.pop(member.id) > accepted_time:
                reason = "ban"
        else:
            async for entry in guild.audit_logs(limit=10, action=discord.AuditLogAction.kick):
                if entry.target == member:
                    reason = "kick"
        try:
            scope = self.shell.create_scope(guild, [''])
            scope.channel = self.shell.get_default_channel(guild)
            scope.user = member.guild.me
            scope.permission = UserPermission.SCRIPT
            scope.vars['target'] = member
            scope.vars['reason'] = reason

            if reason not in ["leave", "kick"]:
                return

            for plugin in self.shell.plugins:
                if reason == "leave":
                    await plugin.on_leave(scope)
                else:
                    await plugin.on_kick(scope)

        except discord.DiscordException:
            self.logger.error(traceback.format_exc())
        else:
            self.logger.error(traceback.format_exc())

    async def on_member_ban(self, guild: discord.Guild, member: discord.Member):
        """
        Triggered when a member is banned.

        Args:
            guild (discord.Guild): The guild from which the member has been banned.
            member (discord.Member): The banned member.
        """
        self.banned_members[member.id] = datetime.datetime.now()
        ban_author = ''
        ban_target = ''
        ban_reason = ''

        try:
            # We see if the bot is the author of the ban
            async for ban in guild.audit_logs(action=discord.AuditLogAction.ban, limit=10):
                if ban.target != member:
                    continue

                author = ban.user
                reason = ban.reason

                if author == guild.me:
                    research = re.search(
                        '(.+#[0-9]{4}) using (pre)?ban command', ban.reason)
                    if research:
                        author = await self.fetch_user(research.group(1)) or author
                        reason += f" using {research.group(2) or ''}ban command)."
                ban_author = author
                ban_reason = reason
                ban_target = ban.target

            # We create the scope
            scope = self.shell.create_scope(guild, [''])
            scope.channel = self.shell.get_default_channel(guild)
            scope.user = guild.me
            scope.permission = UserPermission.SCRIPT
            scope.vars['reason'] = ban_reason
            scope.vars['user'] = ban_author
            scope.vars['target'] = ban_target

            # We send the event to all plugins
            for plugin in self.shell.plugins:
                await plugin.on_ban(scope)

        except discord.DiscordException:
            self.logger.error(traceback.format_exc())
        else:
            self.logger.error(traceback.format_exc())

    async def on_member_unban(self, guild, user):
        """
        Triggered when a member is unbanned.

        Args:
            guild (discord.Guild): The guild from which the member has been unbanned.
            user (discord.User): The unbanned user.
        """
        try:
            scope = self.shell.create_scope(guild, [''])
            scope.channel = self.shell.get_default_channel(guild)
            scope.user = guild.me
            scope.permission = UserPermission.SCRIPT
            scope.vars['target'] = user

            for plugin in self.shell.plugins:
                await plugin.on_unban(scope)

        except discord.DiscordException:
            self.logger.error(traceback.format_exc())
        else:
            self.logger.error(traceback.format_exc())

#############
#  Logging  #
#############


def setup_logger(logfile, errfile):
    """Set up the logger."""
    logger = logging.getLogger('discord')

    logger.setLevel(logging.DEBUG)
    logging.getLogger('discord.http').setLevel(logging.INFO)
    
    # If directories do not exist, create them
    if not os.path.exists(os.path.dirname(logfile)):
        os.makedirs(os.path.dirname(logfile))
    if not os.path.exists(os.path.dirname(errfile)):
        os.makedirs(os.path.dirname(errfile))
    
    # Create the log and error files
    log_handler = logging.handlers.RotatingFileHandler(
        logfile,
        'a',
        1 * 1024 * 1024,
        3,
        'utf-8'
    )
    err_handler = logging.handlers.RotatingFileHandler(
        errfile,
        'a',
        1 * 1024 * 1024,
        3,
        'utf-8'
    )
    dt_fmt = '%Y-%m-%d %H:%M:%S'  # Format for datetime: YYYY-MM-DD HH:MM:SS

    # Format for logging: [datetime] [loglevel] loggername: message
    # Style is set to '{' to avoid conflicts with f-strings
    formatter = logging.Formatter(
        '[{asctime}] [{levelname:<8}] {name}: {message}', dt_fmt, style='{'
        )
    log_handler.setFormatter(formatter)
    err_handler.setFormatter(formatter)

    err_handler.setLevel(logging.WARNING)
    # Check if log file is not empty and doRollover if it is not
    if os.path.exists(logfile) and os.path.getsize(logfile) > 0:
        log_handler.doRollover()
    if os.path.exists(errfile) and os.path.getsize(errfile) > 0:
        err_handler.doRollover()

    logger.addHandler(log_handler)
    logger.addHandler(err_handler)
    return logger

#############
#   Start   #
#############


def main():
    """Start the bot."""
    try:
        with open('config.json', 'r', encoding="UTF-8") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        with open('config.json', 'w', encoding="UTF-8") as f:
            json.dump({"token": "",
                       "dev_mode": False,
                       "log_file": "log/discord.log",
                       "err_file": "log/discord_err.log"},
                      f,
                      indent=4)
        print("Please edit config.json to add a bot token.")
        sys.exit(0)
    for i in range(5):
        try:
            token = config['token']
            dev_mode = config['dev_mode']
            logfile = config['log_file']
            errfile = config['err_file']
        except KeyError as e:
            if e.args[0] == 'token':
                print("Please edit config.json to add a bot token.")
                sys.exit(0)
            elif e.args[0] == 'dev_mode':
                # Set dev_mode to False if not set
                dev_mode = False
                # Modify the config file to add the dev_mode key
                with open('config.json', 'w', encoding="UTF-8") as f:
                    config['dev_mode'] = dev_mode
                    json.dump(config, f, indent=4)
            elif e.args[0] == 'log_file':
                # Set log_file to "discord.log" if not set
                logfile = "log/discord.log"
                # Modify the config file to add the log_file key
                with open('config.json', 'w', encoding="UTF-8") as f:
                    config['log_file'] = logfile
                    json.dump(config, f, indent=4)
            elif e.args[0] == 'err_file':
                # Set err_file to "discord_err.log" if not set
                errfile = "log/discord_err.log"
                # Modify the config file to add the err_file key
                with open('config.json', 'w', encoding="UTF-8") as f:
                    config['err_file'] = errfile
                    json.dump(config, f, indent=4)
            break
    if not token:
        print("Please edit config.json to add a bot token.")
        sys.exit(0)

    logger = setup_logger(logfile, errfile)
    bot = Sylvie(dev_mode)
    try:
        # bot = Sylvie(dev_mode)
        bot.setup_logger(logger)
        bot.run(token)
    except KeyboardInterrupt:
        loop = asyncio.get_running_loop()
        loop.run_until_complete(bot.close())
        loop.close()
        logger.info("Bot closed.")
        sys.exit(0)
    #except Exception as e:
    #    try:
    #        loop = asyncio.get_running_loop()
    #        loop.run_until_complete(bot.close())
    #        loop.close()
    #    except RuntimeError:
    #        pass
    #    logger.exception(f"Bot closed with error: {e}")
    #    sys.exit(1)


if __name__ == '__main__':
    main()

# This file is part of Manager Sylvie 2.0.
# Manager Sylvie 2.0 is free software: you can redistribute it and/or  modify
# it under the terms of the GNU Affero General Public License, version 3,
# as published by the Free Software Foundation.
#
# Manager Sylvie 2.0 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Manager Sylvie 2.0.  If not, see <http://www.gnu.org/licenses/>.
