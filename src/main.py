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

import sys
import traceback
import datetime
import re
import json

import discord
from discord import app_commands

import utils

from database import Database
from plugins.core import CorePlugin

###########
##  Bot  ##
###########


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

        self.tree = app_commands.CommandTree(self)
        self.mode = 'dev' if dev_mode else 'testing'
        self.database = Database(self.mode)
        self.owner = None
        self.banned_members = {}
        self.shell = utils.Shell(self, self.database, self.tree)

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
        print(f'Bot logged on as {self.user}')

        self.owner = self.application.owner
        self.load_plugins()
        channel = await self.fetch_channel(1068165280808833114)
        await channel.send({'testing': 'I\'m ready.', 'dev': 'Dev mode started.'}[self.mode])
        for guild in self.guilds:
            scope = self.shell.create_scope(guild, [""])
            scope.channel = self.shell.get_default_channel(guild)
            scope.user = guild.me
            scope.permission = utils.UserPermission.Script

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
            print(f'Error on_raw_reaction_add: {output}')

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
        scope.permission = utils.UserPermission.Script
        scope.message = message

        for plugin in self.shell.plugins:
            try:
                await plugin.on_reaction(scope, message, emoji, member, added)
            except discord.DiscordException:
                print(traceback.format_exc())
            else:
                print(traceback.format_exc())

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

        scope = self.shell.create_scope(message.guild, custom_prefix or prefix)
        scope.channel = message.channel
        scope.user = message.author
        scope.message = message

        if message.author == self.owner:
            scope.permission = utils.UserPermission.BotOwner
        elif message.author.guild_permissions.administrator:
            scope.permission = utils.UserPermission.Admin

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
            scope.permission = utils.UserPermission.Script
            scope.vars['target'] = member

            for plugin in self.shell.plugins:
                await plugin.on_member_join(scope)

        except discord.DiscordException:
            print(traceback.format_exc())
        else:
            print(traceback.format_exc())

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
            scope.permission = utils.UserPermission.Script
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
            print(traceback.format_exc())
        else:
            print(traceback.format_exc())

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
            #We see if the bot is the author of the ban
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

            #We create the scope
            scope = self.shell.create_scope(guild, [''])
            scope.channel = self.shell.get_default_channel(guild)
            scope.user = guild.me
            scope.permission = utils.UserPermission.Script
            scope.vars['reason'] = ban_reason
            scope.vars['user'] = ban_author
            scope.vars['target'] = ban_target

            #We send the event to all plugins
            for plugin in self.shell.plugins:
                await plugin.on_ban(scope)

        except discord.DiscordException:
            print(traceback.format_exc())
        else:
            print(traceback.format_exc())

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
            scope.permission = utils.UserPermission.Script
            scope.vars['target'] = user

            for plugin in self.shell.plugins:
                await plugin.on_unban(scope)

        except discord.DiscordException:
            print(traceback.format_exc())
        else:
            print(traceback.format_exc())


#############
##  Start  ##
#############

def main():
    """Start the bot."""
    with open('config.json', 'r', encoding="UTF-8") as f:
        config = json.load(f)
    token = config['token']
    dev_mode = config['dev_mode']

    try:
        bot = Sylvie(dev_mode)
        bot.run(token)
    except KeyboardInterrupt:
        bot.loop.run_until_complete(bot.logout())
        bot.loop.close()
        print("Bot closed.")
        sys.exit(0)


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