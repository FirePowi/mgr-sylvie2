"""
Developper of the former "Sylvie" used as based for this bot
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
from typing import Optional

# Thrid party modules
import discord
from dateutil.relativedelta import relativedelta
from pytz import timezone

# Local modules
from utils import Plugin


class CorePlugin(Plugin):
    """
    Core Commands
    """

    name = "Core"

    def command(self, *args, **kwargs):
        """
        Is an redirect to discord.tree.command
        """
        self.shell.tree.command(*args, **kwargs)

    def __init__(self, shell):
        super().__init__(shell)
        # self.add_command("say", self.execute_say)

    async def on_ready(self, scope):
        """
        When the bot is ready, add the slash commands.
        """
        await self.add_slash_command(name="say", callback=self.say, description="Send a message.")

    async def say(
            self,
            interaction: discord.Interaction,
            message: str,
            channel: Optional[discord.abc.GuildChannel],
            user: Optional[discord.User],
            reactions: Optional[str],
            title: Optional[str],
            description: Optional[str],
            footer: Optional[str],
            footerimager: Optional[str],
            thumbnail: Optional[str],
            author: Optional[str],
            authorimage: Optional[str],
            authorurl: Optional[str],
            fields: Optional[str]
            ):
        """
        A command allowing you to send a message.

        Args:
            interaction: The interaction.
            message: The message to send.
            channel: The channel to send the message in.
            user: The user to send the message to.
            reactions: The reactions to add to the message.
            title: The title of the embed.
            description: The description of the embed.
            footer: The footer of the embed.
            footerimager: The footer image of the embed.
            thumbnail: The thumbnail of the embed.
        """
        if not message:
            await interaction.response.send_message(
                "You must specify a message",
                ephemeral=True)
            return

        # Where to send the message
        recipient = channel or user or None
        if not recipient:
            recipient = interaction.channel or interaction.user
        if user and not channel:
            if recipient.dm_channel is None:
                await recipient.create_dm()
            recipient = recipient.dm_channel
        if not recipient:
            await interaction.response.send_message(
                "Could not find a channel to send the message to",
                ephemeral=True)
            return

        # Check permissions
        # Case 0: User is the bot owner, no permissions required
        # Case 1: Recipient is a channel, user must have permission to send messages in the channel
        # Case 2: Recipient is a user, user must have admin permissions
        if interaction.user == self.shell.client.owner:
            pass
        elif isinstance(recipient, discord.abc.GuildChannel):
            if not recipient.permissions_for(interaction.user).send_messages:
                await interaction.response.send_message(
                    "You do not have permission to send messages in that channel",
                    ephemeral=True)
                return
        elif isinstance(recipient, discord.Member):
            if not interaction.user.guild_permissions.administrator:
                await interaction.response.send_message(
                    "You do not have permission to send messages to that user",
                    ephemeral=True)
                return

        embed = None
        # Create the embed if applicable: Check if any of the embed arguments are set
        if any([title,
                description,
                footer,
                footerimager,
                thumbnail,
                author,
                authorimage,
                authorurl,
                fields]):
            embed = discord.Embed()
            embed.type = 'rich'

            embed.title = title
            embed.description = description
            embed.set_thumbnail(url=thumbnail)

            # Set the footer if applicable
            footer_params = {}
            if footer:
                footer_params['text'] = footer
            if footerimager:
                footer_params['icon_url'] = footerimager
            # If any of the footer params are set, set the footer
            if footer_params:
                embed.set_footer(**footer_params)

            # If any of the author params are set, set the author
            if author or authorimage or authorurl:
                embed.set_author(name=author, icon_url=authorimage, url=authorurl)

            # Set the fields if applicable
            for field in fields or []:
                field_key, field_value = field.split('=')
                embed.add_field(
                    name=field_key,
                    value=field_value
                    )

        # Send the message
        message = await recipient.send(message, embed=embed)
        if reactions:
            for reaction in reactions:
                await message.add_reaction(reaction)

        await interaction.response.send_message(
            "Message sent",
            ephemeral=True
            )
