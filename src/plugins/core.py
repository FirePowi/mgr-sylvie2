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
# standard library
from typing import Optional, Union

# Thrid party modules
import discord
import discord.app_commands as app_commands
from dateutil.relativedelta import relativedelta
from pytz import timezone

# Local modules
import src.discord_parse as argparse
from src.utils import Plugin, command, slash_command


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
        self.add_command("say", self.execute_say)

    @app_commands.command(
        name="say",
        description="A command allowing you to send a message")
    async def slash_say(self,
                        interaction: discord.Interaction,
                        message: str,
                        recipient: Optional[Union[discord.abc.GuildChannel,
                                                  discord.User]],
                        reactions: Optional[list[Union[discord.Emoji,
                                                       discord.PartialEmoji]]],
                        title: Optional[str],
                        description: Optional[str],
                        footer: Optional[str],
                        footerimager: Optional[str],
                        thumbnail: Optional[str],
                        author: Optional[str],
                        authorimage: Optional[str],
                        authorurl: Optional[str],
                        fields: Optional[list[str]]):
        """
        A command allowing you to send a message.

        Args:
            interaction: The interaction.
            message: The message to send.
            recipient: The recipient of the message.
            reactions: The reactions to add to the message.
            title: The title of the embed.
            description: The description of the embed.
            footer: The footer of the embed.
            footerimager: The footer image of the embed.
            thumbnail: The thumbnail of the embed.
        """
        if not message:
            interaction.response.send_message(
                "You must specify a message",
                ephemeral=True)
            return

        # Where to send the message
        if not recipient:
            recipient = interaction.channel or interaction.user
        if isinstance(recipient, discord.User):
            if recipient.dm_channel is None:
                await recipient.create_dm()
            recipient = recipient.dm_channel
        if not isinstance(recipient, discord.abc.Messageable):
            recipient = interaction.channel or interaction.user.dm_channel
        if not recipient:
            interaction.response.send_message(
                "Could not find a channel to send the message to",
                ephemeral=True)
            return

        # Check permissions
        if not isinstance(recipient, discord.User):
            if not can_they_see:
                interaction.response.send_message(
                    "You do not have permission to send messages in this channel",
                    ephemeral=True)
                return

    @command(description="A command allowing you to send a message")
    async def execute_say(
        self,
        scope,
        command,
        options,
        lines,
        description=None):
        """Execute the 'say' command within a Discord context.

        Args:
            scope: The current scope (guild, channel, etc.).
            command: The command to execute (in this case, 'say').
            options: Options for the command.
            lines: Lines of text to send.
        """

        # Common arguments shared between main comman and subcommands
        common = argparse.ArgumentParser(add_help=False)
        common.add_argument(
            '--recipient',
            '-r',
            '--channel',
            '-c',
            dest='recipient',
            help="Recipient of the message (can be a channel or a member)",
            metavar='Recipient')
        common.add_argument(
            '--reactions',
            nargs='+',
            help='Emoji reactions to add',
            metavar='EMOJI')

        # Main parser
        parser = argparse.ArgumentParser(
            description=description, prog=command, parents=[common])
        parser.add_argument('message', nargs='?', help="Text to send")

        # Create a container for subparsers
        embed_subparser = parser.add_subparsers(
            required=False,
            title='Embed',
            description='Subcommand to send an Embed message',
            dest='subparser')
        # Create a subparser for embed arguments
        embed_parser = embed_subparser.add_parser(
            '--embed',
            help='embed subcommand',
            parents=[common])
        # Create embed arguments
        embed_parser.add_argument(
            'title',
            help='Embed title')
        embed_parser.add_argument(
            'description',
            nargs='?',
            help='Embed description')
        embed_parser.add_argument('footer', nargs='?', help='Embed footer')
        embed_parser.add_argument(
            '--author', nargs='?', help='Embed author name')
        embed_parser.add_argument(
            '--footerimage',
            '--fi',
            help='Embed footer image')
        embed_parser.add_argument('--image', '-i', help='Embed image')
        embed_parser.add_argument('--thumbnail', '-m', help='Embed thumbnail')
        embed_parser.add_argument('--authorimage', help='Embed author image')
        embed_parser.add_argument('--authorurl', help='Embed author URL')
        embed_parser.add_argument(
            '--fields', nargs="+", help='List of key/value')
        args = await self.parse_options(scope, parser, options)
        if not args:
            return

        if args.recipient:
            # recipient = scope.shell.find_channel(scope.format_text(args.channel).strip(), scope.guild)
            recipient = scope.shell.find_anything(
                scope.guild,
                'channels',
                joker=scope.format_text(args.recipient)
                )
            if not recipient:
                recipient = scope.shell.find_anything(
                    scope.guild,
                    'members',
                    joker=scope.format_text(args.recipient)
                    )
        else:
            recipient = scope.channel

        if not recipient:
            await scope.shell.print(
                scope, 
                f"Unknown channel or member `{args.recipient}`",
                'error')
            return

        if scope.permission < utils.UserPermission.Script and (isinstance(
                recipient, discord.abc.GuildChannel) and not recipient.permission_for(scope.user)):
            await scope.shell.print(scope, "You don't have write permission in this channel.", 'permission')
            return

        if scope.permission < utils.UserPermission.Script and isinstance(
                recipient, discord.User):
            await scope.shell.print(scope, "You don't have permission to send DMs using the bot.", 'permission')
            return

        subscope = scope.create_subscope()
        subscope.channel = recipient
        sftxt = subscope.format_text

        formated_text = ""
        if args.message:
            message = " ".join(
                args.message) if isinstance(
                args.message,
                list) else args.message
            formated_text = sftxt(message)
        if args.message_extra:
            message = " ".join(
                args.message_extra) if isinstance(
                args.message_extra,
                list) else args.message_extra
            formated_text += sftxt(message)

        embed = None
        if any([
                args.title,
                args.description,
                args.footer,
                args.footerimage,
                args.image,
                args.thumbnail,
                args.author,
                args.authorimage,
                args.authorurl,
                args.fields]):
            embed = discord.Embed()
            embed.type = 'rich'

            embed.title = sftxt(args.title) if args.title else None
            embed.description = sftxt(args.description) if args.title else None
            embed.set_image(url=sftxt(args.image)) if args.image else None
            embed.set_thumbnail(url=sftxt(args.thumbnail)
                                ) if args.thumbnail else None

            # Set the footer if applicable
            footer_params = {}
            if args.footer:
                footer_params['text'] = sftxt(args.footer)
            if args.footerimage:
                footer_params['icon_url'] = sftxt(args.footerimage)
            # If any of the footer params are set, set the footer
            if footer_params:
                embed.set_footer(**footer_params)

            # Set the author if applicable
            author_params = {}
            if args.author:
                author_params['name'] = sftxt(args.author)
            if args.authorimage:
                author_params['icon_url'] = sftxt(args.authorimage)
            if args.authorurl:
                author_params['url'] = sftxt(args.authorurl)
            # If any of the author params are set, set the author
            if author_params:
                embed.set_author(**author_params)

            # Set the fields if applicable
            for field in args.fields:
                field_key, field_value = field.split('=')
                embed.add_field(
                    name=sftxt(field_key),
                    value=sftxt(field_value)
                    )

        if embed or len(formated_text.strip()) > 0:
            msg = await subscope.channel.send(formated_text, embed=embed)
            for emoji in args.reactions:
                await msg.add_reaction(emoji)
