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
import re
from typing import Optional, Union
import copy
import inspect
import datetime
import shlex
import discord
from discord import app_commands

from src import homeparse as argparse
# import discord_parse as argparse
from pytz import timezone
from dateutil.relativedelta import relativedelta
from src import utils
from io import StringIO
import asyncio


class CorePlugin(utils.Plugin):
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

    @command(name='say')
    # @app_commands.describe()
    async def slash_say(self,
                        interaction: discord.Interaction,
                        message: str,
                        recipient: Optional[Union[discord.abc.GuildChannel, discord.User]],
                        reactions: Optional[list[Union[discord.Emoji, discord.PartialEmoji, str]]],
                        title: Optional[str],
                        description: Optional[str],
                        footer: Optional[str],
                        footerimager: Optional[str],
                        thumbnail: Optional[str],
                        author: Optional[str],
                        authorimage: Optional[str],
                        authorurl: Optional[str],
                        fields: Optional[list[str]]
                        ):
        """"""
        "A command allowing you to send a message"
        if not recipient:
            pass

    def generate_say_arguments(subcommand=None):
        common_args = {
            'recipient':
            {
                'name': 'recipient', 'aliases': ['c', 'channel', 'r'],
                'description': 'Recipient of the message (can be a channel or a member).',
                'type': Union[discord.abc.GuildChannel, discord.User], 'optional': True
            },
            'reactions':
            {
                'name': 'reactions', 'aliases': None,
                'description': 'Reactions to add to the message after sending it.',
                'type': Optional[list[Union[discord.Emoji, discord.PartialEmoji, str]]]
            }
        }
        if not subcommand:
            subcommand_args = {
                'message':
                {
                    'name': 'message',
                    'aliases': None,
                    'description': 'Message to be sent.',
                    'type': str
                }

            }
        if subcommand == 'embed':
            subcommand_args = {
                'title':
                {
                    'name': 'title',
                    'aliases': None,
                    'description': 'Title of the Embed',
                    'type': str
                },
                'description':
                {
                    'name': 'description',
                    'aliases': None,
                    'description': 'Description of the Embed',
                    'type': str
                },
                'footer':
                {
                    'name': 'footer',
                    'aliases': None,
                    'description': 'Footer of the Embed',
                    'type': str
                },
                'footerimage':
                {
                    'name': 'footerimage',
                    'aliases': ['fi'],
                    'description': 'Footer image of the Embed',
                    'type': Optional[str]
                },
                'image':
                {
                    'name': 'image',
                    'aliases': ['i'],
                    'description': 'Image of the Embed',
                    'type': Optional[str]
                },
                'thumbnail':
                {
                    'name': 'thumbnail',
                    'aliases': ['m'],
                    'description': 'Thumbnail of the Embed',
                    'type': Optional[str]
                },
                'author':
                {
                    'name': 'author',
                    'aliases': None,
                    'description': 'Author of the Embed',
                    'type': Optional[str]
                },
                'authorimage':
                {
                    'name': 'authorimage',
                    'aliases': None,
                    'description': 'Author image of the Embed',
                    'type': Optional[str]
                },
                'authorurl':
                {
                    'name': 'authorurl',
                    'aliases': None,
                    'description': 'Author URL of the Embed',
                    'type': Optional[str]
                },
                'fields':
                {
                    'name': 'fields',
                    'aliases': None,
                    'description': 'List of key/value',
                    'type': Optional[list[str]]
                }

            }

        return common_args

    @utils.command(description="A command allowing you to send a message")
    async def execute_say(self, scope, command, options, lines, description=None):
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
            description='Subcommand to send an Embed message instead of a regular message',
            dest='subparser')
        # Create a subparser for embed arguments
        embed_parser = embed_subparser.add_parser(
            'embed', help='embed subcommand', parents=[common])
        # Create embed arguments
        embed_parser.add_argument('title', help='Embed title')
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
            recipient = scope.shell.find_anything(scope.guild, 'channels', joker=scope.format_text(args.recipient)) or \
                scope.shell.find_anything(
                scope.guild,
                'members',
                joker=scope.format_text(
                    args.recipient))
        else:
            recipient = scope.channel

        if not recipient:
            await scope.shell.print(scope, f"Unknown channel or member `{args.recipient}`", 'error')
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
        if any([args.title, args.description, args.footer, args.footerimage, args.image,
               args.thumbnail, args.author, args.authorimage, args.authorurl, args.fields]):
            embed = discord.Embed()
            embed.type = 'rich'

            embed.title = sftxt(args.title) if args.title else None
            embed.description = sftxt(args.description) if args.title else None
            embed.set_image(url=sftxt(args.image)) if args.image else None
            embed.set_thumbnail(url=sftxt(args.thumbnail)
                                ) if args.thumbnail else None

            footer_params = {'text': sftxt(args.footer) if args.footer else None,
                             'icon_url': sftxt(args.footerimage) if args.footerimage else None}
            if any([footer_params.get('text'), footer_params.get('icon_url')]):
                embed.set_footer(**footer_params)

            author_params = {'name': sftxt(args.author) if args.author else None,
                             'icon_url': sftxt(args.authorimage) if args.authorimage else None,
                             'url': sftxt(args.authorurl) if args.authorurl else None}
            if any([author_params.get('name'), author_params.get(
                    'icon_url'), author_params.get('url')]):
                embed.set_author(**author_params)

            if args.fields:
                field_key = None
                for field in args.fields:
                    if not field_key:
                        field_key = field
                    else:
                        embed.add_field(
                            name=sftxt(field_key), value=sftxt(field))

        if embed or len(formated_text.strip()) > 0:
            msg = await subscope.channel.send(formated_text, embed=embed)
            if args.reactions:
                for emoji in args.reactions:
                    await msg.add_reaction(emoji)
