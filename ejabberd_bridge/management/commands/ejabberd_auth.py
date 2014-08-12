#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (C) 2013  Fabio Falcinelli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import logging
import struct
import sys
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

__author__ = "fabio"


AT_REPLACE_CHAR = '%'


class Command(BaseCommand):
    logger = logging.getLogger(__name__)

    def from_ejabberd(self, encoding="utf-8"):
        """
        Reads data from stdin as passed by eJabberd
        """
        input_length = sys.stdin.read(2).encode(encoding)
        (size,) = struct.unpack(">h", input_length)
        return sys.stdin.read(size).split(":")

    def to_ejabberd(self, answer=False):
        """
        Converts the response into eJabberd format
        """
        b = struct.pack('>hh',
                        2,
                        1 if answer else 0)
        self.logger.debug("To jabber: %s" % b)
        sys.stdout.write(b.decode("utf-8"))
        sys.stdout.flush()

    def auth(self, username=None, server="localhost", password=None, at_replaced=False):
        self.logger.debug("Authenticating %s with password %s on server %s" % (username, password, server))
        #TODO: would be nice if this could take server into account
        user = authenticate(username=username, password=password)
        authorized = user and user.is_active

        if not (authorized or at_replaced): # NOR gate
            username = '@'.join(username.split(AT_REPLACE_CHAR))
            authorized = self.auth(username, server, password, True)

        return authorized

    def isuser(self, username=None, server="localhost", at_replaced=False):
        """
        Checks if the user exists and is active
        """
        self.logger.debug("Validating %s on server %s" % (username, server))
        #TODO: would be nice if this could take server into account
        try:
            user = get_user_model().objects.get(username=username)
            if user.is_active:
                exists = True
            else:
                self.logger.warning("User %s is disabled" % username)
                exists = False
        except User.DoesNotExist:
            exists = False

        if not (exists or at_replaced): # ^(a or b) == (^a) and (^b)
            username = '@'.join(username.split(AT_REPLACE_CHAR))
            exists = self.isuser(username, server, True)

        return exists

    def setpass(self, username=None, server="localhost", password=None):
        """
        Handles password change
        """
        self.logger.debug("Changing password to %s with new password %s on server %s" % (username, password, server))
        #TODO: would be nice if this could take server into account
        try:
            user = get_user_model().objects.get(username=username)
            user.set_password(password)
            user.save()
            return True
        except User.DoesNotExist:
            return False

    def handle(self, *args, **options):
        """
        Gathers parameters from eJabberd and executes authentication
        against django backend
        """
        #logging.basicConfig(
        #    level="DEBUG",
        #    format='%(asctime)s %(levelname)s %(message)s',
        #    filename="/usr/local/var/log/ejabberd/django-bridge.log",
        #    filemode='a')

        self.logger.debug("Starting serving authentication requests for eJabberd")
        success = False
        try:
            while True:
                data = self.from_ejabberd()
                command, username, args = data[0], data[1], data[2:]

                self.logger.debug("Command is %s" % command)
                if command == "auth":
                    success = self.auth(username, args[0], args[1])
                elif command == "isuser":
                    success = self.isuser(username, args[0])
                elif command == "setpass":
                    success = self.setpass(username, args[0], args[1])
                self.to_ejabberd(success)
                if not options.get("run_forever", True):
                    break
        except Exception as e:
            self.logger.error("An error has occurred during eJabberd external authentication: %s" % e)
            self.to_ejabberd(success)
