# mas-token - A maubot plugin to manage your synapse registration tokens via MAS
# this is a fork of the maubot-token plugin by Michael Auer
#
# Copyright (C) 2026 Cassie Wintermute
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper
from maubot import Plugin, MessageEvent
from maubot.handlers import command

import json
import time
import datetime
from typing import Type

error_msg_no_auth = "My mom said I'm not allowed to talk to strangers."
token_msg = """
**{}**\n
- uses_allowed: {}\n
- valid: {}\n
- completed: {}\n
- expiry_time: {}\n
"""


class Config(BaseProxyConfig):

    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("access_token")
        helper.copy("base_command")
        helper.copy("whitelist")
        helper.copy("admin_api")
        helper.copy("default_uses_allowed")
        helper.copy("default_expiry_time")


def parse_single_token(token):
    expiry_time = token["data"]["attributes"]["expires_at"]
    #if expiry_time:
    #    expiry_time = datetime.datetime.fromtimestamp(expiry_time / 1000.0)
    return token_msg.format(token["data"]["attributes"]["token"], token["data"]["attributes"]["usage_limit"],
                            token["data"]["attributes"]["valid"], token["data"]["attributes"]["expires_at"], expiry_time)


def parse_tokens(json):
    valid_tokens = "\u2705 Valid Tokens \u2705\n"
    invalid_tokens = "\u274C Invalid Tokens \u274C\n"
    # To-Do: Rewrite to just check for token["attributes"]["valid"] lol
    for token in json["data"]:
        valid = True
        if token["attributes"]["usage_limit"]:
            valid = valid and token["attributes"]["times_used"] < token["attributes"]["usage_limit"]
        if token["attributes"]["expires_at"]:
            valid = valid and datetime.datetime.fromisoformat(token["attributes"]["expires_at"][:-1]) > datetime.datetime.now()
        if token["attributes"]["revoked_at"]:
            valid = False        
        if valid:
            valid_tokens += "- {}\n".format(token["attributes"]["token"])
        else:
            invalid_tokens += "- {}\n".format(token["attributes"]["token"])
    return invalid_tokens + "\n" + valid_tokens


class TokenBot(Plugin):

    def authenticate(self, user):
        if user in self.config["whitelist"]:
            return True
        return False

    @classmethod
    def get_config_class(cls) -> Type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        self.config.load_and_update()

    # The Matrix Authentication Service uses an internal ID number differant
    # than the given token. This function isn't the most effecient, and may
    # start to be a problem on larger lists of tokens, but for now it works.
    async def _get_token_id(self, base_url, access_token, tokenID):
        url = base_url + '/v1/user-registration-tokens'
        payload = '{}'
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        url += "?page[first]=1000" # Fix for auth API only returning 10 by default -_-
        r = await self.http.get(url, data=payload, headers=headers)
        if (r.status != 200):
            return False, "ERROR: {}".format(r.status)
        resp = await r.json()
        for token in resp["data"]:
            if token["attributes"]["token"] == tokenID:
                return True, token["id"]
        return False, ""

    async def _get_token(self, base_url, access_token, tokenID):
        url = base_url + '/v1/user-registration-tokens'
        if tokenID:
            ret, realTokenID = await self._get_token_id(base_url, access_token, tokenID)
            if ret:
                tokenID = realTokenID
        if tokenID:
            url += "/{}".format(tokenID)
        url += "?page[first]=1000" # Fix for auth API only returning 10 by default -_-
        payload = '{}'
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        r = await self.http.get(url, data=payload, headers=headers)
        if (r.status != 200):
            return False, "ERROR: {}".format(r.status)
        return True, await r.json()

    async def _gen_token(self, base_url, access_token, uses_allowed,
                         expiry_time):
        url = base_url + '/v1/user-registration-tokens'
        payload = {}
        if uses_allowed >= 0:
            payload["usage_limit"] = uses_allowed
        if expiry_time:
            # DateTime Format: 2026-02-23T19:00:00Z
            payload["expires_at"] = expiry_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        r = await self.http.post(url,
                                 data=json.dumps(payload),
                                 headers=headers)
        if (r.status != 201):
            return False, "ERROR: {}".format(r.status)
        return True, await r.json()

    async def _del_token(self, base_url, access_token, tokenID):
        ret, realTokenID = await self._get_token_id(base_url, access_token, tokenID)
        if ret:
            tokenID = realTokenID        
        url = base_url + '/v1/user-registration-tokens/{}/revoke'.format(tokenID)
        payload = '{}'
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        r = await self.http.post(url, data=payload, headers=headers)
        if (r.status != 200):
            return False, "ERROR: {}".format(r.status)
        return True, ""

    async def _undel_token(self, base_url, access_token, tokenID):
        ret, realTokenID = await self._get_token_id(base_url, access_token, tokenID)
        if ret:
            tokenID = realTokenID        
        url = base_url + '/v1/user-registration-tokens/{}/unrevoke'.format(tokenID)
        payload = '{}'
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        r = await self.http.post(url, data=payload, headers=headers)
        if (r.status != 200):
            return False, "ERROR: {}".format(r.status)
        return True, ""




    @command.new(name=lambda self: self.config["base_command"],
                 help="List available Tokens",
                 require_subcommand=True)
    async def token(self, event: MessageEvent) -> None:
        pass

    @token.subcommand(name="list", help="List all [or specific] Tokens")
    @command.argument("token", required=False, pass_raw=True)
    async def list_tokens(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        ret, available_token = await self._get_token(
            self.config["admin_api"], self.config["access_token"], token)
        msg = ""
        if ret:
            if token:
                msg = parse_single_token(available_token)
            else:
                msg = parse_tokens(available_token)
        else:
            msg = available_token
        await event.reply(msg)

    @token.subcommand(name="generate", help="Generate a Token")
    @command.argument("uses",
                      parser=lambda val: int(val) if val else None,
                      required=False)
    @command.argument("expiry",
                      parser=lambda val: int(val) if val else None,
                      required=False)
    async def generate_token(self, event: MessageEvent, uses: int,
                             expiry: int) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        if not uses:
            uses = self.config["default_uses_allowed"]
        if not expiry:
            expiry = self.config["default_expiry_time"]
        expiry = datetime.datetime.now() + datetime.timedelta(0,expiry)
        ret, available_token = await self._gen_token(
            self.config["admin_api"], self.config["access_token"], uses,
            expiry)
        msg = ""
        if ret:
            msg = parse_single_token(available_token)
        else:
            msg = available_token
        await event.reply(msg)

    @token.subcommand(name="delete", help="Delete a Token")
    @command.argument("token", required=True, pass_raw=True)
    async def delete_token(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        ret, available_token = await self._del_token(
            self.config["admin_api"], self.config["access_token"], token)
        msg = "Token deleted!"
        if not ret:
            msg = available_token
        await event.reply(msg)

    @token.subcommand(name="undelete", help="Undelete a Token")
    @command.argument("token", required=True, pass_raw=True)
    async def undelete_token(self, event: MessageEvent, token: str) -> None:
        if not self.authenticate(event.sender):
            await event.reply(error_msg_no_auth)
            return
        ret, available_token = await self._undel_token(
            self.config["admin_api"], self.config["access_token"], token)
        msg = "Token undeleted!"
        if not ret:
            msg = available_token
        await event.reply(msg)
