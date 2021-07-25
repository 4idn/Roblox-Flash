# -*- coding: utf-8 -*-

import os
import httpx
import asyncio
import operator

from enum import IntEnum, unique
from dataclasses import dataclass

from itertools import count
from functools import reduce, wraps, partial
from contextlib import AbstractAsyncContextManager

from typing import (
    Awaitable,
    Optional,
    Type,
    Dict,
    Any,
    ClassVar, 
    List, 
    Union, 
    Callable,
    TypeVar,
    TypedDict,
    get_type_hints, 
    get_origin, 
    get_args
)

@unique
class UserPresenceType(IntEnum):
    OFFLINE = 0
    ONLINE  = 1
    PLAYING = 2
    STUDIO  = 3 # Unchecked


@dataclass
class UserPresence:
    gameId: Optional[str]
    lastLocation: str
    lastOnline: str
    placeId: Optional[int]
    rootPlaceId: Optional[int]
    universeId: Optional[int]
    userId: int
    userPresenceType: int

    @property
    def presence(self) -> UserPresenceType:
        return UserPresenceType(self.userPresenceType)


class TokenRequiredError(Exception):
    pass


class SessionRequiredError(Exception):
    pass


class Roblox(AbstractAsyncContextManager):
    __slots__ = '_client'

    BASE_URL: ClassVar[str] = "https://www.roblox.com/"

    def __init__(self, client: Optional[httpx.AsyncClient] = None, **kwargs):
        self._client = client or httpx.AsyncClient(**kwargs)

    @classmethod
    def authorise(cls: Type['Roblox'], session: str, **kwargs) -> 'Roblox':
        rbx = cls(**kwargs); rbx.session = session
        return rbx

    def required(**attrs: Dict[str, Type]):
        """
            Check if attribute is set and if not raises Exception. Place in order of priority.
        """
        def decorator(fn: Callable[..., Awaitable[Any]]):
            @wraps(fn)
            async def wrapper(self: 'Roblox', *args, **kwargs):
                it = (v for k, v in attrs.items() if not getattr(self, k))
                if exc_type := next(it, False):
                    raise exc_type
                return await fn(self, *args, **kwargs)
            return wrapper
        return decorator

    token_required = partial(required, token=TokenRequiredError)
    authentication_required = partial(required, session=SessionRequiredError)

    def from_json_response(*keys: List[str]):
        """
            Converts json response into return type's type annotation.

            If the functions return type is a list then the json will be converted into
            a list of the list's inner type else will attempt to convert from the dict
            to the object.
        """
        def decorator(fn: Callable[..., Awaitable[httpx.Response]]):
            T = TypeVar('T')

            @wraps(fn)
            async def wrapper(*args, **kwargs) -> T:
                r = await fn(*args, **kwargs)
                json = reduce(operator.getitem, keys, r.json())
                if typing := get_type_hints(fn)["return"]:
                    if typing is list or get_origin(typing) is list:
                        inner, = get_args(typing)
                        return [inner(**o) for o in json]
                    return typing(**json)
                return json
            return wrapper
        return decorator

    async def recieve_token(self) -> None:
        """
           Recieve csrf-token and initial token.
        """
        r = await self.client.post("https://auth.roblox.com/v2/login")
        self.token = r.headers["X-CSRF-TOKEN"]

    @token_required()
    @authentication_required()
    async def authentication_ticket(self) -> str:
        r = await self.client.post("https://auth.roblox.com/v1/authentication-ticket", headers={"Referer": self.BASE_URL})
        return r.headers["rbx-authentication-ticket"]

    @from_json_response("userPresences")
    async def users_presences(self, *ids: List[Union[str, int]]) -> List[UserPresence]:
        """
            Returns list of UserPresences
        """
        return await self.client.post("https://presence.roblox.com/v1/presence/users", json={"userIds": list(set(ids))})

    @property
    def token(self) -> Optional[str]:
        return self.client.headers.get("x-csrf-token")

    @token.setter
    def token(self, value: str) -> None:
        self.client.headers["x-csrf-token"] = value

    @property
    def session(self) -> Optional[str]:
        return self.client.cookies.get(".ROBLOSECURITY")

    @session.setter
    def session(self, value: str) -> None:
        self.client.cookies[".ROBLOSECURITY"] = value

    @property
    def client(self) -> httpx.AsyncClient:
        return self._client

    async def close(self) -> None:
        await self.client.aclose()

    async def __aexit__(self, *_) -> None:
        await self.close()


LaunchOptions = TypedDict('LaunchOptions', {"roblox-player": int, "launchmode": str, "gameinfo": str, "placelauncherurl": str})

def join(user_id: Union[str, int], ticket: str) -> None:
    url = httpx.URL("https://assetgame.roblox.com/game/PlaceLauncher.ashx").copy_merge_params({
        "request": "RequestFollowUser",
        "userId": user_id,
    })

    options = LaunchOptions({
        "roblox-player": 1,
        "launchmode": "play",
        "gameinfo": ticket,
        "placelauncherurl": url
    })

    options = '+'.join(f"{k}:{v!s}" for k, v in options.items())
    os.startfile(options) # Launch game via URL protocol
    
    print(f"Launched game with {options=}")
    

async def main(token: str, user_id: Union[str, int], timeout: Optional[float]=None):
    async with Roblox.authorise(token, timeout=timeout) as roblox:
        await roblox.recieve_token()

        for checks in count():
            presence, = await roblox.users_presences(user_id)

            if presence.userPresenceType == UserPresenceType.PLAYING:
                join(user_id, await roblox.authentication_ticket())
                break

            if (checks % 50) == 0:
                print(f"\rMade {checks} checks to see whether user has joined game", end='')


if __name__ == "__main__":
    from argparse import ArgumentParser
    
    parser = ArgumentParser()
    parser.add_argument("security", help="Roblox security cookie.")
    parser.add_argument("id", help="Id of user who you are trying to join.")
    parser.add_argument("--timeout", help="Timeout for HTTP requests. None by default", type=float, default=None)
    args = parser.parse_args()
    
    asyncio.run(main(args.security, args.id, args.timeout))
