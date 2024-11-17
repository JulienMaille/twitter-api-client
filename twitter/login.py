import random
import sys

from httpx import Client

from .constants import YELLOW, RED, BOLD, RESET, USER_AGENTS, TASK_URL, GUEST_TOKEN_URL
from .util import find_key

def update_token(client: Client, key: str, url: str, **kwargs) -> Client:
    caller_name = sys._getframe(1).f_code.co_name
    try:
        headers = {
            'x-guest-token': client.cookies.get('guest_token', ''),
            'x-csrf-token': client.cookies.get('ct0', ''),
            'x-twitter-auth-type': 'OAuth2Client' if client.cookies.get('auth_token') else '',
        }
        client.headers.update(headers)
        r = client.post(url, **kwargs)
        info = r.json()

        for task in info.get('subtasks', []):
            subtask_id = task.get('subtask_id')
            print(f"[{YELLOW}warning{RESET}] subtask_id: {subtask_id} ({caller_name})")
            if task.get('enter_text', {}).get('keyboard_type', '') == 'email':
                print(f"[{YELLOW}warning{RESET}] {' '.join(find_key(task, 'text'))}")
                client.cookies.set('confirm_email', 'true')  # signal that email challenge must be solved

            if subtask_id == 'DenyLoginSubtask' or subtask_id == 'ArkoseLogin':
                print(f'[{RED}error{RESET}] failed to login{RESET}')
                client.cookies.set('login_failed', 'true')
            
            if subtask_id == 'LoginAcid':
                if task.get('enter_text', {}).get('hint_text', '').casefold() == 'confirmation code':
                    print(f"[{YELLOW}warning{RESET}] email confirmation code challenge.")
                    client.cookies.set('confirmation_code', 'true')

        client.cookies.set(key, info[key])

    except KeyError as e:
        client.cookies.set('flow_errors', 'true')  # signal that an error occurred somewhere in the flow
        print(f'[{RED}error{RESET}] failed to update token at {BOLD}{caller_name}{RESET}\n{e}')
    return client


def init_guest_token(client: Client) -> Client:
    return update_token(client, 'guest_token', GUEST_TOKEN_URL)


def flow_start(client: Client) -> Client:
    return update_token(client, 'flow_token', TASK_URL,
                        params={'flow_name': 'login'},
                        json={
                            "input_flow_data": {
                                "flow_context": {
                                    "debug_overrides": {},
                                    "start_location": {"location": "splash_screen"}
                                }
                            }, "subtask_versions": {}
                        })


def flow_instrumentation(client: Client) -> Client:
    return update_token(client, 'flow_token', TASK_URL, json={
        "flow_token": client.cookies.get('flow_token'),
        "subtask_inputs": [{
            "subtask_id": "LoginJsInstrumentationSubtask",
            "js_instrumentation": {"response": "{\"rf\":{\"a4fc506d24bb4843c48a1966940c2796bf4fb7617a2d515ad3297b7df6b459b6\":121,\"bff66e16f1d7ea28c04653dc32479cf416a9c8b67c80cb8ad533b2a44fee82a3\":-1,\"ac4008077a7e6ca03210159dbe2134dea72a616f03832178314bb9931645e4f7\":-22,\"c3a8a81a9b2706c6fec42c771da65a9597c537b8e4d9b39e8e58de9fe31ff239\":-12},\"s\":\"ZHYaDA9iXRxOl2J3AZ9cc23iJx-Fg5E82KIBA_fgeZFugZGYzRtf8Bl3EUeeYgsK30gLFD2jTQx9fAMsnYCw0j8ahEy4Pb5siM5zD6n7YgOeWmFFaXoTwaGY4H0o-jQnZi5yWZRAnFi4lVuCVouNz_xd2BO2sobCO7QuyOsOxQn2CWx7bjD8vPAzT5BS1mICqUWyjZDjLnRZJU6cSQG5YFIHEPBa8Kj-v1JFgkdAfAMIdVvP7C80HWoOqYivQR7IBuOAI4xCeLQEdxlGeT-JYStlP9dcU5St7jI6ExyMeQnRicOcxXLXsan8i5Joautk2M8dAJFByzBaG4wtrPhQ3QAAAZEi-_t7\"}", "link": "next_link"}
        }],
    })


def flow_username(client: Client) -> Client:
    return update_token(client, 'flow_token', TASK_URL, json={
        "flow_token": client.cookies.get('flow_token'),
        "subtask_inputs": [{
            "subtask_id": "LoginEnterUserIdentifierSSO",
            "settings_list": {
                "setting_responses": [{
                    "key": "user_identifier",
                    "response_data": {"text_data": {"result": client.cookies.get('username')}}
                }], "link": "next_link"}}],
    })


def flow_password(client: Client) -> Client:
    return update_token(client, 'flow_token', TASK_URL, json={
        "flow_token": client.cookies.get('flow_token'),
        "subtask_inputs": [{
            "subtask_id": "LoginEnterPassword",
            "enter_password": {"password": client.cookies.get('password'), "link": "next_link"}}]
    })


def flow_duplication_check(client: Client) -> Client:
    return update_token(client, 'flow_token', TASK_URL, json={
        "flow_token": client.cookies.get('flow_token'),
        "subtask_inputs": [{
            "subtask_id": "AccountDuplicationCheck",
            "check_logged_in_account": {"link": "AccountDuplicationCheck_false"},
        }],
    })


def confirm_email(client: Client) -> Client:
    return update_token(client, 'flow_token', TASK_URL, json={
        "flow_token": client.cookies.get('flow_token'),
        "subtask_inputs": [
            {
                "subtask_id": "LoginAcid",
                "enter_text": {
                    "text": client.cookies.get('email'),
                    "link": "next_link"
                }
            }]
    })


def solve_confirmation_challenge(client: Client, **kwargs) -> Client:
    if fn := kwargs.get('proton'):
        confirmation_code = fn()
        return update_token(client, 'flow_token', TASK_URL, json={
            "flow_token": client.cookies.get('flow_token'),
            'subtask_inputs': [
                {
                    'subtask_id': 'LoginAcid',
                    'enter_text': {
                        'text': confirmation_code,
                        'link': 'next_link',
                    },
                },
            ],
        })


def execute_login_flow(client: Client, **kwargs) -> Client | None:
    client = init_guest_token(client)
    for fn in [flow_start, flow_instrumentation, flow_username, flow_password, flow_duplication_check]:
        client = fn(client)

    # login failed
    if client.cookies.get('login_failed') == 'true':
        return

    # solve email challenge
    if client.cookies.get('confirm_email') == 'true':
        client = confirm_email(client)

    # solve confirmation challenge (Proton Mail only)
    if client.cookies.get('confirmation_code') == 'true':
        if not kwargs.get('proton'):
            print(f'[{RED}warning{RESET}] Please check your email for a confirmation code'
                  f' and log in again using the web app. If you wish to automatically solve'
                  f' email confirmation challenges, add a Proton Mail account in your account settings')
            return
        client = solve_confirmation_challenge(client, **kwargs)
    return client


def login(email: str, username: str, password: str, **kwargs) -> Client:
    client = Client(
        cookies={
            "email": email,
            "username": username,
            "password": password,
            "guest_token": None,
            "flow_token": None,
        },
        headers={
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'content-type': 'application/json',
            'user-agent': kwargs.get('user_agent', random.choice(USER_AGENTS)),
            'x-twitter-active-user': 'yes',
            'x-twitter-client-language': 'en',
        },
        follow_redirects=True
    )
    client = execute_login_flow(client, **kwargs)
    if not client or client.cookies.get('flow_errors') == 'true':
        raise Exception(f'[{RED}error{RESET}] {BOLD}{username}{RESET} login failed')
    return client
