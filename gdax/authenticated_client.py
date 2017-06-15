#
# GDAX/AuthenticatedClient.py
# Daniel Paquin
#
# For authenticated requests to the GDAX exchange

import hmac
import hashlib
import time
import requests
import base64
import json
from requests.auth import AuthBase
from gdax.public_client import PublicClient


class AuthenticatedClient(PublicClient):
    def __init__(self, key, b64secret, passphrase,
                 api_url="https://api.gdax.com"):
        super(self.__class__, self).__init__(api_url)
        self.auth = GdaxAuth(key, b64secret, passphrase)

    def get_account(self, account_id):
        r = requests.get(self.url + '/accounts/' + account_id, auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_accounts(self):
        return self.get_account('')

    def get_account_history(self, account_id, **kwargs):
        url = self.url + '/accounts/{}/ledger'.format(account_id)
        return self._get_paginated_response(url, kwargs)[0]

    def get_account_holds(self, account_id, **kwargs):
        url = self.url + '/accounts/{}/holds'.format(account_id)
        return self._get_paginated_response(url, kwargs)[0]

    # TODO: buy and sell are woefully incomplete

    def place_order(self, product_id, side, order_type, **kwargs):
        # Check for illegal combinations
        if kwargs.get('overdraft_enabled') is not None and \
                        kwargs.get('funding_amount') is not None:
            raise ValueError('Margin funding must be specified through use of '
                             'overdraft or by setting a funding amount, but not'
                             ' both')

        # Build params dict
        params = {'product_id': product_id,
                  'side': side,
                  'type': order_type
                  }
        params.update(kwargs)
        r = requests.post(self.url + '/orders',
                          data=json.dumps(params), auth=self.auth)
        return r.json()

    def place_limit_order(self, product_id, side, price, size,
                          client_oid=None,
                          self_trade_prevention=None,
                          time_in_force=None,
                          cancel_after=None,
                          post_only=None):
        # Check for illegal combinations
        if cancel_after is not None and time_in_force != 'GTT':
            raise ValueError('May only specify a cancel period when time_in_'
                             'force is `GTT`')
        if post_only is not None and time_in_force in ['IOC', 'FOK']:
            raise ValueError('post_only is invalid when time_in_force is `IOC` '
                             'or `FOK`')

        # Build params dict
        params = {'product_id': product_id,
                  'side': side,
                  'order_type': 'limit',
                  'price': price,
                  'size': size}
        if client_oid is not None:
            params['client_oid'] = client_oid
        if self_trade_prevention is not None:
            params['stp'] = self_trade_prevention
        if time_in_force is not None:
            params['time_in_force'] = time_in_force
        if cancel_after is not None:
            params['cancel_after'] = cancel_after
        if post_only is not None:
            params['post_only'] = post_only

        return self.place_order(**params)

    def buyOLD(self, product_id):
        params = {'side': 'buy', 'product_id': product_id}
        r = requests.post(self.url + '/orders',
                          data=json.dumps(params), auth=self.auth)
        return r.json()

    def sellOLD(self, product_id):
        params = {'side': 'buy', 'product_id': product_id}
        r = requests.post(self.url + '/orders',
                          data=json.dumps(params), auth=self.auth)
        return r.json()

    def cancel_order(self, order_id):
        r = requests.delete(self.url + '/orders/' + order_id, auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def cancel_all(self, product_id=None):
        params = {'product_id': product_id}
        if product_id is not None:
            r = requests.delete(self.url + '/orders',
                                data=json.dumps(params), auth=self.auth)
        else:
            r = requests.delete(self.url + '/orders', auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_order(self, order_id):
        r = requests.get(self.url + '/orders/' + order_id, auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_orders(self, **kwargs):
        url = self.url + '/orders'
        return self._get_paginated_response(url, kwargs)[0]

    def get_fills(self, product_id=None, order_id=None, **kwargs):
        url = self.url + '/fills'
        params = {}
        if product_id:
            params['product_id'] = product_id
        if order_id:
            params['order_id'] = order_id
        params.update(kwargs)

        # Return `after` param so client can access more recent fills on next
        # call of get_fills if desired.
        message, r = self._get_paginated_response(url, params)
        return r.headers['cb-after'], message

    def get_fundings(self, status=None, **kwargs):
        url = self.url + '/funding'
        params = {}
        if status is not None:
            params['status'] = status
        params.update(kwargs)
        return self._get_paginated_response(url, params)[0]

    def repay_funding(self, amount, currency):
        params = {
            'amount': amount,
            'currency': currency  # example: USD
            }
        r = requests.post(self.url + '/funding/repay',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def margin_transfer(self, margin_profile_id, transfer_type, currency,
                        amount):
        params = {
            'margin_profile_id': margin_profile_id,
            'type': transfer_type,
            'currency': currency,  # example: USD
            'amount': amount
        }
        r = requests.post(self.url + '/profiles/margin-transfer',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_position(self):
        r = requests.get(self.url + '/position', auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def close_position(self, repay_only):
        params = {'repay_only': repay_only}
        r = requests.post(self.url + '/position/close',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def deposit(self, amount, currency, payment_method_id):
        params = {
            'amount': amount,
            'currency': currency,
            'payment_method_id': payment_method_id
        }
        r = requests.post(self.url + '/deposits/payment-method',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def coinbase_deposit(self, amount, currency, coinbase_account_id):
        params = {
            'amount': amount,
            'currency': currency,
            'coinbase_account_id': coinbase_account_id
        }
        r = requests.post(self.url + '/deposits/coinbase-account',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def withdraw(self, amount, currency, payment_method_id):
        params = {
            'amount': amount,
            'currency': currency,
            'payment_method_id': payment_method_id
        }
        r = requests.post(self.url + '/withdrawals/payment-method',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def coinbase_withdraw(self, amount, currency, coinbase_account_id):
        params = {
            'amount': amount,
            'currency': currency,
            'coinbase_account_id': coinbase_account_id
        }
        r = requests.post(self.url + '/withdrawals/coinbase',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def crypto_withdraw(self, amount, currency, crypto_address):
        params = {
            'amount': amount,
            'currency': currency,
            'crypto_address': crypto_address
        }
        r = requests.post(self.url + '/withdrawals/crypto',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_payment_methods(self):
        r = requests.get(self.url + '/payment-methods', auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_coinbase_accounts(self):
        r = requests.get(self.url + '/coinbase-accounts', auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def create_report(self, report_type, start_date, end_date, product_id=None,
                      account_id=None, report_format='pdf', email=None):
        params = {
            'type': report_type,
            'start_date': start_date,
            'end_date': end_date,
            'format': report_format,
        }
        if product_id is not None:
            params['product_id'] = product_id
        if account_id is not None:
            params['account_id'] = account_id
        if email is not None:
            params['email'] = email

        r = requests.post(self.url + '/reports',
                          data=json.dumps(params), auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_report(self, report_id):
        r = requests.get(self.url + '/reports/' + report_id, auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def get_trailing_volume(self):
        r = requests.get(self.url + '/users/self/trailing-volume',
                         auth=self.auth)
        # r.raise_for_status()
        return r.json()

    def _get_paginated_response(self, url, params=None):
        """Get a paginated response by making multiple http requests.

        Args:
            url (str): Full endpoint URL
            params (Optional[dict]): HTTP request parameters

        Returns:
            list: Merged responses from paginated requests
            requests.models.Response: Response object from last HTTP
                response

        """
        if params is None:
            params = {}
        result = []
        r = requests.get(url, params=params, auth=self.auth)
        if r.json():
            result = r.json()
        while 'cb-after' in r.headers:
            params['after'] = r.headers['cb-after']
            r = requests.get(url, params=params, auth=self.auth)
            if r.json():
                result += r.json()
        return result, r


class GdaxAuth(AuthBase):
    # Provided by GDAX: https://docs.gdax.com/#signing-a-message
    def __init__(self, api_key, secret_key, passphrase):
        self.api_key = api_key
        self.secret_key = secret_key
        self.passphrase = passphrase

    def __call__(self, request):
        timestamp = str(time.time())
        message = timestamp + request.method + request.path_url + \
                  (request.body or '')
        message = message.encode('ascii')
        hmac_key = base64.b64decode(self.secret_key)
        signature = hmac.new(hmac_key, message, hashlib.sha256)
        signature_b64 = base64.b64encode(signature.digest())
        request.headers.update({
            'Content-Type': 'Application/json',
            'CB-ACCESS-SIGN': signature_b64,
            'CB-ACCESS-TIMESTAMP': timestamp,
            'CB-ACCESS-KEY': self.api_key,
            'CB-ACCESS-PASSPHRASE': self.passphrase
        })
        return request
