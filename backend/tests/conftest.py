import os
import sys
from pathlib import Path
import pytest
from dotenv import load_dotenv

# Ensure backend and root are in sys.path
backend_dir = Path(__file__).resolve().parent.parent
root_dir = backend_dir.parent

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Load .env file from root or backend
env_path = root_dir / '.env'
if not env_path.exists():
    env_path = backend_dir / '.env'
load_dotenv(dotenv_path=env_path)

@pytest.fixture(scope='session')
def test_domain():
    return 'cloudflare.com'

@pytest.fixture(scope='session')
def test_cve():
    return 'CVE-2021-44228'

@pytest.fixture(scope='session')
def api_keys():
    return {
        'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
        'urlscan': os.getenv('URLSCAN_API_KEY', ''),
        'otx': os.getenv('OTX_API_KEY', ''),
        'shodan': os.getenv('SHODAN_API_KEY', ''),
        'gemini': os.getenv('GEMINI_API_KEY', ''),
        'leakcheck': os.getenv('LEAKCHECK_API_KEY', ''),
        'zap_url': os.getenv('ZAP_API_URL', ''),
        'zap_key': os.getenv('ZAP_API_KEY', ''),
    }
