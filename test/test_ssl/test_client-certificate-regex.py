import pathlib

import pytest
from requests.exceptions import SSLError


@pytest.fixture(scope="session")
def clientcerts():
    """
    pytest fixture to deduplicate used yields
    """
    current_file_path = pathlib.Path(__file__)
    clientcerts_path = current_file_path.parent.joinpath("clientcerts")
    
    client_cert = clientcerts_path.joinpath("Valid.crt")
    client_key = clientcerts_path.joinpath("Valid.key")
    invalid_client_cert = clientcerts_path.joinpath("Revoked.crt")
    invalid_client_key = clientcerts_path.joinpath("Revoked.key")
    yield {
        "client_cert": client_cert,
        "client_key": client_key,
        "invalid_client_cert": invalid_client_cert,
        "invalid_client_key": invalid_client_key,
    }

def test_client_certificate_regex_virtual_host_is_enforced(docker_compose, nginxproxy):
    """
    Test connection to a website with mTLS enabled without providing a client certificate.
    """
    r = nginxproxy.get("https://regex.nginx-proxy.tld/port")
    assert r.status_code == 400
    assert "400 No required SSL certificate was sent" in r.text

def test_client_certificate_regex_virtual_host_is_authenticated(docker_compose, nginxproxy, clientcerts):
    """
    Test connection to a website with mTLS enabled providing a valid client certificate.
    """
    r = nginxproxy.get("https://regex.nginx-proxy.tld/port", cert=(clientcerts["client_cert"], clientcerts["client_key"]))
    assert r.status_code == 200
    assert "answer from port 84\n" in r.text

def test_client_certificate_regex_virtual_host_is_revoked_crl(docker_compose, nginxproxy, clientcerts):
    """
    Test connection to a website with mTLS enabled providing a revoked client certificate on the CRL.
    """
    r = nginxproxy.get("https://regex.nginx-proxy.tld/port", cert=(clientcerts["invalid_client_cert"], clientcerts["invalid_client_key"]))
    assert r.status_code == 400
    assert "400 The SSL certificate error" in r.text
