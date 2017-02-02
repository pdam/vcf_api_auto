import pytest



def pytest_addoption(parser):
    parser.addoption("--vcf_ip", action="store", default="10.9.8.118",
        help="VCFC IP Address")

@pytest.fixture
def vcf_ip(request):
    return request.config.getoption("--vcf_ip")