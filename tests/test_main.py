import pytest
from main import generate_password


def test_same_url_variants_produce_same_password():
    mk = 'TestMasterKey1234567890ABCDEFG'  # deterministic test key
    urls = ['https://www.github.com', 'https://github.com', 'http://github.com', 'github.com']
    pwds = [generate_password(mk, u) for u in urls]
    assert len(set(pwds)) == 1


def test_include_path_query_changes_password():
    mk = 'TestMasterKey1234567890ABCDEFG'
    url = 'https://example.com/some/path?x=1'
    base_pwd = generate_password(mk, url, include_path=False, include_query=False)
    path_pwd = generate_password(mk, url, include_path=True, include_query=False)
    query_pwd = generate_password(mk, url, include_path=False, include_query=True)
    assert base_pwd != path_pwd
    assert base_pwd != query_pwd


def test_password_length_and_expand_hmac():
    mk = 'TestMasterKey1234567890ABCDEFG'
    url = 'https://example.com'
    pwd_16 = generate_password(mk, url, length=16)
    pwd_32 = generate_password(mk, url, length=32)
    pwd_64 = generate_password(mk, url, length=64)
    assert len(pwd_16) == 16
    assert len(pwd_32) == 32
    assert len(pwd_64) == 64


def test_password_contains_all_categories():
    mk = 'TestMasterKey1234567890ABCDEFG'
    url = 'https://example.com'
    pwd = generate_password(mk, url, length=16)
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!@#$%^&*()_+-=[]{}|;:,.?~`" for c in pwd)


def test_generate_master_key_and_usage():
    from main import generate_master_key
    mk = generate_master_key(32)
    # 应当是字符串并且可用于生成密码
    assert isinstance(mk, str)
    pwd = generate_password(mk, 'https://example.com')
    assert len(pwd) == 16
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
