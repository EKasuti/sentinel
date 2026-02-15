from utils.url_validator import is_safe_url

def test_safe_urls():
    assert is_safe_url("https://www.google.com") == True
    assert is_safe_url("http://example.com") == True

def test_unsafe_urls():
    assert is_safe_url("http://localhost") == False
    assert is_safe_url("http://127.0.0.1") == False
    assert is_safe_url("http://192.168.1.1") == False
    assert is_safe_url("http://10.0.0.1") == False
    assert is_safe_url("http://172.16.0.1") == False
    assert is_safe_url("ftp://google.com") == False
    assert is_safe_url("javascript:alert(1)") == False

if __name__ == "__main__":
    try:
        test_safe_urls()
        print("✅ test_safe_urls passed")
        test_unsafe_urls()
        print("✅ test_unsafe_urls passed")
    except AssertionError as e:
        print(f"❌ Tests failed")
        exit(1)
