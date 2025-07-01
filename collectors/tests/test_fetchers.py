import unittest
from feeds import fetchers

class TestFetchers(unittest.TestCase):

    def test_fetchers_return(self):
        # Only tests that they run without exception, not that data is correct
        for fetch_func in fetchers.FEED_REGISTRY:
            try:
                fetch_func()
            except Exception as e:
                self.fail(f"{fetch_func.__name__} raised {e}")

if __name__ == '__main__':
    unittest.main()


