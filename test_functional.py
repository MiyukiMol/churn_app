from selenium import webdriver
import unittest

class TestApp(unittest.TestCase):

    def setUp(self):
        self.driver = webdriver.Firefox()
        self.driver.implicitly_wait(10)

    def tearDown(self):
        self.driver.quit()

    def test_login_logout(self):
        self.driver.get('http://localhost:5000/login')
        username_input = self.driver.find_element('name','username')
        username_input.send_keys('test')
        password_input = self.driver.find_element('name','password')
        password_input.send_keys('test')
        submit_button = self.driver.find_element('name','submit')
        submit_button.click()
        logout_link = self.driver.find_element('name','logout')
        logout_link.click()




if __name__ == '__main__':
    unittest.main()