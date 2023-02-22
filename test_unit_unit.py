import unittest
from app import app, db, Users

class TestApp(unittest.TestCase):

    def setUp(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'        
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        db.create_all()

    # def tearDown(self):
    #     db.session.remove()
    #     db.drop_all()
        
    def test_user_creation(self):
        user = Users(name='test', username='testuser',email='test@email.com', password_hash='testpass')
        db.session.add(user)
        db.session.commit()
        retrieved_user = Users.query.filter_by(username='testuser').first()
        self.assertEqual(user.username, retrieved_user.username)
        self.assertEqual(user.password_hash, retrieved_user.password_hash)
    
    def test_hello(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_login(self):
        response = self.app.post('/login', data=dict(
            username='testuser',
            password_hash='testpass'
        ))
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestApp)
    test_result = unittest.TextTestRunner(verbosity=2).run(test_suite)
    print(test_result)