from app import app
import pytest
from flask import Flask
from flask_bcrypt import Bcrypt
from app import Users

from flask import url_for

app = Flask ( __name__ )
bcrypt = Bcrypt (app)

@pytest.fixture
def test_client ():
    users = Users()
    users.insert('test100','test100','test100@test.fr',bcrypt.generate_password_hash('123456').decode('utf-8'))
    return users

def test_add_user ():
    user = Users(username="user_name", name="name", email="mail@test.fr", password_hash=bcrypt.generate_password_hash('123456').decode ('utf-8'))
    assert user.username == 'user_name'
    assert user.name == 'name'
    assert user.email == 'mail@test.fr'
    assert user.password_hash != '123456'

def test_home_route():
    response = app.test_client().get('/test')
    assert response.status_code == 200
    assert b"root" in response.data



def client():
    user = Users(username="user_name", password_hash=bcrypt.generate_password_hash('123456').decode ('utf-8'))
    with app.test_client(user) as client:
        response = app.test_client.get('/login')
        assert response.status_code == 200


def test_account_page__logged_in(test_client):
    #login user
    url = url_for('mon_compte') # nom de la fonction, pas de la page
    data = dict(email ="test_user@gmail.com", password ="123456")
    response = test_client.post(url, data=data)
    # assert response.status_code == 302
    url = url_for('do_login') # nom de la fonction, pas de la page
    response = test_client.post(url)

    assert response.status_code == 200
